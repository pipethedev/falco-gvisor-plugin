package gvisor

import (
	"container/list"
	"maps"
	"slices"
	"sync/atomic"

	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
)

const (
	maxAncestors      = 8
	maxTrackedSockets = 256
	// maxTableBytes caps one sandbox's table; tableFloorBytes is what every
	// table may hold even when the tables together exceed
	// maxProcessTablesBytes.
	maxTableBytes         = 16 << 20
	tableFloorBytes       = 1 << 20
	maxProcessTablesBytes = 256 << 20
	rowOverheadBytes      = 512
	stringHeaderBytes     = 16
	socketEntryBytes      = 48
)

// processBudget is the memory the process tables of all connections share,
// as estimated by rowBytes.
type processBudget struct {
	used  atomic.Int64
	limit int64
}

// Snapshot is the process context attached to one event: the acting process
// and up to maxAncestors of its ancestors, nearest first.
type Snapshot struct {
	Process   ProcessInfo   `json:"proc"`
	Ancestors []ProcessInfo `json:"anc,omitempty"`
	// PrevUID is the effective uid before a credential-changing syscall,
	// set only on setuid-family events for processes seen before.
	PrevUID *uint32 `json:"prevuid,omitempty"`
	// L4 is the transport protocol of the socket a connect used, when the
	// socket() call that created it was seen.
	L4 string `json:"l4,omitempty"`
	// ExecFallback marks the first event of a process after an exec whose
	// sentry/execve point was never received but whose effect (the task
	// renamed to the new program) shows it happened, so exec rules see it.
	ExecFallback bool `json:"execfb,omitempty"`
}

// ProcessTable tracks the processes of one sandbox, keyed by thread-group id.
// It is not safe for concurrent use; each connection owns its own table.
// Besides holding at most limit processes, it evicts its least recently
// used rows to stay within maxBytes, and within floorBytes while the tables
// sharing its budget are over the budget's limit, so one sandbox cannot grow
// the plugin's memory by forking processes with long command lines.
type ProcessTable struct {
	limit      int
	maxBytes   int64
	floorBytes int64
	budget     *processBudget
	bytes      int64
	sizes      map[int32]int64
	entries    map[int32]*list.Element
	lru        *list.List
	sockets    map[int32]map[int64]string
}

// NewProcessTable returns a table holding at most limit processes.
func NewProcessTable(limit int) *ProcessTable {
	return newBudgetedProcessTable(limit, nil)
}

func newBudgetedProcessTable(limit int, budget *processBudget) *ProcessTable {
	return &ProcessTable{
		limit:      limit,
		maxBytes:   maxTableBytes,
		floorBytes: tableFloorBytes,
		budget:     budget,
		sizes:      make(map[int32]int64),
		entries:    make(map[int32]*list.Element),
		lru:        list.New(),
		sockets:    make(map[int32]map[int64]string),
	}
}

// release returns the table's memory to the shared budget once its
// connection is closed.
func (t *ProcessTable) release() {
	t.charge(-t.bytes)
}

func (t *ProcessTable) charge(delta int64) {
	t.bytes += delta
	if t.budget != nil {
		t.budget.used.Add(delta)
	}
}

// account updates the estimated size of a row after it changed.
func (t *ProcessTable) account(proc *ProcessInfo) {
	size := proc.rowBytes() + int64(len(t.sockets[proc.Pid]))*socketEntryBytes
	t.charge(size - t.sizes[proc.Pid])
	t.sizes[proc.Pid] = size
}

func (t *ProcessTable) overBudget() bool {
	if t.bytes > t.maxBytes {
		return true
	}
	return t.budget != nil && t.bytes > t.floorBytes && t.budget.used.Load() > t.budget.limit
}

// trim evicts the least recently used rows while the table is over budget,
// always keeping the most recent one.
func (t *ProcessTable) trim() {
	for t.lru.Len() > 1 && t.overBudget() {
		t.evictOldest()
	}
}

// Len returns the number of tracked processes.
func (t *ProcessTable) Len() int {
	return len(t.entries)
}

// Apply updates the table with a point and returns the snapshot describing
// the process that emitted it.
func (t *ProcessTable) Apply(p Point) Snapshot {
	ctx := p.Context()
	if ctx == nil {
		return Snapshot{}
	}
	proc := t.upsert(ctx.GetThreadGroupId())
	if start := ctx.GetThreadGroupStartTimeNs(); start != 0 && proc.StartTimeNs != 0 && start != proc.StartTimeNs {
		*proc = ProcessInfo{Pid: proc.Pid}
		delete(t.sockets, proc.Pid)
	}
	var prevUID *uint32
	if isCredentialChange(p.Msg) && proc.HasCreds {
		uid := proc.UID
		prevUID = &uid
	}
	_, sentryExec := p.Msg.(*pb.ExecveInfo)
	execFallback := false
	if pending := proc.pending; pending != nil {
		switch outcome := pending.resolve(ctx.GetThreadId(), ctx.GetProcessName()); {
		case sentryExec || outcome == execFailed:
			proc.pending = nil
		case outcome == execHappened:
			proc.pending = nil
			proc.commitExec(pending, truncateComm(ctx.GetProcessName()))
			execFallback = true
		}
	}
	proc.applyContext(ctx)

	switch m := p.Msg.(type) {
	case *pb.Start:
		proc.applyStart(m)
	case *pb.ExecveInfo:
		proc.applyExec(m)
	case *pb.Execve:
		if exit := m.GetExit(); exit != nil && exit.GetErrorno() == 0 {
			proc.applySyscallExec(m, ctx)
		}
	case *pb.CloneInfo:
		t.applyClone(proc, m)
	case *pb.Socket:
		if exit := m.GetExit(); exit != nil && exit.GetErrorno() == 0 && exit.GetResult() >= 0 {
			t.recordSocket(proc.Pid, exit.GetResult(), l4ProtoOf(m.GetDomain(), m.GetType()))
		}
	}

	snap := t.snapshot(proc)
	snap.PrevUID = prevUID
	snap.ExecFallback = execFallback
	if c, ok := p.Msg.(*pb.Connect); ok {
		snap.L4 = t.sockets[proc.Pid][c.GetFd()]
	}
	if _, ok := p.Msg.(*pb.TaskExit); ok {
		switch {
		case !isThreadGroupLeader(ctx):
			proc.threads = max(proc.threads-1, 0)
		case proc.threads == 0:
			t.retire(proc.Pid)
		}
	}
	t.account(proc)
	t.trim()
	return snap
}

func (t *ProcessTable) applyClone(parent *ProcessInfo, info *pb.CloneInfo) {
	child := info.GetCreatedThreadGroupId()
	if child == parent.Pid {
		parent.threads++
		return
	}
	if child == 0 {
		return
	}
	created := parent.clone()
	created.Pid = child
	created.Ppid = parent.Pid
	created.StartTimeNs = info.GetCreatedThreadStartTimeNs()
	*t.upsert(child) = created
	if inherited := t.sockets[parent.Pid]; len(inherited) > 0 {
		t.sockets[child] = maps.Clone(inherited)
	}
	if row, ok := t.lookup(child); ok {
		t.account(row)
	}
}

func (t *ProcessTable) upsert(pid int32) *ProcessInfo {
	if elem, ok := t.entries[pid]; ok {
		t.lru.MoveToFront(elem)
		return elem.Value.(*ProcessInfo)
	}
	for len(t.entries) >= t.limit {
		t.evictOldest()
	}
	proc := &ProcessInfo{Pid: pid}
	t.entries[pid] = t.lru.PushFront(proc)
	return proc
}

func (t *ProcessTable) lookup(pid int32) (*ProcessInfo, bool) {
	elem, ok := t.entries[pid]
	if !ok {
		return nil, false
	}
	return elem.Value.(*ProcessInfo), true
}

// retire makes a process the first to be evicted. It is called when the
// leader exits with no other thread of the group known to be alive; the row
// is kept, not removed, because threads created before the plugin attached
// are unknown, and a later event from the group moves it back to the front.
// A reused pid is recognised by its new start time or by the clone that
// creates it.
func (t *ProcessTable) retire(pid int32) {
	if elem, ok := t.entries[pid]; ok {
		t.lru.MoveToBack(elem)
	}
}

func (t *ProcessTable) remove(pid int32) {
	if elem, ok := t.entries[pid]; ok {
		t.lru.Remove(elem)
		delete(t.entries, pid)
	}
	delete(t.sockets, pid)
	t.charge(-t.sizes[pid])
	delete(t.sizes, pid)
}

// recordSocket remembers the transport protocol of a socket fd, so a later
// connect on it can report fd.l4proto. Each process keeps at most
// maxTrackedSockets entries.
func (t *ProcessTable) recordSocket(pid int32, fd int64, l4 string) {
	fds := t.sockets[pid]
	if fds == nil {
		fds = make(map[int64]string)
		t.sockets[pid] = fds
	}
	if _, known := fds[fd]; !known && len(fds) >= maxTrackedSockets {
		return
	}
	fds[fd] = l4
}

func (t *ProcessTable) evictOldest() {
	oldest := t.lru.Back()
	if oldest == nil {
		return
	}
	t.remove(oldest.Value.(*ProcessInfo).Pid)
}

// snapshot copies the process and its ancestors. Argv slices are shared
// rather than copied: they are only ever replaced, never modified in place.
// Only the parent's argv is kept, since no field reads older ancestors' argv.
func (t *ProcessTable) snapshot(proc *ProcessInfo) Snapshot {
	snap := Snapshot{Process: *proc}
	var visited [maxAncestors + 1]int32
	visited[0] = proc.Pid
	seen := visited[:1]
	for ppid := proc.Ppid; len(snap.Ancestors) < maxAncestors && ppid != 0 && !slices.Contains(seen, ppid); {
		parent, ok := t.lookup(ppid)
		if !ok {
			break
		}
		seen = append(seen, ppid)
		ancestor := *parent
		if len(snap.Ancestors) > 0 {
			ancestor.Argv = nil
		}
		snap.Ancestors = append(snap.Ancestors, ancestor)
		ppid = parent.Ppid
	}
	return snap
}

func isCredentialChange(msg any) bool {
	switch msg.(type) {
	case *pb.Setid, *pb.Setresid:
		return true
	default:
		return false
	}
}

func isThreadGroupLeader(ctx *pb.ContextData) bool {
	return ctx.GetThreadId() == ctx.GetThreadGroupId()
}
