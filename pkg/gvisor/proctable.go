package gvisor

import (
	"container/list"
	"slices"

	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
)

const maxAncestors = 8

// Snapshot is the process context attached to one event: the acting process
// and up to maxAncestors of its ancestors, nearest first.
type Snapshot struct {
	Process   ProcessInfo   `json:"proc"`
	Ancestors []ProcessInfo `json:"anc,omitempty"`
}

// ProcessTable tracks the processes of one sandbox, keyed by thread-group id.
// It is not safe for concurrent use; each connection owns its own table.
type ProcessTable struct {
	limit   int
	entries map[int32]*list.Element
	lru     *list.List
}

// NewProcessTable returns a table holding at most limit processes.
func NewProcessTable(limit int) *ProcessTable {
	return &ProcessTable{
		limit:   limit,
		entries: make(map[int32]*list.Element),
		lru:     list.New(),
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
	proc.applyContext(ctx)

	switch m := p.Msg.(type) {
	case *pb.Start:
		proc.applyStart(m)
	case *pb.ExecveInfo:
		proc.applyExec(m)
	case *pb.CloneInfo:
		t.applyClone(proc, m)
	}

	snap := t.snapshot(proc)
	if exit, ok := p.Msg.(*pb.TaskExit); ok && isThreadGroupLeader(exit.GetContextData()) {
		t.remove(proc.Pid)
	}
	return snap
}

func (t *ProcessTable) applyClone(parent *ProcessInfo, info *pb.CloneInfo) {
	child := info.GetCreatedThreadGroupId()
	if child == 0 || child == parent.Pid {
		return
	}
	created := parent.clone()
	created.Pid = child
	created.Ppid = parent.Pid
	created.StartTimeNs = info.GetCreatedThreadStartTimeNs()
	*t.upsert(child) = created
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

func (t *ProcessTable) remove(pid int32) {
	if elem, ok := t.entries[pid]; ok {
		t.lru.Remove(elem)
		delete(t.entries, pid)
	}
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

func isThreadGroupLeader(ctx *pb.ContextData) bool {
	return ctx.GetThreadId() == ctx.GetThreadGroupId()
}
