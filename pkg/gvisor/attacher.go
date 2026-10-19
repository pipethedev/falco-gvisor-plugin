package gvisor

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultListTimeout   = 15 * time.Second
	defaultAttachTimeout = 30 * time.Second
	defaultAttachGrace   = 15 * time.Second
	pendingPollInterval  = 500 * time.Millisecond
	attachConcurrency    = 4
	statusRunning        = "running"
	flagRoot             = "--root"
	cmdList              = "list"
	flagFormatJSON       = "--format=json"
	cmdTrace             = "trace"
	cmdCreate            = "create"
	flagForce            = "--force"
	flagConfig           = "--config"
)

var sandboxIDAnnotations = []string{
	"io.kubernetes.cri.sandbox-id",
	"io.kubernetes.cri-o.SandboxID",
}

// ConnectionLister reports the live sandbox connections.
type ConnectionLister interface {
	Connections() []ConnInfo
}

type runscState struct {
	ID          string            `json:"id"`
	Status      string            `json:"status"`
	Annotations map[string]string `json:"annotations"`
}

// attachBinding ties a 'runsc trace create' process to the sandbox it
// attaches. That process, not the Sentry, connects the plugin socket
// (gVisor runs the sink setup there and donates the connected fd to the
// sandbox), so the connection's peer pid is the pid the binding is keyed by.
type attachBinding struct {
	sandboxID string
	done      bool
}

type sandboxSet struct {
	order       []string
	byContainer map[string]string
}

// Attacher attaches trace sessions to running sandboxes that have no live
// connection, so sandboxes started before Falco are monitored too.
type Attacher struct {
	runscPath     string
	runscRoot     string
	sessionConfig string
	runner        Runner
	conns         ConnectionLister
	stats         *Stats
	listTimeout   time.Duration
	attachTimeout time.Duration
	attachGrace   time.Duration

	mu       sync.Mutex
	attached map[int32]*attachBinding
}

// NewAttacher returns an attacher using the runsc settings from cfg.
func NewAttacher(cfg Config, runner Runner, conns ConnectionLister, stats *Stats) *Attacher {
	return &Attacher{
		runscPath:     cfg.RunscPath,
		runscRoot:     cfg.RunscRoot,
		sessionConfig: cfg.SessionConfigPath,
		runner:        runner,
		conns:         conns,
		stats:         stats,
		listTimeout:   defaultListTimeout,
		attachTimeout: defaultAttachTimeout,
		attachGrace:   defaultAttachGrace,
		attached:      make(map[int32]*attachBinding),
	}
}

// Run sweeps once immediately when attachNow is set, then every interval
// until ctx is cancelled. A zero interval disables periodic sweeps.
func (a *Attacher) Run(ctx context.Context, attachNow bool, interval time.Duration) {
	if attachNow {
		_ = guard(a.stats, "attacher sweep", func() { a.Sweep(ctx) })
	}
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = guard(a.stats, "attacher sweep", func() { a.Sweep(ctx) })
		}
	}
}

// Sweep lists running sandboxes and attaches every one without a live
// connection. Failures are logged and counted, never returned.
func (a *Attacher) Sweep(ctx context.Context) {
	sandboxes, err := a.listSandboxes(ctx)
	if err != nil {
		a.stats.AttacherFailed.Store(true)
		logger.Printf("attacher: %v", err)
		return
	}
	a.stats.AttacherFailed.Store(false)
	a.forgetGone(sandboxes)
	if !a.waitForPendingConnections(ctx) {
		return
	}
	connected := a.connectedSandboxes(sandboxes)

	sem := make(chan struct{}, attachConcurrency)
	var wg sync.WaitGroup
	var unmonitored atomic.Int64
	defer func() { a.stats.UnmonitoredSandboxes.Store(unmonitored.Load()) }()
	for _, id := range sandboxes.order {
		if connected[id] {
			continue
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			wg.Wait()
			return
		}
		if a.connectedSandboxes(sandboxes)[id] {
			<-sem
			continue
		}
		wg.Go(func() {
			defer func() { <-sem }()
			attached := false
			if err := guard(a.stats, "attach", func() { attached = a.attach(ctx, id) }); err != nil || !attached {
				unmonitored.Add(1)
			}
		})
	}
	wg.Wait()
}

// waitForPendingConnections holds the sweep while a recently accepted
// connection has not yet identified its sandbox (no container id seen, no
// attach binding): attaching now could force-replace that very session.
// Connections older than attachGrace are no longer considered pending.
// It returns false if ctx is cancelled.
func (a *Attacher) waitForPendingConnections(ctx context.Context) bool {
	for a.hasPendingConnection(time.Now()) {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(pendingPollInterval):
		}
	}
	return true
}

func (a *Attacher) hasPendingConnection(now time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, conn := range a.conns.Connections() {
		if _, bound := a.attached[conn.PeerPID]; bound && conn.PeerPID != 0 {
			continue
		}
		if len(conn.ContainerIDs) == 0 && now.Sub(conn.Since) < a.attachGrace {
			return true
		}
	}
	return false
}

func (a *Attacher) listSandboxes(ctx context.Context) (sandboxSet, error) {
	ctx, cancel := context.WithTimeout(ctx, a.listTimeout)
	defer cancel()
	out, err := a.runner.Run(ctx, nil, a.runscPath, a.listArgs()...)
	if err != nil {
		return sandboxSet{}, fmt.Errorf("list sandboxes: %w", err)
	}
	var states []runscState
	if err := json.Unmarshal(out, &states); err != nil {
		return sandboxSet{}, fmt.Errorf("decode runsc list: %w", err)
	}
	set := sandboxSet{byContainer: make(map[string]string)}
	seen := map[string]bool{}
	for _, st := range states {
		if st.Status != statusRunning || st.ID == "" {
			continue
		}
		sandbox := sandboxIDOf(st)
		set.byContainer[st.ID] = sandbox
		if !seen[sandbox] {
			seen[sandbox] = true
			set.order = append(set.order, sandbox)
		}
	}
	return set, nil
}

func (a *Attacher) connectedSandboxes(sandboxes sandboxSet) map[string]bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	connected := map[string]bool{}
	conns := a.conns.Connections()
	live := make(map[int32]bool, len(conns))
	for _, conn := range conns {
		live[conn.PeerPID] = true
	}
	for pid, binding := range a.attached {
		if binding.done && !live[pid] {
			delete(a.attached, pid)
		}
	}
	for _, conn := range conns {
		if binding, ok := a.attached[conn.PeerPID]; ok && conn.PeerPID != 0 {
			connected[binding.sandboxID] = true
		}
		for _, cid := range conn.ContainerIDs {
			if id, ok := sandboxes.byContainer[cid]; ok {
				connected[id] = true
			}
		}
	}
	return connected
}

func (a *Attacher) forgetGone(sandboxes sandboxSet) {
	running := make(map[string]bool, len(sandboxes.order))
	for _, id := range sandboxes.order {
		running[id] = true
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for pid, binding := range a.attached {
		if !running[binding.sandboxID] {
			delete(a.attached, pid)
		}
	}
}

func (a *Attacher) attach(ctx context.Context, sandboxID string) bool {
	ctx, cancel := context.WithTimeout(ctx, a.attachTimeout)
	defer cancel()
	a.stats.AttachAttempts.Add(1)
	binding := &attachBinding{sandboxID: sandboxID}
	onStart := func(pid int32) {
		a.mu.Lock()
		defer a.mu.Unlock()
		a.attached[pid] = binding
	}
	_, err := a.runner.Run(ctx, onStart, a.runscPath, a.attachArgs(sandboxID)...)
	a.mu.Lock()
	binding.done = true
	a.mu.Unlock()
	if err != nil {
		a.stats.AttachFailures.Add(1)
		logger.Printf("attach sandbox %s: %v", shortID(sandboxID), err)
		return false
	}
	logger.Printf("attached trace session to sandbox %s", shortID(sandboxID))
	return true
}

func (a *Attacher) listArgs() []string {
	return []string{flagRoot, a.runscRoot, cmdList, flagFormatJSON}
}

func (a *Attacher) attachArgs(sandboxID string) []string {
	return []string{flagRoot, a.runscRoot, cmdTrace, cmdCreate, flagForce, flagConfig, a.sessionConfig, sandboxID}
}

func sandboxIDOf(st runscState) string {
	for _, key := range sandboxIDAnnotations {
		if id := st.Annotations[key]; id != "" {
			return id
		}
	}
	return st.ID
}
