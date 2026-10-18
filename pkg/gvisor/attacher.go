package gvisor

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

const (
	defaultListTimeout   = 15 * time.Second
	defaultAttachTimeout = 30 * time.Second
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

	mu       sync.Mutex
	attached map[int32]string
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
		attached:      make(map[int32]string),
	}
}

// Run sweeps once immediately when attachNow is set, then every interval
// until ctx is cancelled. A zero interval disables periodic sweeps.
func (a *Attacher) Run(ctx context.Context, attachNow bool, interval time.Duration) {
	if attachNow {
		a.Sweep(ctx)
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
			a.Sweep(ctx)
		}
	}
}

// Sweep lists running sandboxes and attaches every one without a live
// connection. Failures are logged and counted, never returned.
func (a *Attacher) Sweep(ctx context.Context) {
	sandboxes, err := a.listSandboxes(ctx)
	if err != nil {
		logger.Printf("attacher: %v", err)
		return
	}
	a.forgetGone(sandboxes)
	connected := a.connectedSandboxes(sandboxes)

	sem := make(chan struct{}, attachConcurrency)
	var wg sync.WaitGroup
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
		wg.Go(func() {
			defer func() { <-sem }()
			a.attach(ctx, id)
		})
	}
	wg.Wait()
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
	for _, conn := range a.conns.Connections() {
		if id, ok := a.attached[conn.PeerPID]; ok && conn.PeerPID != 0 {
			connected[id] = true
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
	for pid, id := range a.attached {
		if !running[id] {
			delete(a.attached, pid)
		}
	}
}

func (a *Attacher) attach(ctx context.Context, sandboxID string) {
	ctx, cancel := context.WithTimeout(ctx, a.attachTimeout)
	defer cancel()
	a.stats.AttachAttempts.Add(1)
	onStart := func(pid int32) {
		a.mu.Lock()
		defer a.mu.Unlock()
		a.attached[pid] = sandboxID
	}
	if _, err := a.runner.Run(ctx, onStart, a.runscPath, a.attachArgs(sandboxID)...); err != nil {
		a.stats.AttachFailures.Add(1)
		logger.Printf("attach sandbox %s: %v", shortID(sandboxID), err)
		return
	}
	logger.Printf("attached trace session to sandbox %s", shortID(sandboxID))
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
