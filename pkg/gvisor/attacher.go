package gvisor

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultListTimeout   = 15 * time.Second
	defaultAttachTimeout = 30 * time.Second
	defaultAttachGrace   = 15 * time.Second
	pendingPollInterval  = 500 * time.Millisecond
	acceptSlack          = time.Second
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

var sandboxIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.+-]*$`)

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
	// podAnnotations enables grouping containers into their pod sandbox by
	// the CRI sandbox-id annotations. Only containerd and CRI-O set them
	// reliably; under Docker any user can set annotations.
	podAnnotations bool

	// rootMissing records that the last sweep found no runsc state root,
	// so the warning is logged once until it appears.
	rootMissing bool

	mu       sync.Mutex
	attached map[int32]*attachBinding
}

// NewAttacher returns an attacher using the runsc settings from cfg.
func NewAttacher(cfg Config, runner Runner, conns ConnectionLister, stats *Stats) *Attacher {
	return &Attacher{
		runscPath:      cfg.RunscPath,
		runscRoot:      cfg.RunscRoot,
		sessionConfig:  cfg.SessionConfigPath,
		runner:         runner,
		conns:          conns,
		stats:          stats,
		listTimeout:    defaultListTimeout,
		attachTimeout:  defaultAttachTimeout,
		attachGrace:    defaultAttachGrace,
		podAnnotations: cfg.MetadataProvider == providerCRI,
		attached:       make(map[int32]*attachBinding),
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
	a.warnMissingRoot()
	sandboxes, err := a.listSandboxes(ctx)
	if err != nil {
		a.stats.AttacherFailed.Store(true)
		logger.Printf("attacher: %v", err)
		return
	}
	listedAt := time.Now()
	a.stats.AttacherFailed.Store(false)
	a.forgetGone(sandboxes)
	if !a.waitForPendingConnections(ctx, listedAt) {
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
		if !a.waitForPendingConnections(ctx, listedAt) {
			<-sem
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
// Connections older than attachGrace are no longer considered pending, and
// neither are those accepted after the sandboxes were listed (plus
// acceptSlack for the accept to follow the connect): a sandbox's pod-init
// session connects during 'runsc create', before the sandbox is listed as
// running, so later connections belong to sandboxes this sweep does not
// attach. The wait therefore ends at most attachGrace after the listing,
// however many sandboxes keep starting. It returns false if ctx is
// cancelled.
func (a *Attacher) waitForPendingConnections(ctx context.Context, listedAt time.Time) bool {
	for a.hasPendingConnection(time.Now(), listedAt) {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(pendingPollInterval):
		}
	}
	return true
}

func (a *Attacher) hasPendingConnection(now, listedAt time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, conn := range a.conns.Connections() {
		if conn.Since.After(listedAt.Add(acceptSlack)) {
			continue
		}
		if _, bound := a.attached[conn.PeerPID]; bound && conn.PeerPID != 0 {
			continue
		}
		if len(conn.ContainerIDs) == 0 && now.Sub(conn.Since) < a.attachGrace {
			return true
		}
	}
	return false
}

// warnMissingRoot logs when the runsc state root does not exist: runsc then
// lists no sandboxes instead of failing, so a runscRoot that does not match
// the runtime (the Docker default on a containerd host) would otherwise go
// unnoticed. It is a warning, not a failure, because a host that has not
// run a sandbox yet may have no root either.
func (a *Attacher) warnMissingRoot() {
	_, err := os.Stat(a.runscRoot)
	missing := err != nil
	if missing && !a.rootMissing {
		logger.Printf("attacher: runsc state root: %v; sandboxes running elsewhere are not found, check runscRoot", err)
	}
	a.rootMissing = missing
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
		if st.Status != statusRunning {
			continue
		}
		if !sandboxIDPattern.MatchString(st.ID) {
			logger.Printf("attacher: skipping container with unexpected id %q", st.ID)
			continue
		}
		sandbox := a.sandboxIDOf(st)
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

// sandboxIDOf returns the id of the sandbox a container runs in: the CRI
// sandbox-id annotation when pod annotations are trusted and the value is a
// valid id, the container's own id otherwise.
func (a *Attacher) sandboxIDOf(st runscState) string {
	if !a.podAnnotations {
		return st.ID
	}
	for _, key := range sandboxIDAnnotations {
		if id := st.Annotations[key]; sandboxIDPattern.MatchString(id) {
			return id
		}
	}
	return st.ID
}
