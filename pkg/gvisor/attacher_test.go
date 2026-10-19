package gvisor

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeCall struct {
	name string
	args []string
}

type fakeRunner struct {
	mu        sync.Mutex
	calls     []fakeCall
	list      string
	failFor   map[string]bool
	block     bool
	nextPID   int32
	pidOfLast map[string]int32
}

func (f *fakeRunner) Run(ctx context.Context, onStart func(pid int32), name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	f.calls = append(f.calls, fakeCall{name: name, args: args})
	f.nextPID++
	pid := f.nextPID
	sandbox := args[len(args)-1]
	if f.pidOfLast == nil {
		f.pidOfLast = map[string]int32{}
	}
	f.pidOfLast[sandbox] = pid
	block, fail, list := f.block, f.failFor[sandbox], f.list
	f.mu.Unlock()

	if onStart != nil {
		onStart(pid)
	}
	if slices.Contains(args, cmdList) {
		return []byte(list), nil
	}
	if block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if fail {
		return nil, errors.New("sandbox gone")
	}
	return nil, nil
}

func (f *fakeRunner) attached() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var ids []string
	for _, c := range f.calls {
		if slices.Contains(c.args, cmdCreate) {
			ids = append(ids, c.args[len(c.args)-1])
		}
	}
	slices.Sort(ids)
	return ids
}

type fakeConns struct {
	mu    sync.Mutex
	conns []ConnInfo
}

func (f *fakeConns) Connections() []ConnInfo {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]ConnInfo(nil), f.conns...)
}

const runscListJSON = `[
 {"id":"aaa","status":"running"},
 {"id":"bbb","status":"running"},
 {"id":"ccc","status":"stopped"},
 {"id":"pod1-pause","status":"running","annotations":{"io.kubernetes.cri.sandbox-id":"pod1-pause"}},
 {"id":"pod1-app","status":"running","annotations":{"io.kubernetes.cri.sandbox-id":"pod1-pause"}}
]`

func newTestAttacher(runner Runner, conns ConnectionLister) (*Attacher, *Stats) {
	return newTestAttacherWith(runner, conns, providerCRI)
}

func newTestAttacherWith(runner Runner, conns ConnectionLister, provider string) (*Attacher, *Stats) {
	cfg := DefaultConfig()
	cfg.MetadataProvider = provider
	cfg.RunscPath = "/usr/local/bin/runsc"
	cfg.RunscRoot = "/run/runsc"
	cfg.SessionConfigPath = "/etc/falco/session.json"
	stats := &Stats{}
	return NewAttacher(cfg, runner, conns, stats), stats
}

func TestAttacherCommands(t *testing.T) {
	runner := &fakeRunner{list: runscListJSON}
	a, stats := newTestAttacher(runner, &fakeConns{})
	a.Sweep(context.Background())

	if got := runner.attached(); !reflect.DeepEqual(got, []string{"aaa", "bbb", "pod1-pause"}) {
		t.Errorf("attached %v", got)
	}
	runner.mu.Lock()
	defer runner.mu.Unlock()
	wantList := fakeCall{"/usr/local/bin/runsc", []string{"--root", "/run/runsc", "list", "--format=json"}}
	if !reflect.DeepEqual(runner.calls[0], wantList) {
		t.Errorf("list call %+v", runner.calls[0])
	}
	wantAttach := []string{"--root", "/run/runsc", "trace", "create", "--force", "--config", "/etc/falco/session.json", "aaa"}
	found := false
	for _, c := range runner.calls {
		found = found || reflect.DeepEqual(c.args, wantAttach)
	}
	if !found {
		t.Errorf("no call with args %v", wantAttach)
	}
	if stats.AttachAttempts.Load() != 3 || stats.AttachFailures.Load() != 0 {
		t.Errorf("attempts=%d failures=%d", stats.AttachAttempts.Load(), stats.AttachFailures.Load())
	}
}

func TestAttacherSkipsConnected(t *testing.T) {
	runner := &fakeRunner{list: runscListJSON}
	conns := &fakeConns{conns: []ConnInfo{{ContainerIDs: []string{"pod1-app"}}}}
	a, _ := newTestAttacher(runner, conns)
	a.Sweep(context.Background())
	if got := runner.attached(); !reflect.DeepEqual(got, []string{"aaa", "bbb"}) {
		t.Fatalf("first sweep attached %v", got)
	}

	runner.mu.Lock()
	idlePID := runner.pidOfLast["aaa"]
	runner.calls = nil
	runner.mu.Unlock()
	conns.mu.Lock()
	conns.conns = append(conns.conns, ConnInfo{PeerPID: idlePID})
	conns.mu.Unlock()

	a.Sweep(context.Background())
	if got := runner.attached(); !reflect.DeepEqual(got, []string{"bbb"}) {
		t.Errorf("second sweep attached %v, want only bbb", got)
	}
}

func TestAttacherExpiresBindingsWithoutConnection(t *testing.T) {
	runner := &fakeRunner{list: runscListJSON}
	conns := &fakeConns{}
	a, _ := newTestAttacher(runner, conns)
	a.Sweep(context.Background())

	runner.mu.Lock()
	stalePID := runner.pidOfLast["aaa"]
	runner.calls = nil
	runner.mu.Unlock()
	a.Sweep(context.Background())

	conns.mu.Lock()
	conns.conns = []ConnInfo{{PeerPID: stalePID}}
	conns.mu.Unlock()
	runner.mu.Lock()
	runner.calls = nil
	runner.mu.Unlock()
	a.Sweep(context.Background())
	if got := runner.attached(); !slices.Contains(got, "aaa") {
		t.Errorf("a connection reusing an expired attach PID kept sandbox aaa from being re-attached: %v", got)
	}
}

func TestAttacherWaitsForPendingConnection(t *testing.T) {
	runner := &fakeRunner{list: `[{"id":"aaa","status":"running"}]`}
	conns := &fakeConns{conns: []ConnInfo{{Since: time.Now()}}}
	a, _ := newTestAttacher(runner, conns)
	go func() {
		time.Sleep(2 * pendingPollInterval)
		conns.mu.Lock()
		conns.conns[0].ContainerIDs = []string{"aaa"}
		conns.mu.Unlock()
	}()
	a.Sweep(context.Background())
	if got := runner.attached(); len(got) != 0 {
		t.Errorf("attached %v while a new connection had not yet identified its sandbox", got)
	}

	stale := &fakeConns{conns: []ConnInfo{{Since: time.Now().Add(-time.Hour)}}}
	b, _ := newTestAttacher(&fakeRunner{list: `[{"id":"aaa","status":"running"}]`}, stale)
	b.attachGrace = time.Millisecond
	done := make(chan struct{})
	go func() { b.Sweep(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(testWait):
		t.Fatal("a connection older than the grace period blocked the sweep")
	}
}

func TestAttacherFailuresAndTimeouts(t *testing.T) {
	runner := &fakeRunner{list: runscListJSON, failFor: map[string]bool{"aaa": true}}
	a, stats := newTestAttacher(runner, &fakeConns{})
	a.Sweep(context.Background())
	if stats.AttachFailures.Load() != 1 || stats.UnmonitoredSandboxes.Load() != 1 {
		t.Errorf("failures = %d unmonitored = %d", stats.AttachFailures.Load(), stats.UnmonitoredSandboxes.Load())
	}
	runner.mu.Lock()
	runner.failFor = nil
	runner.mu.Unlock()
	a.Sweep(context.Background())
	if stats.UnmonitoredSandboxes.Load() != 0 {
		t.Errorf("unmonitored not cleared after a successful sweep: %d", stats.UnmonitoredSandboxes.Load())
	}

	blocking := &fakeRunner{list: runscListJSON, block: true}
	b, bstats := newTestAttacher(blocking, &fakeConns{})
	b.attachTimeout = 50 * time.Millisecond
	start := time.Now()
	b.Sweep(context.Background())
	if elapsed := time.Since(start); elapsed > testWait {
		t.Errorf("sweep took %v despite timeouts", elapsed)
	}
	if bstats.AttachFailures.Load() != 3 {
		t.Errorf("timed-out attaches counted %d", bstats.AttachFailures.Load())
	}
}

func TestAttacherBadListOutput(t *testing.T) {
	runner := &fakeRunner{list: "not json"}
	a, stats := newTestAttacher(runner, &fakeConns{})
	a.Sweep(context.Background())
	if stats.AttachAttempts.Load() != 0 {
		t.Error("attached despite unreadable list")
	}
	if !stats.AttacherFailed.Load() {
		t.Error("list failure not reported as attacher_failed")
	}
}

func TestAttacherRunStopsOnCancel(t *testing.T) {
	runner := &fakeRunner{list: "[]"}
	a, _ := newTestAttacher(runner, &fakeConns{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		a.Run(ctx, true, 10*time.Millisecond)
		close(done)
	}()
	waitFor(t, "periodic sweeps", func() bool {
		runner.mu.Lock()
		defer runner.mu.Unlock()
		return len(runner.calls) >= 3
	})
	cancel()
	select {
	case <-done:
	case <-time.After(testWait):
		t.Fatal("Run did not stop")
	}
}

func TestExecRunner(t *testing.T) {
	var pid int32
	out, err := execRunner{}.Run(context.Background(), func(p int32) { pid = p }, "sh", "-c", "echo hello")
	if err != nil || strings.TrimSpace(string(out)) != "hello" || pid <= 0 {
		t.Errorf("out=%q err=%v pid=%d", out, err, pid)
	}
	if _, err := (execRunner{}).Run(context.Background(), nil, "sh", "-c", "echo boom >&2; exit 3"); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Errorf("expected stderr in error, got %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := (execRunner{}).Run(ctx, nil, "sleep", "5"); err == nil || time.Since(start) > testWait {
		t.Errorf("timeout not enforced: %v", err)
	}
	big, err := (execRunner{}).Run(context.Background(), nil, "sh", "-c", "head -c 200000 /dev/zero | tr '\\0' a")
	if err != nil || len(big) != 200000 {
		t.Errorf("output beyond 64 KiB: %d bytes, %v", len(big), err)
	}
	if out, err := (execRunner{outputLimit: 1024}).Run(context.Background(), nil, "sh", "-c", "head -c 2000 /dev/zero"); !errors.Is(err, errOutputTruncated) || out != nil {
		t.Errorf("output over the limit returned %d bytes, err %v; want errOutputTruncated", len(out), err)
	}
	if _, err := (execRunner{}).Run(context.Background(), nil, "/nonexistent/runsc"); err == nil {
		t.Error("expected error for missing binary")
	}
}

func TestAttacherSandboxIDs(t *testing.T) {
	const list = `[
 {"id":"web","status":"running","annotations":{"io.kubernetes.cri.sandbox-id":"other"}},
 {"id":"-bad","status":"running"},
 {"id":"pod2-app","status":"running","annotations":{"io.kubernetes.cri.sandbox-id":"--force"}}
]`
	cases := map[string][]string{
		providerDocker: {"pod2-app", "web"},
		providerCRI:    {"other", "pod2-app"},
	}
	for provider, want := range cases {
		t.Run(provider, func(t *testing.T) {
			runner := &fakeRunner{list: list}
			a, _ := newTestAttacherWith(runner, &fakeConns{}, provider)
			a.Sweep(context.Background())
			if got := runner.attached(); !reflect.DeepEqual(got, want) {
				t.Errorf("attached %v, want %v", got, want)
			}
		})
	}
}

type appearingConns struct {
	mu    sync.Mutex
	calls int
	after int
	conn  ConnInfo
}

func (c *appearingConns) Connections() []ConnInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	if c.calls <= c.after {
		return nil
	}
	return []ConnInfo{c.conn}
}

func (c *appearingConns) identify(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.conn.ContainerIDs = []string{id}
}

func TestAttacherRechecksPendingBeforeEachAttach(t *testing.T) {
	runner := &fakeRunner{list: `[{"id":"aaa","status":"running"}]`}
	conns := &appearingConns{after: 1, conn: ConnInfo{Since: time.Now()}}
	a, _ := newTestAttacher(runner, conns)
	go func() {
		time.Sleep(2 * pendingPollInterval)
		conns.identify("aaa")
	}()
	a.Sweep(context.Background())
	if got := runner.attached(); len(got) != 0 {
		t.Errorf("attached %v over a connection that arrived during the sweep", got)
	}
}

type churningConns struct{}

func (churningConns) Connections() []ConnInfo {
	return []ConnInfo{{PeerPID: 1, Since: time.Now()}}
}

func TestAttacherSweepNotHeldOffByChurn(t *testing.T) {
	runner := &fakeRunner{list: `[{"id":"aaa","status":"running"}]`}
	a, _ := newTestAttacher(runner, churningConns{})
	done := make(chan struct{})
	go func() { a.Sweep(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(testWait):
		t.Fatal("sandboxes that keep connecting held the sweep off")
	}
	if got := runner.attached(); !slices.Equal(got, []string{"aaa"}) {
		t.Errorf("attached %v, want [aaa]", got)
	}
}
