package gvisor

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	runtime "k8s.io/cri-api/pkg/apis/runtime/v1"
)

func shortSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "gv")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "s.sock")
}

func TestDockerFetcher(t *testing.T) {
	path := shortSocketPath(t)
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), networkUnix, path)
	if err != nil {
		t.Fatal(err)
	}
	var requested atomic.Value
	srv := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested.Store(r.URL.Path)
		if !strings.Contains(r.URL.Path, testContainerID) {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"Id":"` + testContainerID + `","Name":"/web","Config":{"Image":"nginx:1.27","Env":["SECRET=hunter2"],"Labels":{"app":"web","team":"x"}}}`))
	})}
	go func() { _ = srv.Serve(listener) }()
	t.Cleanup(func() { _ = srv.Close() })

	fetcher := NewDockerFetcher(path)
	t.Cleanup(func() { _ = fetcher.Close() })
	info, err := fetcher.Fetch(context.Background(), testContainerID)
	if err != nil {
		t.Fatal(err)
	}
	want := &ContainerInfo{ID: testContainerID, Name: "web", Image: "nginx:1.27", Labels: map[string]string{"app": "web", "team": "x"}}
	if !reflect.DeepEqual(info, want) {
		t.Errorf("got %+v, want %+v", info, want)
	}
	if got := requested.Load(); got != "/containers/"+testContainerID+"/json" {
		t.Errorf("requested %v", got)
	}
	if _, err := fetcher.Fetch(context.Background(), "missing"); err == nil {
		t.Error("expected error for unknown container")
	}
}

func TestMetadataTypesHaveNoEnvironment(t *testing.T) {
	for _, typ := range []reflect.Type{reflect.TypeFor[dockerInspect](), reflect.TypeFor[ContainerInfo]()} {
		assertNoEnvField(t, typ, typ.Name())
	}
}

func assertNoEnvField(t *testing.T, typ reflect.Type, path string) {
	t.Helper()
	if typ.Kind() != reflect.Struct {
		return
	}
	for field := range typ.Fields() {
		name := strings.ToLower(field.Name + field.Tag.Get("json"))
		if strings.Contains(name, "env") {
			t.Errorf("%s.%s may carry environment variables", path, field.Name)
		}
		assertNoEnvField(t, field.Type, path+"."+field.Name)
	}
}

type fakeCRI struct {
	runtime.UnimplementedRuntimeServiceServer
	verbose atomic.Bool
}

func (f *fakeCRI) ListContainers(_ context.Context, req *runtime.ListContainersRequest) (*runtime.ListContainersResponse, error) {
	if req.GetFilter().GetId() != testContainerID {
		return &runtime.ListContainersResponse{}, nil
	}
	return &runtime.ListContainersResponse{Containers: []*runtime.Container{{
		Id:           testContainerID,
		PodSandboxId: "sandbox1",
		Metadata:     &runtime.ContainerMetadata{Name: "app"},
		Image:        &runtime.ImageSpec{Image: "sha256:abc"},
		Labels:       map[string]string{labelPodName: "web-0", "app": "web"},
	}}}, nil
}

func (f *fakeCRI) ContainerStatus(_ context.Context, req *runtime.ContainerStatusRequest) (*runtime.ContainerStatusResponse, error) {
	if req.GetVerbose() {
		f.verbose.Store(true)
	}
	return &runtime.ContainerStatusResponse{Status: &runtime.ContainerStatus{Image: &runtime.ImageSpec{Image: "docker.io/library/nginx:1.27"}}}, nil
}

func (f *fakeCRI) PodSandboxStatus(_ context.Context, req *runtime.PodSandboxStatusRequest) (*runtime.PodSandboxStatusResponse, error) {
	if req.GetVerbose() {
		f.verbose.Store(true)
	}
	if req.GetPodSandboxId() != "sandbox1" {
		return nil, errors.New("not found")
	}
	return &runtime.PodSandboxStatusResponse{Status: &runtime.PodSandboxStatus{
		Metadata: &runtime.PodSandboxMetadata{Name: "web-0", Namespace: "prod"},
		Labels:   map[string]string{"app": "web", "tier": "front"},
	}}, nil
}

func TestCRIFetcher(t *testing.T) {
	path := shortSocketPath(t)
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), networkUnix, path)
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeCRI{}
	srv := grpc.NewServer()
	runtime.RegisterRuntimeServiceServer(srv, fake)
	go func() { _ = srv.Serve(listener) }()
	t.Cleanup(srv.Stop)

	fetcher, err := NewCRIFetcher(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fetcher.Close() })

	info, err := fetcher.Fetch(context.Background(), testContainerID)
	if err != nil {
		t.Fatal(err)
	}
	if info.Name != "app" || info.Image != "docker.io/library/nginx:1.27" || info.PodName != "web-0" || info.PodNamespace != "prod" || info.PodLabels["tier"] != "front" {
		t.Errorf("unexpected info %+v", info)
	}

	sandbox, err := fetcher.Fetch(context.Background(), "sandbox1")
	if err != nil {
		t.Fatal(err)
	}
	if sandbox.PodName != "web-0" || sandbox.Name != "web-0" {
		t.Errorf("sandbox lookup %+v", sandbox)
	}
	if _, err := fetcher.Fetch(context.Background(), "nope"); !errors.Is(err, errCRINotFound) {
		t.Errorf("err = %v", err)
	}
	if fake.verbose.Load() {
		t.Error("CRI requests must never be verbose")
	}
}

type stubFetcher struct {
	mu      sync.Mutex
	calls   int
	info    *ContainerInfo
	err     error
	release chan struct{}
}

func (s *stubFetcher) Fetch(ctx context.Context, _ string) (*ContainerInfo, error) {
	if s.release != nil {
		select {
		case <-s.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	return s.info, s.err
}

func (s *stubFetcher) Close() error { return nil }

func (s *stubFetcher) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func TestMetadataCacheAsyncAndTTL(t *testing.T) {
	stub := &stubFetcher{
		info:    &ContainerInfo{ID: testContainerID, Name: "web", Labels: map[string]string{"app": "web", "secret-ish": "x"}},
		release: make(chan struct{}),
	}
	cache := NewMetadataCache(stub, time.Minute, []string{"app"}, &Stats{})
	t.Cleanup(func() { _ = cache.Close() })
	clock := time.Unix(1000, 0)
	var clockMu sync.Mutex
	cache.now = func() time.Time { clockMu.Lock(); defer clockMu.Unlock(); return clock }

	if got := cache.Lookup(testContainerID); got != nil {
		t.Fatal("lookup must not block and returns nil before fetch completes")
	}
	close(stub.release)
	waitFor(t, "metadata", func() bool { return cache.Lookup(testContainerID) != nil })
	info := cache.Lookup(testContainerID)
	if _, ok := info.Labels["secret-ish"]; ok || info.Labels["app"] != "web" {
		t.Errorf("allowlist not applied: %v", info.Labels)
	}
	for range 10 {
		cache.Lookup(testContainerID)
	}
	if stub.callCount() != 1 {
		t.Errorf("fetched %d times within TTL", stub.callCount())
	}

	clockMu.Lock()
	clock = clock.Add(2 * time.Minute)
	clockMu.Unlock()
	if cache.Lookup(testContainerID) == nil {
		t.Error("stale entry should be served while refreshing")
	}
	waitFor(t, "refresh", func() bool { return stub.callCount() == 2 })
}

func TestMetadataCacheProviderDown(t *testing.T) {
	stub := &stubFetcher{err: errors.New("connection refused")}
	cache := NewMetadataCache(stub, time.Minute, nil, &Stats{})
	t.Cleanup(func() { _ = cache.Close() })
	cache.Lookup(testContainerID)
	waitFor(t, "failed fetch", func() bool { return stub.callCount() == 1 })
	for range 5 {
		if cache.Lookup(testContainerID) != nil {
			t.Fatal("expected nil metadata when provider is down")
		}
	}
	if stub.callCount() != 1 {
		t.Errorf("negative cache not honoured: %d calls", stub.callCount())
	}
}

func TestMetadataCacheBounded(t *testing.T) {
	stub := &stubFetcher{info: &ContainerInfo{Name: "x"}}
	cache := NewMetadataCache(stub, time.Minute, nil, &Stats{})
	t.Cleanup(func() { _ = cache.Close() })
	cache.maxItems = 3
	for i := range 10 {
		id := strings.Repeat(string(rune('a'+i)), 64)
		cache.Lookup(id)
		waitFor(t, "fetch "+id[:1], func() bool { return cache.Lookup(id) != nil })
	}
	cache.mu.Lock()
	n := len(cache.entries)
	cache.mu.Unlock()
	if n > cache.maxItems {
		t.Errorf("cache holds %d entries, cap %d", n, cache.maxItems)
	}
}

type panickingFetcher struct{}

func (panickingFetcher) Fetch(context.Context, string) (*ContainerInfo, error) { panic("fetcher bug") }

func (panickingFetcher) Close() error { return nil }

func TestMetadataCacheFetchPanic(t *testing.T) {
	stats := &Stats{}
	cache := NewMetadataCache(panickingFetcher{}, time.Minute, nil, stats)
	t.Cleanup(func() { _ = cache.Close() })
	if info := cache.Lookup(testContainerID); info != nil {
		t.Errorf("metadata from a panicking fetcher: %+v", info)
	}
	inflight := func() bool {
		cache.mu.Lock()
		defer cache.mu.Unlock()
		_, ok := cache.inflight[testContainerID]
		return ok
	}
	deadline := time.Now().Add(testWait)
	for inflight() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if inflight() {
		t.Error("a panicking fetch stayed in flight, blocking every later fetch for the container")
	}
	if stats.Panics.Load() != 1 {
		t.Errorf("panics = %d", stats.Panics.Load())
	}
}

func TestMetadataCacheDisabled(t *testing.T) {
	cache := NewMetadataCache(nil, time.Minute, nil, &Stats{})
	if cache.Lookup(testContainerID) != nil {
		t.Error("none provider must return nil")
	}
	if err := cache.Close(); err != nil {
		t.Error(err)
	}
}
