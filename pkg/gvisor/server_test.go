//go:build linux

package gvisor

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
	"gvisor.dev/gvisor/pkg/sentry/seccheck/sinks/remote/wire"
)

type fakeResolver map[string]*ContainerInfo

func (f fakeResolver) Lookup(id string) *ContainerInfo { return f[id] }

func (f fakeResolver) Await(id string, _ time.Duration) *ContainerInfo { return f[id] }

type collector struct {
	events chan []byte
	accept bool
}

func newCollector(size int) *collector {
	return &collector{events: make(chan []byte, size), accept: true}
}

func (c *collector) emit(_ uint64, data []byte, _ time.Time) error {
	if !c.accept {
		return ErrQueueFull
	}
	select {
	case c.events <- data:
		return nil
	default:
		return ErrQueueFull
	}
}

func (c *collector) next(t *testing.T) Event {
	t.Helper()
	select {
	case data := <-c.events:
		evt, err := DecodeEvent(data)
		if err != nil {
			t.Fatal(err)
		}
		return evt
	case <-time.After(testWait):
		t.Fatal("timed out waiting for event")
		return Event{}
	}
}

func startServer(t *testing.T, mutate func(*Config), c *collector, resolver ContainerResolver) (*Server, *Stats) {
	t.Helper()
	cfg := DefaultConfig()
	cfg.SocketPath = filepath.Join(t.TempDir(), "gvisor.sock")
	if mutate != nil {
		mutate(&cfg)
	}
	stats := &Stats{}
	srv := NewServer(cfg, c.emit, resolver, stats)
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	return srv, stats
}

func dialSandbox(t *testing.T, path string, version uint32) *net.UnixConn {
	t.Helper()
	conn, err := net.DialUnix(networkUnixPacket, nil, &net.UnixAddr{Name: path, Net: networkUnixPacket})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	hs, err := proto.Marshal(&pb.Handshake{Version: version})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(hs); err != nil {
		t.Fatal(err)
	}
	return conn
}

func completeHandshake(t *testing.T, conn *net.UnixConn) {
	t.Helper()
	buf := make([]byte, handshakeBufferSize)
	_ = conn.SetReadDeadline(time.Now().Add(testWait))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("handshake reply: %v", err)
	}
	var reply pb.Handshake
	if err := proto.Unmarshal(buf[:n], &reply); err != nil || reply.GetVersion() != wire.CurrentVersion {
		t.Fatalf("bad handshake reply %v: %v", &reply, err)
	}
}

func connectSandbox(t *testing.T, path string) *net.UnixConn {
	t.Helper()
	conn := dialSandbox(t, path, wire.CurrentVersion)
	completeHandshake(t, conn)
	return conn
}

func send(t *testing.T, conn *net.UnixConn, pkt []byte) {
	t.Helper()
	if _, err := conn.Write(pkt); err != nil {
		t.Fatal(err)
	}
}

func TestServerEnrichesEvents(t *testing.T) {
	c := newCollector(16)
	resolver := fakeResolver{testContainerID: {ID: testContainerID, Name: "web", Image: "nginx:1"}}
	srv, stats := startServer(t, nil, c, resolver)
	conn := connectSandbox(t, srv.socketPath)

	send(t, conn, mustPacket(t, pb.MessageType_MESSAGE_SENTRY_EXEC, &pb.ExecveInfo{
		ContextData: testContext(1, 0, "sh"), BinaryPath: "/bin/sh", Argv: []string{"sh"},
	}))
	send(t, conn, mustPacket(t, pb.MessageType_MESSAGE_SENTRY_EXEC, &pb.ExecveInfo{
		ContextData: testContext(2, 1, "sh"), BinaryPath: "/usr/bin/id", Argv: []string{"id", "-u"},
	}))

	c.next(t)
	evt := c.next(t)
	if evt.Context.Process.Cmdline() != "id -u" || len(evt.Context.Ancestors) != 1 || evt.Context.Ancestors[0].ExePath != "/bin/sh" {
		t.Errorf("unexpected process context %+v", evt.Context.Snapshot)
	}
	if evt.Context.Container == nil || evt.Context.Container.Name != "web" {
		t.Errorf("container metadata missing: %+v", evt.Context.Container)
	}
	waitFor(t, "event counter", func() bool { return stats.Events.Load() == 2 })
	waitFor(t, "connection info", func() bool {
		conns := srv.Connections()
		return len(conns) == 1 && len(conns[0].ContainerIDs) == 1 && conns[0].ContainerIDs[0] == testContainerID
	})
}

func TestServerWaitsForFirstContainerMetadata(t *testing.T) {
	c := newCollector(4)
	stub := &stubFetcher{info: &ContainerInfo{ID: testContainerID, Name: "web"}, release: make(chan struct{})}
	cache := NewMetadataCache(stub, time.Minute, nil, &Stats{})
	t.Cleanup(func() { _ = cache.Close() })
	srv, _ := startServer(t, nil, c, cache)
	conn := connectSandbox(t, srv.socketPath)

	go func() {
		time.Sleep(30 * time.Millisecond)
		close(stub.release)
	}()
	send(t, conn, mustPacket(t, pb.MessageType_MESSAGE_SENTRY_EXEC, &pb.ExecveInfo{
		ContextData: testContext(1, 0, "sh"), BinaryPath: "/tmp/xmrig", Argv: []string{"xmrig"},
	}))
	evt := c.next(t)
	if evt.Context.Container == nil || evt.Context.Container.Name != "web" {
		t.Errorf("first event of a new container lacks metadata resolved within metadataWaitMillis: %+v", evt.Context.Container)
	}
}

type panickingResolver struct{ fakeResolver }

func (p panickingResolver) Lookup(id string) *ContainerInfo {
	if id == "boom" {
		panic("resolver bug")
	}
	return p.fakeResolver.Lookup(id)
}

func (p panickingResolver) Await(id string, d time.Duration) *ContainerInfo { return p.Lookup(id) }

func TestServerSurvivesPanicInPointProcessing(t *testing.T) {
	c := newCollector(4)
	srv, stats := startServer(t, nil, c, panickingResolver{fakeResolver{}})
	conn := connectSandbox(t, srv.socketPath)

	bad := testContext(1, 0, "sh")
	bad.ContainerId = "boom"
	send(t, conn, mustPacket(t, pb.MessageType_MESSAGE_SENTRY_EXEC, &pb.ExecveInfo{ContextData: bad, BinaryPath: "/bin/sh"}))
	send(t, conn, mustPacket(t, pb.MessageType_MESSAGE_SENTRY_EXEC, &pb.ExecveInfo{ContextData: testContext(2, 1, "id"), BinaryPath: "/usr/bin/id", Argv: []string{"id"}}))

	if evt := c.next(t); evt.Context.Process.Comm != "id" {
		t.Errorf("the point after a panic was not processed: %+v", evt.Context.Process)
	}
	if stats.Panics.Load() != 1 || stats.DropPanic.Load() != 1 || stats.Connections.Load() != 1 {
		t.Errorf("panics=%d drops=%d connections=%d", stats.Panics.Load(), stats.DropPanic.Load(), stats.Connections.Load())
	}
}

func TestServerRedactsArgs(t *testing.T) {
	c := newCollector(2)
	srv, _ := startServer(t, func(cfg *Config) { cfg.CaptureArgs = false }, c, fakeResolver{})
	conn := connectSandbox(t, srv.socketPath)
	send(t, conn, mustPacket(t, pb.MessageType_MESSAGE_SENTRY_EXEC, &pb.ExecveInfo{
		ContextData: testContext(1, 0, "sh"), BinaryPath: "/usr/bin/mysql", Argv: []string{"mysql", "-p", "s3cret"},
	}))
	evt := c.next(t)
	if got := evt.Context.Process.Argv; len(got) != 1 || got[0] != "mysql" {
		t.Errorf("process argv = %v, want only argv[0]", got)
	}
	if got := evt.Point.Msg.(*pb.ExecveInfo).GetArgv(); len(got) != 1 {
		t.Errorf("forwarded packet still carries arguments: %v", got)
	}
}

func TestServerReleasesClosedConnections(t *testing.T) {
	c := newCollector(1)
	srv, stats := startServer(t, nil, c, fakeResolver{})
	conn := connectSandbox(t, srv.socketPath)
	waitFor(t, "connection", func() bool { return stats.Connections.Load() == 1 })
	_ = conn.Close()
	waitFor(t, "connection release", func() bool { return stats.Connections.Load() == 0 && len(srv.Connections()) == 0 })
}

func TestServerRejectsBadHandshakeOnly(t *testing.T) {
	c := newCollector(16)
	srv, stats := startServer(t, nil, c, fakeResolver{})
	good := connectSandbox(t, srv.socketPath)

	for _, version := range []uint32{0, wire.CurrentVersion + 1} {
		bad := dialSandbox(t, srv.socketPath, version)
		_ = bad.SetReadDeadline(time.Now().Add(testWait))
		if _, err := bad.Read(make([]byte, handshakeBufferSize)); err == nil {
			t.Errorf("version %d: expected connection to be closed", version)
		}
	}
	waitFor(t, "rejections", func() bool { return stats.HandshakeRejected.Load() == 2 })

	send(t, good, mustPacket(t, pb.MessageType_MESSAGE_SENTRY_TASK_EXIT, &pb.TaskExit{ContextData: testContext(1, 0, "sh")}))
	c.next(t)
}

func TestServerConcurrentConnections(t *testing.T) {
	const clients, perClient = 8, 50
	c := newCollector(clients * perClient)
	srv, stats := startServer(t, nil, c, fakeResolver{})

	var wg sync.WaitGroup
	for i := range clients {
		conn := connectSandbox(t, srv.socketPath)
		wg.Go(func() {
			for j := range perClient {
				pkt, err := encodePacket(pb.MessageType_MESSAGE_SENTRY_EXEC, 0, &pb.ExecveInfo{
					ContextData: testContext(int32(j+1), 0, "w"), BinaryPath: "/bin/true",
				})
				if err == nil {
					_, err = conn.Write(pkt)
				}
				if err != nil {
					t.Errorf("client %d: %v", i, err)
					return
				}
			}
		})
	}
	wg.Wait()
	waitFor(t, "all events", func() bool { return stats.Events.Load() == clients*perClient })
	if got := stats.TotalConnections.Load(); got != clients {
		t.Errorf("total connections = %d", got)
	}
}

func TestServerCountsDrops(t *testing.T) {
	c := newCollector(1)
	c.accept = false
	srv, stats := startServer(t, func(cfg *Config) { cfg.MaxEventSize = minMaxEventSize }, c, fakeResolver{})
	conn := connectSandbox(t, srv.socketPath)

	ctx := testContext(1, 0, "sh")
	send(t, conn, mustPacket(t, pb.MessageType_MESSAGE_SENTRY_TASK_EXIT, &pb.TaskExit{ContextData: ctx}))
	send(t, conn, mustPacket(t, pb.MessageType_MESSAGE_SENTRY_EXEC, &pb.ExecveInfo{ContextData: ctx, BinaryPath: string(make([]byte, 2*minMaxEventSize))}))
	send(t, conn, []byte{1, 2, 3})
	send(t, conn, mustPacket(t, pb.MessageType_MESSAGE_SYSCALL_WRITE, &pb.Write{ContextData: ctx}))
	dropped, err := encodePacket(pb.MessageType_MESSAGE_SENTRY_TASK_EXIT, 5, &pb.TaskExit{ContextData: ctx})
	if err != nil {
		t.Fatal(err)
	}
	send(t, conn, dropped)

	waitFor(t, "drop counters", func() bool {
		return stats.DropChannelFull.Load() == 2 &&
			stats.DropTruncated.Load() == 1 &&
			stats.DropDecodeError.Load() == 1 &&
			stats.DropUnsupported.Load() == 1 &&
			stats.DropSandbox.Load() == 5
	})
}

func TestServerShutdown(t *testing.T) {
	c := newCollector(1)
	srv, stats := startServer(t, nil, c, fakeResolver{})
	connectSandbox(t, srv.socketPath)
	connectSandbox(t, srv.socketPath)
	waitFor(t, "connections", func() bool { return stats.Connections.Load() == 2 })

	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(srv.socketPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("socket not removed: %v", err)
	}
	if got := stats.Connections.Load(); got != 0 {
		t.Errorf("connections after close = %d", got)
	}
	if err := srv.Close(); err != nil {
		t.Errorf("second close: %v", err)
	}
}

func TestServerSocketReuse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "gvisor.sock")
	setPath := func(cfg *Config) { cfg.SocketPath = path }

	first, _ := startServer(t, setPath, newCollector(1), fakeResolver{})
	second := NewServer(Config{SocketPath: path, MaxEventSize: defaultMaxEventSize, MaxTrackedProcesses: 1}, newCollector(1).emit, fakeResolver{}, &Stats{})
	if err := second.Start(); !errors.Is(err, errSocketInUse) {
		t.Fatalf("expected errSocketInUse, got %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	stale, err := net.ListenUnix(networkUnixPacket, &net.UnixAddr{Name: path, Net: networkUnixPacket})
	if err != nil {
		t.Fatal(err)
	}
	stale.SetUnlinkOnClose(false)
	_ = stale.Close()

	srv, _ := startServer(t, setPath, newCollector(1), fakeResolver{})
	info, err := os.Stat(srv.socketPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != socketPerm {
		t.Errorf("socket perm = %o", perm)
	}
}
