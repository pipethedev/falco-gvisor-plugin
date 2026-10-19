package gvisor

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"
	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
	"gvisor.dev/gvisor/pkg/sentry/seccheck/sinks/remote/wire"
)

const (
	networkUnixPacket   = "unixpacket"
	socketDirPerm       = 0o750
	socketPerm          = 0o660
	handshakeBufferSize = 10240
	handshakeTimeout    = 5 * time.Second
	minWireVersion      = 1
	acceptRetryDelay    = 100 * time.Millisecond
	staleProbeTimeout   = 500 * time.Millisecond
	maxConnContainers   = 256
	oversizeLogInterval = 10 * time.Second
)

var (
	errSocketInUse          = errors.New("socket already in use by a live listener")
	errUnsupportedHandshake = errors.New("unsupported wire version")
)

// EmitFunc hands an encoded event to Falco on behalf of a sandbox
// connection (owner). It must not block; it returns ErrQueueFull or
// ErrQueueShare when the event could not be queued, and ErrSourceClosed
// once the source is shutting down, which is not counted as a drop.
type EmitFunc func(owner uint64, data []byte, ts time.Time) error

// ContainerResolver returns cached metadata for a container id, or nil when
// it is not known yet. Implementations must not block.
type ContainerResolver interface {
	Lookup(containerID string) *ContainerInfo
}

// ConnInfo describes one live sandbox connection.
type ConnInfo struct {
	PeerPID      int32
	ContainerIDs []string
	Since        time.Time
}

// Server accepts gVisor remote-sink connections and turns trace points into
// enriched plugin events.
type Server struct {
	socketPath   string
	maxEventSize int
	maxProcesses int
	metadataWait time.Duration
	maxHeldBytes int64
	heldBytes    atomic.Int64
	maxConns     int
	requireRunsc bool
	captureArgs  bool
	emit         EmitFunc
	resolver     ContainerResolver
	stats        *Stats

	listener *net.UnixListener
	wg       sync.WaitGroup

	mu     sync.Mutex
	conns  map[*sandboxConn]struct{}
	closed bool
	nextID atomic.Uint64

	lastRejectLog time.Time
}

type sandboxConn struct {
	id      uint64
	since   time.Time
	conn    *net.UnixConn
	peerPID int32
	drops   uint64

	hold metadataHold

	mu           sync.Mutex
	containerIDs map[string]struct{}
	idOrder      []string
}

// NewServer returns a server that is not listening yet.
func NewServer(cfg Config, emit EmitFunc, resolver ContainerResolver, stats *Stats) *Server {
	return &Server{
		socketPath:   cfg.SocketPath,
		maxEventSize: cfg.MaxEventSize,
		maxProcesses: cfg.MaxTrackedProcesses,
		metadataWait: cfg.metadataWait(),
		maxHeldBytes: int64(cfg.MaxQueueBytes),
		maxConns:     cfg.MaxConnections,
		requireRunsc: cfg.RequireRunscPeer,
		captureArgs:  cfg.CaptureArgs,
		emit:         emit,
		resolver:     resolver,
		stats:        stats,
		conns:        make(map[*sandboxConn]struct{}),
	}
}

// Start creates the listening socket and begins accepting connections.
func (s *Server) Start() error {
	if err := os.MkdirAll(filepath.Dir(s.socketPath), socketDirPerm); err != nil {
		return fmt.Errorf("create socket directory: %w", err)
	}
	if err := checkSocketDir(filepath.Dir(s.socketPath), os.Geteuid()); err != nil {
		return err
	}
	if err := removeStaleSocket(s.socketPath); err != nil {
		return err
	}
	listener, err := net.ListenUnix(networkUnixPacket, &net.UnixAddr{Name: s.socketPath, Net: networkUnixPacket})
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.socketPath, err)
	}
	listener.SetUnlinkOnClose(true)
	if err := os.Chmod(s.socketPath, socketPerm); err != nil {
		_ = listener.Close()
		return fmt.Errorf("chmod %s: %w", s.socketPath, err)
	}
	s.listener = listener
	s.wg.Add(1)
	go s.acceptLoop()
	logger.Printf("listening on %s", s.socketPath)
	return nil
}

// Close stops accepting, closes every connection, waits for all goroutines
// and removes the socket.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	var err error
	if s.listener != nil {
		err = s.listener.Close()
	}
	for c := range s.conns {
		_ = c.conn.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
	return err
}

// Connections lists the live sandbox connections.
func (s *Server) Connections() []ConnInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	infos := make([]ConnInfo, 0, len(s.conns))
	for c := range s.conns {
		infos = append(infos, c.info())
	}
	return infos
}

func (s *Server) acceptLoop() {
	defer s.wg.Done()
	for {
		keepGoing := true
		_ = guard(s.stats, "accept loop", func() { keepGoing = s.acceptOne() })
		if !keepGoing {
			return
		}
	}
}

func (s *Server) acceptOne() bool {
	conn, err := s.listener.AcceptUnix()
	if err != nil {
		if errors.Is(err, net.ErrClosed) {
			return false
		}
		logger.Printf("accept: %v", err)
		time.Sleep(acceptRetryDelay)
		return true
	}
	pid, uid, credOK := peerCred(conn)
	if err := checkPeer(pid, uid, credOK, os.Geteuid(), s.requireRunsc); err != nil {
		s.stats.PeerRejected.Add(1)
		logger.Printf("rejected connection from pid %d (uid %d): %v", pid, uid, err)
		_ = conn.Close()
		return true
	}
	if s.connectionCount() >= s.maxConns {
		s.stats.ConnRejected.Add(1)
		if time.Since(s.lastRejectLog) > oversizeLogInterval {
			s.lastRejectLog = time.Now()
			logger.Printf("refused connection from pid %d: %d connections already open (maxConnections)", pid, s.maxConns)
		}
		_ = conn.Close()
		return true
	}
	sc := &sandboxConn{id: s.nextID.Add(1), since: time.Now(), conn: conn, peerPID: pid, containerIDs: map[string]struct{}{}}
	if !s.track(sc) {
		_ = conn.Close()
		return false
	}
	s.wg.Add(1)
	go s.serve(sc)
	return true
}

func (s *Server) connectionCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.conns)
}

func (s *Server) track(sc *sandboxConn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.conns[sc] = struct{}{}
	return true
}

func (s *Server) untrack(sc *sandboxConn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.conns, sc)
}

func (s *Server) serve(sc *sandboxConn) {
	defer s.wg.Done()
	defer s.untrack(sc)
	defer sc.logDrops()
	defer func() { _ = sc.conn.Close() }()

	if err := handshake(sc.conn); err != nil {
		s.stats.HandshakeRejected.Add(1)
		logger.Printf("handshake with pid %d rejected: %v", sc.peerPID, err)
		return
	}
	s.stats.Connections.Add(1)
	s.stats.TotalConnections.Add(1)
	defer s.stats.Connections.Add(-1)

	table := NewProcessTable(s.maxProcesses)
	reader, err := newDatagramReader(sc.conn)
	if err != nil {
		logger.Printf("sandbox connection %d: %v", sc.id, err)
		return
	}
	var lastDropped uint32
	var lastOversizeLog time.Time
	deadlineSet := false
	for {
		switch {
		case sc.hold.active():
			_ = sc.conn.SetReadDeadline(s.holdDeadline(sc))
			deadlineSet = true
		case deadlineSet:
			_ = sc.conn.SetReadDeadline(time.Time{})
			deadlineSet = false
		}
		msg, err := reader.next(s.maxEventSize)
		timedOut := errors.Is(err, os.ErrDeadlineExceeded)
		if sc.hold.active() && (s.holdReady(sc) || (err != nil && !timedOut)) {
			_ = guard(s.stats, "metadata hold flush", func() { s.flushHold(sc) })
		}
		if timedOut {
			continue
		}
		var oversize *oversizeError
		if errors.As(err, &oversize) {
			s.stats.DropTruncated.Add(1)
			if time.Since(lastOversizeLog) > oversizeLogInterval {
				lastOversizeLog = time.Now()
				logger.Printf("sandbox connection %d: dropped %v (limit %d); raise maxEventSize", sc.id, oversize, s.maxEventSize)
			}
			continue
		}
		if err != nil {
			return
		}
		point, err := DecodePoint(msg)
		if err == nil && !s.captureArgs {
			point, err = redactArgs(point)
		}
		if err != nil {
			s.countDecodeError(err)
			continue
		}
		s.stats.DropSandbox.Add(uint64(point.Dropped - lastDropped))
		lastDropped = point.Dropped
		if err := guard(s.stats, "point processing", func() { s.handlePoint(sc, table, point) }); err != nil {
			s.stats.DropPanic.Add(1)
		}
	}
}

func (s *Server) countDecodeError(err error) {
	if errors.Is(err, errUnsupportedType) {
		s.stats.DropUnsupported.Add(1)
		return
	}
	s.stats.DropDecodeError.Add(1)
}

func (s *Server) emitEvent(sc *sandboxConn, ctx EventContext, point Point) {
	data, err := EncodeEvent(ctx, point.Raw)
	if err != nil {
		s.stats.DropContextSize.Add(1)
		return
	}
	if err := s.emit(sc.id, data, pointTime(point)); err != nil {
		if errors.Is(err, ErrSourceClosed) {
			return
		}
		sc.drops++
		if errors.Is(err, ErrQueueShare) {
			s.stats.DropQueueShare.Add(1)
		} else {
			s.stats.DropChannelFull.Add(1)
		}
		return
	}
	s.stats.Events.Add(1)
}

func handshake(conn *net.UnixConn) error {
	if err := conn.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return err
	}
	buf := make([]byte, handshakeBufferSize)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("read handshake: %w", err)
	}
	var in pb.Handshake
	if err := proto.Unmarshal(buf[:n], &in); err != nil {
		return fmt.Errorf("decode handshake: %w", err)
	}
	if in.GetVersion() < minWireVersion || in.GetVersion() > wire.CurrentVersion {
		return fmt.Errorf("%w: %d", errUnsupportedHandshake, in.GetVersion())
	}
	out, err := proto.Marshal(&pb.Handshake{Version: wire.CurrentVersion})
	if err != nil {
		return fmt.Errorf("encode handshake: %w", err)
	}
	if _, err := conn.Write(out); err != nil {
		return fmt.Errorf("write handshake: %w", err)
	}
	return conn.SetDeadline(time.Time{})
}

func removeStaleSocket(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if info.Mode().Type() != fs.ModeSocket {
		return fmt.Errorf("%s exists and is not a socket", path)
	}
	dialer := &net.Dialer{Timeout: staleProbeTimeout}
	if conn, err := dialer.DialContext(context.Background(), networkUnixPacket, path); err == nil {
		_ = conn.Close()
		return fmt.Errorf("%w: %s", errSocketInUse, path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale socket %s: %w", path, err)
	}
	return nil
}

func pointContainerID(p Point) string {
	if start, ok := p.Msg.(*pb.Start); ok && start.GetId() != "" {
		return start.GetId()
	}
	return p.Context().GetContainerId()
}

func pointTime(p Point) time.Time {
	if ns := p.Context().GetTimeNs(); ns > 0 {
		return time.Unix(0, ns)
	}
	return time.Now()
}

func (sc *sandboxConn) addContainer(id string) bool {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if _, seen := sc.containerIDs[id]; seen {
		return false
	}
	if len(sc.idOrder) >= maxConnContainers {
		delete(sc.containerIDs, sc.idOrder[0])
		sc.idOrder = sc.idOrder[1:]
	}
	sc.containerIDs[id] = struct{}{}
	sc.idOrder = append(sc.idOrder, id)
	return true
}

func (sc *sandboxConn) logDrops() {
	if sc.drops == 0 {
		return
	}
	info := sc.info()
	ids := make([]string, 0, len(info.ContainerIDs))
	for _, id := range info.ContainerIDs {
		ids = append(ids, shortID(id))
	}
	logger.Printf("sandbox connection %d (containers %v) dropped %d events: event queue or its share full", sc.id, ids, sc.drops)
}

func (sc *sandboxConn) info() ConnInfo {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	ids := make([]string, 0, len(sc.containerIDs))
	for id := range sc.containerIDs {
		ids = append(ids, id)
	}
	return ConnInfo{PeerPID: sc.peerPID, ContainerIDs: ids, Since: sc.since}
}
