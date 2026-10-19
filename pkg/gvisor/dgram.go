package gvisor

import (
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
	"gvisor.dev/gvisor/pkg/sentry/seccheck/sinks/remote/wire"
)

const baseReadBuffer = 64 << 10

var errOversize = errors.New("datagram exceeds maxEventSize")

// oversizeError describes a datagram that was consumed and discarded
// because it exceeded the size limit.
type oversizeError struct {
	size    int
	msgType pb.MessageType
}

func (e *oversizeError) Error() string {
	return fmt.Sprintf("%v: %d-byte %s", errOversize, e.size, e.msgType)
}

func (e *oversizeError) Unwrap() error { return errOversize }

// datagramReader reads whole seqpacket datagrams of any size up to a limit.
// It peeks at each datagram's length first (MSG_PEEK|MSG_TRUNC), so a
// datagram larger than the usual buffer is read into a buffer of its own
// instead of being truncated, and only datagrams beyond the limit are lost.
type datagramReader struct {
	conn *net.UnixConn
	raw  syscall.RawConn
	buf  []byte
	head [wire.HeaderStructSize]byte
}

func newDatagramReader(conn *net.UnixConn) (*datagramReader, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("raw connection: %w", err)
	}
	return &datagramReader{conn: conn, raw: raw, buf: make([]byte, baseReadBuffer)}, nil
}

// next returns the next datagram. The returned slice is only valid until
// the following call. A datagram larger than limit is consumed and
// reported as an *oversizeError.
func (r *datagramReader) next(limit int) ([]byte, error) {
	size, err := r.peekSize()
	if err != nil {
		return nil, err
	}
	if size == 0 {
		return nil, io.EOF
	}
	if size > limit {
		_, _ = r.conn.Read(r.head[:])
		return nil, &oversizeError{size: size, msgType: r.headType(size)}
	}
	buf := r.buf
	if size > len(buf) {
		buf = make([]byte, size)
	}
	n, err := r.conn.Read(buf[:size])
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (r *datagramReader) peekSize() (int, error) {
	var n int
	var opErr error
	err := r.raw.Read(func(fd uintptr) bool {
		n, _, opErr = unix.Recvfrom(int(fd), r.head[:], unix.MSG_PEEK|unix.MSG_TRUNC)
		return !errors.Is(opErr, unix.EAGAIN)
	})
	if err != nil {
		return 0, err
	}
	return n, opErr
}

func (r *datagramReader) headType(size int) pb.MessageType {
	if size < wire.HeaderStructSize {
		return pb.MessageType_MESSAGE_UNKNOWN
	}
	var hdr wire.Header
	hdr.UnmarshalBytes(r.head[:])
	return pb.MessageType(hdr.MessageType)
}
