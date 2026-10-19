package gvisor

import (
	"errors"
	"fmt"
	"runtime"

	"google.golang.org/protobuf/proto"
	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
	"gvisor.dev/gvisor/pkg/sentry/seccheck/sinks/remote/wire"
)

var (
	errShortMessage    = errors.New("message shorter than wire header")
	errBadHeaderSize   = errors.New("invalid wire header size")
	errUnsupportedType = errors.New("unsupported message type")
)

// Point is a decoded gVisor trace point.
type Point struct {
	Type    pb.MessageType
	Dropped uint32
	Msg     proto.Message
	Raw     []byte
	Arch    string

	header []byte
}

type contextual interface {
	GetContextData() *pb.ContextData
}

type syscallMessage interface {
	GetSysno() uint64
	GetExit() *pb.Exit
}

var messageFactories = map[pb.MessageType]func() proto.Message{
	pb.MessageType_MESSAGE_CONTAINER_START:           func() proto.Message { return &pb.Start{} },
	pb.MessageType_MESSAGE_SENTRY_CLONE:              func() proto.Message { return &pb.CloneInfo{} },
	pb.MessageType_MESSAGE_SENTRY_EXEC:               func() proto.Message { return &pb.ExecveInfo{} },
	pb.MessageType_MESSAGE_SENTRY_EXIT_NOTIFY_PARENT: func() proto.Message { return &pb.ExitNotifyParentInfo{} },
	pb.MessageType_MESSAGE_SENTRY_TASK_EXIT:          func() proto.Message { return &pb.TaskExit{} },
	pb.MessageType_MESSAGE_SYSCALL_RAW:               func() proto.Message { return &pb.Syscall{} },
	pb.MessageType_MESSAGE_SYSCALL_OPEN:              func() proto.Message { return &pb.Open{} },
	pb.MessageType_MESSAGE_SYSCALL_CONNECT:           func() proto.Message { return &pb.Connect{} },
	pb.MessageType_MESSAGE_SYSCALL_EXECVE:            func() proto.Message { return &pb.Execve{} },
	pb.MessageType_MESSAGE_SYSCALL_SOCKET:            func() proto.Message { return &pb.Socket{} },
	pb.MessageType_MESSAGE_SYSCALL_CHDIR:             func() proto.Message { return &pb.Chdir{} },
	pb.MessageType_MESSAGE_SYSCALL_CLONE:             func() proto.Message { return &pb.Clone{} },
	pb.MessageType_MESSAGE_SYSCALL_BIND:              func() proto.Message { return &pb.Bind{} },
	pb.MessageType_MESSAGE_SYSCALL_ACCEPT:            func() proto.Message { return &pb.Accept{} },
	pb.MessageType_MESSAGE_SYSCALL_LISTEN:            func() proto.Message { return &pb.Listen{} },
	pb.MessageType_MESSAGE_SYSCALL_PTRACE:            func() proto.Message { return &pb.Ptrace{} },
	pb.MessageType_MESSAGE_SYSCALL_SETID:             func() proto.Message { return &pb.Setid{} },
	pb.MessageType_MESSAGE_SYSCALL_SETRESID:          func() proto.Message { return &pb.Setresid{} },
}

// DecodePoint parses one seqpacket message: a wire header followed by a
// protobuf payload. Environment variables are stripped before the point is
// returned, and Raw is re-encoded when that changes the payload.
func DecodePoint(msg []byte) (Point, error) {
	if len(msg) < wire.HeaderStructSize {
		return Point{}, errShortMessage
	}
	var hdr wire.Header
	hdr.UnmarshalBytes(msg[:wire.HeaderStructSize])
	if int(hdr.HeaderSize) < wire.HeaderStructSize || int(hdr.HeaderSize) > len(msg) {
		return Point{}, fmt.Errorf("%w: %d", errBadHeaderSize, hdr.HeaderSize)
	}
	msgType := pb.MessageType(hdr.MessageType)
	factory, ok := messageFactories[msgType]
	if !ok {
		return Point{}, fmt.Errorf("%w: %d", errUnsupportedType, hdr.MessageType)
	}
	payload := msg[hdr.HeaderSize:]
	decoded := factory()
	if err := proto.Unmarshal(payload, decoded); err != nil {
		return Point{}, fmt.Errorf("unmarshal %s: %w", msgType, err)
	}
	p := Point{Type: msgType, Dropped: hdr.DroppedCount, Msg: decoded, Raw: msg, Arch: runtime.GOARCH, header: msg[:hdr.HeaderSize]}
	if scrubEnvironment(decoded) {
		if err := p.reencode(); err != nil {
			return Point{}, err
		}
	}
	return p, nil
}

// Context returns the point's common context data, or nil when absent.
func (p Point) Context() *pb.ContextData {
	if c, ok := p.Msg.(contextual); ok {
		return c.GetContextData()
	}
	return nil
}

func scrubEnvironment(msg proto.Message) bool {
	switch m := msg.(type) {
	case *pb.Start:
		if len(m.Env) > 0 {
			m.Env = nil
			return true
		}
	case *pb.ExecveInfo:
		if len(m.Env) > 0 {
			m.Env = nil
			return true
		}
	case *pb.Execve:
		if len(m.Envv) > 0 {
			m.Envv = nil
			return true
		}
	}
	return false
}

// reencode rebuilds Raw from the (modified) message, keeping the original
// wire header bytes so header fields a newer gVisor adds are preserved.
func (p *Point) reencode() error {
	payload, err := proto.Marshal(p.Msg)
	if err != nil {
		return fmt.Errorf("marshal %s: %w", p.Type, err)
	}
	raw := make([]byte, 0, len(p.header)+len(payload))
	raw = append(raw, p.header...)
	raw = append(raw, payload...)
	p.Raw = raw
	p.header = p.Raw[:len(p.header)]
	return nil
}

func encodePacket(msgType pb.MessageType, dropped uint32, msg proto.Message) ([]byte, error) {
	payload, err := proto.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("marshal %s: %w", msgType, err)
	}
	hdr := wire.Header{
		HeaderSize:   wire.HeaderStructSize,
		MessageType:  uint16(msgType),
		DroppedCount: dropped,
	}
	out := make([]byte, wire.HeaderStructSize, wire.HeaderStructSize+len(payload))
	hdr.MarshalBytes(out)
	return append(out, payload...), nil
}
