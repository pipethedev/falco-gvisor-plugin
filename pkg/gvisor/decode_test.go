package gvisor

import (
	"bytes"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"
	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
	"gvisor.dev/gvisor/pkg/sentry/seccheck/sinks/remote/wire"
)

func TestDecodePointTypes(t *testing.T) {
	ctx := testContext(42, 1, "sh")
	cases := []struct {
		msgType   pb.MessageType
		msg       proto.Message
		wantType  string
		wantPoint string
	}{
		{pb.MessageType_MESSAGE_CONTAINER_START, &pb.Start{ContextData: ctx, Id: testContainerID, Args: []string{"sh"}}, "container_start", "container/start"},
		{pb.MessageType_MESSAGE_SENTRY_CLONE, &pb.CloneInfo{ContextData: ctx, CreatedThreadGroupId: 43}, "sentry_clone", "sentry/clone"},
		{pb.MessageType_MESSAGE_SENTRY_EXEC, &pb.ExecveInfo{ContextData: ctx, BinaryPath: "/bin/ls", Argv: []string{"ls"}}, "sentry_execve", "sentry/execve"},
		{pb.MessageType_MESSAGE_SENTRY_TASK_EXIT, &pb.TaskExit{ContextData: ctx, ExitStatus: 1}, "task_exit", "sentry/task_exit"},
		{pb.MessageType_MESSAGE_SENTRY_EXIT_NOTIFY_PARENT, &pb.ExitNotifyParentInfo{ContextData: ctx}, "exit_notify_parent", "sentry/exit_notify_parent"},
		{pb.MessageType_MESSAGE_SYSCALL_CONNECT, &pb.Connect{ContextData: ctx, Sysno: sysnoOf(t, "connect"), Exit: &pb.Exit{}}, "connect", "syscall/connect/exit"},
		{pb.MessageType_MESSAGE_SYSCALL_SOCKET, &pb.Socket{ContextData: ctx, Sysno: sysnoOf(t, "socket"), Exit: &pb.Exit{Result: 3}}, "socket", "syscall/socket/exit"},
		{pb.MessageType_MESSAGE_SYSCALL_OPEN, &pb.Open{ContextData: ctx, Sysno: sysnoOf(t, "openat"), Pathname: "/etc/passwd"}, "openat", "syscall/openat/enter"},
		{pb.MessageType_MESSAGE_SYSCALL_EXECVE, &pb.Execve{ContextData: ctx, Sysno: sysnoOf(t, "execve"), Exit: &pb.Exit{}}, "execve", "syscall/execve/exit"},
		{pb.MessageType_MESSAGE_SYSCALL_PTRACE, &pb.Ptrace{ContextData: ctx, Sysno: sysnoOf(t, "ptrace"), Exit: &pb.Exit{}}, "ptrace", "syscall/ptrace/exit"},
		{pb.MessageType_MESSAGE_SYSCALL_RAW, &pb.Syscall{ContextData: ctx, Sysno: 99999}, "syscall_99999", "syscall/syscall_99999/enter"},
	}
	for _, tc := range cases {
		t.Run(tc.msgType.String(), func(t *testing.T) {
			p := mustPoint(t, tc.msgType, tc.msg)
			if p.Type != tc.msgType {
				t.Errorf("type = %v", p.Type)
			}
			if !proto.Equal(p.Msg, tc.msg) {
				t.Errorf("round trip mismatch: %v != %v", p.Msg, tc.msg)
			}
			if got := p.Context().GetThreadGroupId(); got != 42 {
				t.Errorf("context tgid = %d", got)
			}
			if got := p.EventType(); got != tc.wantType {
				t.Errorf("EventType = %q, want %q", got, tc.wantType)
			}
			if got := p.PointName(); got != tc.wantPoint {
				t.Errorf("PointName = %q, want %q", got, tc.wantPoint)
			}
		})
	}
}

func TestDecodePointErrors(t *testing.T) {
	valid := mustPacket(t, pb.MessageType_MESSAGE_SENTRY_EXEC, &pb.ExecveInfo{BinaryPath: "/bin/sh"})
	badHeader := append([]byte(nil), valid...)
	badHeader[0] = 0xff
	unknown := mustPacket(t, pb.MessageType_MESSAGE_SYSCALL_TIMERFD_GETTIME, &pb.Syscall{})
	garbage := append(append([]byte(nil), valid[:wire.HeaderStructSize]...), 0xff, 0xff, 0xff)

	cases := map[string]struct {
		msg  []byte
		want error
	}{
		"empty":       {nil, errShortMessage},
		"short":       {valid[:3], errShortMessage},
		"header size": {badHeader, errBadHeaderSize},
		"unsupported": {unknown, errUnsupportedType},
		"garbage":     {garbage, nil},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := DecodePoint(tc.msg)
			if err == nil {
				t.Fatal("expected error")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestDecodePointScrubsEnvironment(t *testing.T) {
	cases := []struct {
		msgType pb.MessageType
		msg     proto.Message
	}{
		{pb.MessageType_MESSAGE_CONTAINER_START, &pb.Start{Env: []string{"SECRET=1"}}},
		{pb.MessageType_MESSAGE_SENTRY_EXEC, &pb.ExecveInfo{Env: []string{"SECRET=1"}}},
		{pb.MessageType_MESSAGE_SYSCALL_EXECVE, &pb.Execve{Envv: []string{"SECRET=1"}}},
	}
	for _, tc := range cases {
		p := mustPoint(t, tc.msgType, tc.msg)
		again, err := DecodePoint(p.Raw)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range []proto.Message{p.Msg, again.Msg} {
			switch v := m.(type) {
			case *pb.Start:
				if len(v.Env) > 0 {
					t.Error("start env kept")
				}
			case *pb.ExecveInfo:
				if len(v.Env) > 0 {
					t.Error("execve info env kept")
				}
			case *pb.Execve:
				if len(v.Envv) > 0 {
					t.Error("execve envv kept")
				}
			}
		}
	}
}

func TestReencodeKeepsExtendedHeader(t *testing.T) {
	payload, err := proto.Marshal(&pb.ExecveInfo{BinaryPath: "/bin/sh", Env: []string{"SECRET=1"}})
	if err != nil {
		t.Fatal(err)
	}
	const extended = wire.HeaderStructSize + 4
	hdr := wire.Header{HeaderSize: extended, MessageType: uint16(pb.MessageType_MESSAGE_SENTRY_EXEC), DroppedCount: 7}
	pkt := make([]byte, extended)
	hdr.MarshalBytes(pkt)
	copy(pkt[wire.HeaderStructSize:], []byte{0xaa, 0xbb, 0xcc, 0xdd})
	pkt = append(pkt, payload...)

	p, err := DecodePoint(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p.Raw[:extended], pkt[:extended]) {
		t.Errorf("re-encoding after stripping env lost the extended header: % x", p.Raw[:extended])
	}
	again, err := DecodePoint(p.Raw)
	if err != nil || again.Dropped != 7 || len(again.Msg.(*pb.ExecveInfo).GetEnv()) != 0 {
		t.Errorf("re-encoded packet: %v, dropped=%d", err, again.Dropped)
	}
}

func FuzzDecodePoint(f *testing.F) {
	f.Add(mustPacket(f, pb.MessageType_MESSAGE_SENTRY_EXEC, &pb.ExecveInfo{BinaryPath: "/bin/sh", Argv: []string{"sh", "-c"}}))
	f.Add(mustPacket(f, pb.MessageType_MESSAGE_SYSCALL_CONNECT, &pb.Connect{Address: []byte{2, 0, 0, 80, 1, 2, 3, 4}}))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, msg []byte) {
		p, err := DecodePoint(msg)
		if err != nil {
			return
		}
		_ = p.EventType()
		_ = p.PointName()
		_ = p.Context()
	})
}
