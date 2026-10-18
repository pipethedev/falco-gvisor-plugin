package gvisor

import (
	"encoding/binary"
	"errors"
	"reflect"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
)

func TestEnvelopeRoundTrip(t *testing.T) {
	msg := &pb.ExecveInfo{ContextData: testContext(2, 1, "sh"), BinaryPath: "/bin/sh"}
	packet := mustPacket(t, pb.MessageType_MESSAGE_SENTRY_EXEC, msg)
	ctx := EventContext{
		Snapshot: Snapshot{
			Process:   ProcessInfo{Pid: 2, Ppid: 1, Comm: "sh", Argv: []string{"sh", "-c", "id"}},
			Ancestors: []ProcessInfo{{Pid: 1, Comm: "init"}},
		},
		Container: &ContainerInfo{ID: testContainerID, Name: "web", Labels: map[string]string{"app": "web"}},
	}
	data, err := EncodeEvent(ctx, packet)
	if err != nil {
		t.Fatal(err)
	}
	evt, err := DecodeEvent(data)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(evt.Context, ctx) {
		t.Errorf("context mismatch:\n got %+v\nwant %+v", evt.Context, ctx)
	}
	if !proto.Equal(evt.Point.Msg, msg) {
		t.Errorf("point mismatch")
	}
}

func TestEnvelopeSizeCap(t *testing.T) {
	bigArg := strings.Repeat("x", maxArgvBytes)
	ancestors := make([]ProcessInfo, maxAncestors)
	for i := range ancestors {
		ancestors[i] = ProcessInfo{Pid: int32(i + 10), Comm: "sh", Argv: []string{"sh", bigArg}}
	}
	labels := map[string]string{}
	for i := range 64 {
		labels[strings.Repeat("k", i+1)] = strings.Repeat("v", 512)
	}
	ctx := EventContext{
		Snapshot:  Snapshot{Process: ProcessInfo{Pid: 1, Argv: []string{"x", bigArg}}, Ancestors: ancestors},
		Container: &ContainerInfo{ID: testContainerID, Labels: labels},
	}
	data, err := EncodeEvent(ctx, mustPacket(t, pb.MessageType_MESSAGE_SENTRY_TASK_EXIT, &pb.TaskExit{}))
	if err != nil {
		t.Fatal(err)
	}
	if ctxLen := binary.LittleEndian.Uint32(data[len(envelopeMagic):]); ctxLen > maxContextBytes {
		t.Errorf("context %d bytes exceeds cap", ctxLen)
	}
	evt, err := DecodeEvent(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range evt.Context.Ancestors {
		if a.Argv != nil {
			t.Error("ancestor argv should be dropped first")
		}
	}
	if len(evt.Context.Process.Argv) != 2 {
		t.Error("process argv should survive when ancestors suffice")
	}
	if len(ctx.Ancestors[0].Argv) != 2 {
		t.Error("input context was mutated")
	}
}

func TestEnvelopeRejects(t *testing.T) {
	packet := mustPacket(t, pb.MessageType_MESSAGE_SENTRY_TASK_EXIT, &pb.TaskExit{})
	good, err := EncodeEvent(EventContext{}, packet)
	if err != nil {
		t.Fatal(err)
	}
	badLen := append([]byte(nil), good...)
	binary.LittleEndian.PutUint32(badLen[len(envelopeMagic):], 1<<30)

	for name, data := range map[string][]byte{
		"empty":      nil,
		"bad magic":  append([]byte("XXXX"), good[len(envelopeMagic):]...),
		"bad length": badLen,
	} {
		if _, err := DecodeEvent(data); !errors.Is(err, errNotEnvelope) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func FuzzDecodeEvent(f *testing.F) {
	good, err := EncodeEvent(EventContext{}, mustPacket(f, pb.MessageType_MESSAGE_SENTRY_TASK_EXIT, &pb.TaskExit{}))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good)
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = DecodeEvent(data)
	})
}

func TestEnvelopeArchSelectsSyscallTable(t *testing.T) {
	cases := []struct {
		arch  string
		sysno uint64
	}{
		{"amd64", 42},
		{"arm64", 203},
	}
	for _, tc := range cases {
		packet := mustPacket(t, pb.MessageType_MESSAGE_SYSCALL_CONNECT, &pb.Connect{ContextData: testContext(1, 0, "c"), Sysno: tc.sysno, Exit: &pb.Exit{}})
		data, err := EncodeEvent(EventContext{Arch: tc.arch}, packet)
		if err != nil {
			t.Fatal(err)
		}
		evt, err := DecodeEvent(data)
		if err != nil {
			t.Fatal(err)
		}
		if got := evt.Point.EventType(); got != "connect" {
			t.Errorf("%s sysno %d decoded as %q, want connect", tc.arch, tc.sysno, got)
		}
	}
}
