package gvisor

import (
	"testing"
	"time"

	"go.uber.org/goleak"

	"google.golang.org/protobuf/proto"
	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
)

const (
	testWait        = 5 * time.Second
	testContainerID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

func testContext(tgid, ppid int32, comm string) *pb.ContextData {
	return &pb.ContextData{
		TimeNs:              1_700_000_000_000_000_000,
		ThreadId:            tgid,
		ThreadGroupId:       tgid,
		ParentThreadGroupId: ppid,
		ContainerId:         testContainerID,
		ProcessName:         comm,
		Cwd:                 "/app",
		Credentials:         &pb.Credentials{RealUid: 1000, EffectiveUid: 1000, RealGid: 1000, EffectiveGid: 1000},
	}
}

func mustPacket(t testing.TB, msgType pb.MessageType, msg proto.Message) []byte {
	t.Helper()
	pkt, err := encodePacket(msgType, 0, msg)
	if err != nil {
		t.Fatal(err)
	}
	return pkt
}

func mustPoint(t testing.TB, msgType pb.MessageType, msg proto.Message) Point {
	t.Helper()
	p, err := DecodePoint(mustPacket(t, msgType, msg))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func sysnoOf(t testing.TB, name string) uint64 {
	t.Helper()
	for nr, n := range syscallNames {
		if n == name {
			return nr
		}
	}
	t.Fatalf("no syscall %q on this arch", name)
	return 0
}

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(testWait)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
