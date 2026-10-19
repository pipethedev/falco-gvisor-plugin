package gvisor

import (
	"strings"
	"testing"

	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
)

const benchDepth = maxAncestors + 2

func benchArgv() []string {
	return []string{"/usr/local/bin/app", "--config", "/etc/app/config.yaml", "--listen", ":8080", strings.Repeat("x", 256)}
}

func benchTable(b *testing.B) *ProcessTable {
	b.Helper()
	table := NewProcessTable(defaultMaxTrackedProcess)
	for pid := int32(1); pid <= benchDepth; pid++ {
		table.Apply(mustPoint(b, pb.MessageType_MESSAGE_SENTRY_EXEC, &pb.ExecveInfo{
			ContextData: testContext(pid, pid-1, "app"), BinaryPath: "/usr/local/bin/app", Argv: benchArgv(),
		}))
	}
	return table
}

func benchConnect(b *testing.B) []byte {
	b.Helper()
	return mustPacket(b, pb.MessageType_MESSAGE_SYSCALL_CONNECT, &pb.Connect{
		ContextData: testContext(benchDepth, benchDepth-1, "app"), Exit: &pb.Exit{},
		Address: []byte{2, 0, 1, 187, 10, 0, 0, 1},
	})
}

func BenchmarkDecodePoint(b *testing.B) {
	pkt := benchConnect(b)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := DecodePoint(pkt); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkProcessTableApply(b *testing.B) {
	table := benchTable(b)
	point := mustPoint(b, pb.MessageType_MESSAGE_SYSCALL_CONNECT, &pb.Connect{ContextData: testContext(benchDepth, benchDepth-1, "app"), Exit: &pb.Exit{}})
	b.ReportAllocs()
	for b.Loop() {
		table.Apply(point)
	}
}

func BenchmarkEncodeEvent(b *testing.B) {
	table := benchTable(b)
	pkt := benchConnect(b)
	point, err := DecodePoint(pkt)
	if err != nil {
		b.Fatal(err)
	}
	ctx := EventContext{Snapshot: table.Apply(point), Container: &ContainerInfo{ID: testContainerID, Name: "web", Image: "nginx"}}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := EncodeEvent(ctx, pkt); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSourcePipeline(b *testing.B) {
	table := benchTable(b)
	pkt := benchConnect(b)
	container := &ContainerInfo{ID: testContainerID, Name: "web", Image: "nginx"}
	b.ReportAllocs()
	for b.Loop() {
		point, err := DecodePoint(pkt)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := EncodeEvent(EventContext{Snapshot: table.Apply(point), Container: container}, point.Raw); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeEventAndExtract(b *testing.B) {
	table := benchTable(b)
	pkt := benchConnect(b)
	point, err := DecodePoint(pkt)
	if err != nil {
		b.Fatal(err)
	}
	data, err := EncodeEvent(EventContext{Snapshot: table.Apply(point)}, pkt)
	if err != nil {
		b.Fatal(err)
	}
	fields := []string{fieldEvtType, fieldFDRIP, fieldFDRPort, fieldProcName, fieldProcCmdline, fieldProcPName, fieldContainerID}
	b.ReportAllocs()
	for b.Loop() {
		evt, err := DecodeEvent(data)
		if err != nil {
			b.Fatal(err)
		}
		for _, f := range fields {
			ExtractField(&evt, FieldRequest{Name: f})
		}
	}
}
