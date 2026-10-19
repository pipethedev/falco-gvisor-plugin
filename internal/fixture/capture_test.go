package fixture

import (
	"bytes"
	"errors"
	"testing"

	"github.com/falcosecurity/plugins/plugins/gvisor/pkg/gvisor"
)

const (
	realCaptureFixture = rulesTestsDir + "/attack_real_runsc_drop_exec.json"
	realCaptureArch    = "arm64"
)

type realEvent struct {
	point  string
	comm   string
	exe    string
	upper  bool
	lower  bool
	fdName string
	execFB bool
}

func realCaptureEvents(t *testing.T) []realEvent {
	t.Helper()
	f, err := Load(realCaptureFixture)
	if err != nil {
		t.Fatal(err)
	}
	packets, err := f.Packets()
	if err != nil {
		t.Fatal(err)
	}
	table := gvisor.NewProcessTable(64)
	var events []realEvent
	var lastTime int64
	for i, pkt := range packets {
		p, err := gvisor.DecodePoint(pkt)
		if err != nil {
			t.Fatalf("real packet %d does not decode: %v", i, err)
		}
		p.Arch = realCaptureArch
		if ctx := p.Context(); ctx.GetContainerId() != f.ContainerID || ctx.GetTimeNs() < lastTime {
			t.Fatalf("packet %d: container %q time %d (previous %d)", i, ctx.GetContainerId(), ctx.GetTimeNs(), lastTime)
		} else {
			lastTime = ctx.GetTimeNs()
		}
		data, err := gvisor.EncodeEvent(gvisor.EventContext{Snapshot: table.Apply(p), Arch: realCaptureArch}, p.Raw)
		if err != nil {
			t.Fatal(err)
		}
		evt, err := gvisor.DecodeEvent(data)
		if err != nil {
			t.Fatal(err)
		}
		str := func(name string) string {
			v, _ := gvisor.ExtractField(&evt, gvisor.FieldRequest{Name: name})
			s, _ := v.(string)
			return s
		}
		flag := func(name string) bool {
			v, _ := gvisor.ExtractField(&evt, gvisor.FieldRequest{Name: name})
			b, _ := v.(bool)
			return b
		}
		events = append(events, realEvent{
			point: str("gvisor.point"), comm: str("proc.name"), exe: str("proc.exepath"),
			upper: flag("proc.is_exe_upper_layer"), lower: flag("proc.is_exe_lower_layer"), fdName: str("fd.name"),
			execFB: flag("gvisor.is_exec_fallback"),
		})
	}
	return events
}

func TestRealRunscCaptureSemantics(t *testing.T) {
	events := realCaptureEvents(t)
	want := []struct {
		name  string
		match func(realEvent) bool
	}{
		{"dropped binary exec flagged upper, not lower", func(e realEvent) bool {
			return e.point == "sentry/execve" && e.exe == "/tmp/update" && e.comm == "update" && e.upper && !e.lower
		}},
		{"busybox applet keeps its invoked name, image binary on lower layer", func(e realEvent) bool {
			return e.point == "sentry/execve" && e.comm == "cat" && e.exe == "/usr/bin/busybox" && e.lower && !e.upper
		}},
		{"openat resolves the opened path", func(e realEvent) bool {
			return e.point == "syscall/openat/exit" && e.comm == "cat" && e.fdName == "/etc/passwd"
		}},
		{"the copy writes the dropped binary", func(e realEvent) bool {
			return e.point == "syscall/openat/exit" && e.comm == "cp" && e.fdName == "/tmp/update"
		}},
		{"leader exit carries the exited process", func(e realEvent) bool {
			return e.point == "sentry/task_exit" && e.comm == "update"
		}},
	}
	syscallExecs := 0
	for _, e := range events {
		if e.point == "syscall/execve/exit" {
			syscallExecs++
		}
		if e.execFB {
			t.Errorf("real capture: %s %s flagged as an exec fallback though no sentry/execve point was dropped", e.comm, e.point)
		}
	}
	if syscallExecs == 0 {
		t.Error("real capture has no syscall exec exits to check the fallback flag against")
	}
	for _, w := range want {
		found := false
		for _, e := range events {
			found = found || w.match(e)
		}
		if !found {
			t.Errorf("real capture: no event where %s", w.name)
		}
	}
}

func TestCaptureRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteCaptureHeader(&buf); err != nil {
		t.Fatal(err)
	}
	for _, pkt := range [][]byte{{1, 2, 3}, {}, {4}} {
		if err := WriteCapturedPacket(&buf, pkt); err != nil {
			t.Fatal(err)
		}
	}
	packets, err := ReadCapture(&buf)
	if err != nil || len(packets) != 3 || len(packets[0]) != 3 || packets[2][0] != 4 {
		t.Fatalf("round trip = %v, %v", packets, err)
	}
	if _, err := ReadCapture(bytes.NewReader([]byte("nope"))); !errors.Is(err, errNotCapture) {
		t.Errorf("bad magic err = %v", err)
	}
}
