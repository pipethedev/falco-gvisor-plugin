package gvisor

import (
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
)

func clonePoint(t *testing.T, parent, ppid, child int32, comm string) Point {
	t.Helper()
	return mustPoint(t, pb.MessageType_MESSAGE_SENTRY_CLONE, &pb.CloneInfo{
		ContextData:              testContext(parent, ppid, comm),
		CreatedThreadGroupId:     child,
		CreatedThreadId:          child,
		CreatedThreadStartTimeNs: int64(child),
	})
}

func execPoint(t *testing.T, pid, ppid int32, path string, argv ...string) Point {
	t.Helper()
	return mustPoint(t, pb.MessageType_MESSAGE_SENTRY_EXEC, &pb.ExecveInfo{
		ContextData:          testContext(pid, ppid, "x"),
		BinaryPath:           path,
		Argv:                 argv,
		BinarySha256:         []byte{0xde, 0xad},
		BinaryOverlayfsUpper: true,
		Stdin:                &pb.FdInfo{Socket: &pb.SocketInfo{Family: linux.AF_INET}},
		Stdout:               &pb.FdInfo{Mode: linux.S_IFIFO},
		Stderr:               &pb.FdInfo{Mode: linux.S_IFCHR, Path: "/dev/pts/3"},
	})
}

func exitPoint(t *testing.T, pid, tid int32) Point {
	t.Helper()
	ctx := testContext(pid, 1, "x")
	ctx.ThreadId = tid
	return mustPoint(t, pb.MessageType_MESSAGE_SENTRY_TASK_EXIT, &pb.TaskExit{ContextData: ctx})
}

func TestProcessTableLifecycle(t *testing.T) {
	table := NewProcessTable(defaultMaxTrackedProcess)
	table.Apply(execPoint(t, 1, 0, "/bin/sh", "sh"))
	table.Apply(clonePoint(t, 1, 0, 2, "sh"))

	child, ok := table.lookup(2)
	if !ok {
		t.Fatal("cloned child not tracked")
	}
	if child.Ppid != 1 || child.ExePath != "/bin/sh" {
		t.Errorf("child did not inherit parent: %+v", child)
	}

	snap := table.Apply(execPoint(t, 2, 1, "/tmp/xmrig", "/tmp/xmrig", "--donate-level", "1"))
	p := snap.Process
	if p.Comm != "xmrig" || p.Exe() != "/tmp/xmrig" || p.Args() != "--donate-level 1" || p.Cmdline() != "xmrig --donate-level 1" {
		t.Errorf("exec not applied: %+v", p)
	}
	if p.SHA256 != "dead" || !p.UpperLayer || p.StdinType != FDTypeIPv4 || p.StdoutType != FDTypePipe || p.StderrType != FDTypeFile {
		t.Errorf("binary info not applied: %+v", p)
	}
	if p.TTY != ptsMajor<<devMinorBits|3 {
		t.Errorf("tty = %d", p.TTY)
	}
	if len(snap.Ancestors) != 1 || snap.Ancestors[0].Comm != "sh" {
		t.Errorf("ancestors = %+v", snap.Ancestors)
	}

	table.Apply(exitPoint(t, 2, 7))
	if _, ok := table.lookup(2); !ok {
		t.Error("non-leader thread exit removed the process")
	}
	exitSnap := table.Apply(exitPoint(t, 2, 2))
	if exitSnap.Process.Comm != "xmrig" {
		t.Error("exit snapshot lost process state")
	}
	if _, ok := table.lookup(2); ok {
		t.Error("leader exit did not remove the process")
	}
}

func TestProcessTableThreadCloneIgnored(t *testing.T) {
	table := NewProcessTable(defaultMaxTrackedProcess)
	table.Apply(clonePoint(t, 5, 1, 5, "node"))
	if table.Len() != 1 {
		t.Errorf("thread clone created a process: len=%d", table.Len())
	}
}

func TestProcessTableEviction(t *testing.T) {
	const limit = 3
	table := NewProcessTable(limit)
	for pid := int32(1); pid <= 5; pid++ {
		table.Apply(execPoint(t, pid, 0, "/bin/true", "true"))
	}
	if table.Len() != limit {
		t.Fatalf("len = %d, want %d", table.Len(), limit)
	}
	for _, pid := range []int32{1, 2} {
		if _, ok := table.lookup(pid); ok {
			t.Errorf("pid %d should have been evicted", pid)
		}
	}
	table.Apply(execPoint(t, 3, 0, "/bin/true", "true"))
	table.Apply(execPoint(t, 6, 0, "/bin/true", "true"))
	if _, ok := table.lookup(3); !ok {
		t.Error("recently used pid 3 was evicted")
	}
}

func TestProcessTableMissingParent(t *testing.T) {
	table := NewProcessTable(defaultMaxTrackedProcess)
	snap := table.Apply(execPoint(t, 10, 999, "/usr/bin/curl", "curl"))
	if snap.Process.Ppid != 999 || len(snap.Ancestors) != 0 {
		t.Errorf("unexpected snapshot %+v", snap)
	}
}

func TestProcessTableAncestryCapAndCycle(t *testing.T) {
	table := NewProcessTable(defaultMaxTrackedProcess)
	for pid := int32(1); pid <= 12; pid++ {
		table.Apply(execPoint(t, pid, pid-1, "/bin/sh", "sh"))
	}
	if snap := table.Apply(execPoint(t, 12, 11, "/bin/sh", "sh")); len(snap.Ancestors) != maxAncestors {
		t.Errorf("ancestors = %d, want %d", len(snap.Ancestors), maxAncestors)
	}

	table.Apply(execPoint(t, 100, 101, "/bin/a", "a"))
	snap := table.Apply(execPoint(t, 101, 100, "/bin/b", "b"))
	if len(snap.Ancestors) != 1 {
		t.Errorf("cycle not stopped: %d ancestors", len(snap.Ancestors))
	}
}

func TestProcessTableSnapshotIsolated(t *testing.T) {
	table := NewProcessTable(defaultMaxTrackedProcess)
	snap := table.Apply(execPoint(t, 1, 0, "/bin/sh", "sh", "-c", "x"))
	table.Apply(execPoint(t, 1, 0, "/bin/ls", "ls"))
	if snap.Process.ExePath != "/bin/sh" || snap.Process.Argv[1] != "-c" {
		t.Errorf("snapshot mutated by later update: %+v", snap.Process)
	}
}

func TestBudgetArgv(t *testing.T) {
	long := strings.Repeat("a", maxArgvBytes*2)
	got := budgetArgv([]string{"cmd", long, "tail"}, maxArgvBytes)
	total := 0
	for _, a := range got {
		total += len(a)
	}
	if total > maxArgvBytes {
		t.Errorf("argv bytes = %d > %d", total, maxArgvBytes)
	}
	if got[0] != "cmd" || len(got) != 2 {
		t.Errorf("unexpected argv %d entries", len(got))
	}
}

func TestStartPoint(t *testing.T) {
	table := NewProcessTable(defaultMaxTrackedProcess)
	snap := table.Apply(mustPoint(t, pb.MessageType_MESSAGE_CONTAINER_START, &pb.Start{
		ContextData: testContext(1, 0, "init"),
		Id:          testContainerID,
		Args:        []string{"/usr/local/bin/node", "server.js"},
		Cwd:         "/srv",
		Terminal:    true,
	}))
	if snap.Process.Comm != "node" || snap.Process.Cwd != "/srv" || snap.Process.TTY == 0 {
		t.Errorf("start not applied: %+v", snap.Process)
	}
}
