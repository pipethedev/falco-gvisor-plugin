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
		BinaryMode:           linux.S_IFREG | 0o755,
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
	if exitSnap.Process.ExePath != "/tmp/xmrig" {
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

func TestSnapshotKeepsOnlyParentArgv(t *testing.T) {
	table := NewProcessTable(defaultMaxTrackedProcess)
	table.Apply(execPoint(t, 1, 0, "/bin/init", "init", "--system"))
	table.Apply(execPoint(t, 2, 1, "/bin/sh", "sh", "-c", "run"))
	snap := table.Apply(execPoint(t, 3, 2, "/bin/app", "app"))
	if len(snap.Ancestors) != 2 {
		t.Fatalf("ancestors = %d", len(snap.Ancestors))
	}
	if snap.Ancestors[0].Cmdline() != "sh -c run" {
		t.Errorf("parent argv lost: %q", snap.Ancestors[0].Cmdline())
	}
	if snap.Ancestors[1].Argv != nil || snap.Ancestors[1].Comm != "init" {
		t.Errorf("grandparent should keep its name but not its argv: %+v", snap.Ancestors[1])
	}
}

func TestBudgetArgv(t *testing.T) {
	long := strings.Repeat("a", maxArgvBytes*2)
	got := budgetArgv([]string{"cmd", long, "tail"})
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

func TestExecCommUsesInvokedPath(t *testing.T) {
	table := NewProcessTable(defaultMaxTrackedProcess)
	snap := table.Apply(mustPoint(t, pb.MessageType_MESSAGE_SENTRY_EXEC, &pb.ExecveInfo{
		ContextData: testContext(5, 1, "sh"),
		BinaryPath:  "/usr/bin/busybox",
		Execfn:      "/bin/cat",
		Argv:        []string{"cat", "/etc/hosts"},
	}))
	if snap.Process.Comm != "cat" || snap.Process.ExePath != "/usr/bin/busybox" {
		t.Errorf("comm=%q exepath=%q, want comm from execfn and exepath from the resolved binary", snap.Process.Comm, snap.Process.ExePath)
	}
}

func TestTTYEncoding(t *testing.T) {
	cases := map[string]uint32{
		"/dev/pts/3":   34819,
		"/dev/pts/300": 1083436,
		"/dev/tty1":    ttyUnknownNumber,
		"/dev/null":    0,
	}
	for path, want := range cases {
		if got := ttyOf(&pb.FdInfo{Path: path}); got != want {
			t.Errorf("ttyOf(%s) = %d, want %d", path, got, want)
		}
	}
}

func startedContext(pid, ppid int32, comm string, start int64) *pb.ContextData {
	ctx := testContext(pid, ppid, comm)
	ctx.ThreadGroupStartTimeNs = start
	return ctx
}

func TestProcessTablePidReuseReplacesRow(t *testing.T) {
	table := NewProcessTable(defaultMaxTrackedProcess)
	table.Apply(mustPoint(t, pb.MessageType_MESSAGE_SENTRY_EXEC, &pb.ExecveInfo{
		ContextData: startedContext(5, 1, "old", 100), BinaryPath: "/bin/old", Argv: []string{"old", "-x"}, BinaryMode: 0o755,
	}))
	snap := table.Apply(mustPoint(t, pb.MessageType_MESSAGE_SYSCALL_CONNECT, &pb.Connect{
		ContextData: startedContext(5, 1, "new", 200), Exit: &pb.Exit{},
	}))
	if p := snap.Process; p.ExePath != "" || len(p.Argv) != 0 || p.Comm != "new" || p.StartTimeNs != 200 {
		t.Errorf("a reused pid kept the previous process: %+v", p)
	}
}

func TestProcessTableSyscallExec(t *testing.T) {
	table := NewProcessTable(defaultMaxTrackedProcess)
	table.Apply(mustPoint(t, pb.MessageType_MESSAGE_SENTRY_EXEC, &pb.ExecveInfo{
		ContextData: testContext(6, 1, "sh"), BinaryPath: "/usr/bin/busybox", Execfn: "/bin/cat", Argv: []string{"cat"},
		BinaryMode: 0o755, BinaryOverlayfsLower: true,
	}))
	same := table.Apply(mustPoint(t, pb.MessageType_MESSAGE_SYSCALL_EXECVE, &pb.Execve{
		ContextData: testContext(6, 1, "cat"), Exit: &pb.Exit{}, Fd: linux.AT_FDCWD, Pathname: "/bin/cat", Argv: []string{"cat"},
	}))
	if p := same.Process; p.ExePath != "/usr/bin/busybox" || !p.LowerLayer || !p.HasBinaryInfo {
		t.Errorf("the syscall exit of an exec already reported by sentry/execve discarded its details: %+v", p)
	}

	missed := table.Apply(mustPoint(t, pb.MessageType_MESSAGE_SYSCALL_EXECVE, &pb.Execve{
		ContextData: testContext(6, 1, "update"), Exit: &pb.Exit{}, Fd: linux.AT_FDCWD, Pathname: "update", Argv: []string{"./update", "-q"},
	}))
	p := missed.Process
	if p.ExePath != "/app/update" || p.Comm != "update" || p.Args() != "-q" || p.HasBinaryInfo || p.LowerLayer {
		t.Errorf("an exec whose sentry point was dropped must show the new program with unknown binary details: %+v", p)
	}

	failed := table.Apply(mustPoint(t, pb.MessageType_MESSAGE_SYSCALL_EXECVE, &pb.Execve{
		ContextData: testContext(6, 1, "update"), Exit: &pb.Exit{Errorno: 2}, Fd: linux.AT_FDCWD, Pathname: "/nope",
	}))
	if failed.Process.ExePath != "/app/update" {
		t.Error("a failed execve changed the process")
	}
}

func TestProcessTableRefreshesComm(t *testing.T) {
	table := NewProcessTable(defaultMaxTrackedProcess)
	table.Apply(execPoint(t, 7, 1, "/usr/bin/python3", "python3"))
	snap := table.Apply(mustPoint(t, pb.MessageType_MESSAGE_SYSCALL_CONNECT, &pb.Connect{ContextData: testContext(7, 1, "worker-1"), Exit: &pb.Exit{}}))
	if snap.Process.Comm != "worker-1" {
		t.Errorf("comm not refreshed from context after a rename: %q", snap.Process.Comm)
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
