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
	worker := testContext(2, 1, "xmrig")
	worker.ThreadId = 9
	sibling := table.Apply(mustPoint(t, pb.MessageType_MESSAGE_SYSCALL_CONNECT, &pb.Connect{ContextData: worker, Exit: &pb.Exit{}}))
	if p := sibling.Process; p.ExePath != "/tmp/xmrig" || !p.UpperLayer || p.SHA256 != "dead" {
		t.Errorf("a thread still running after its leader exited lost the process identity: %+v", p)
	}
}

func TestProcessTableEvictsExitedFirst(t *testing.T) {
	table := NewProcessTable(2)
	table.Apply(execPoint(t, 2, 1, "/usr/bin/live", "live"))
	table.Apply(execPoint(t, 3, 1, "/usr/bin/done", "done"))
	table.Apply(exitPoint(t, 3, 3))
	table.Apply(execPoint(t, 4, 1, "/usr/bin/new", "new"))
	if _, ok := table.lookup(2); !ok {
		t.Error("a live process was evicted before one that had exited")
	}
	if _, ok := table.lookup(3); ok {
		t.Error("the exited process was not evicted first")
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
	execExit := func(pid int32, comm, pathname string, errno int64, argv ...string) Snapshot {
		return table.Apply(mustPoint(t, pb.MessageType_MESSAGE_SYSCALL_EXECVE, &pb.Execve{
			ContextData: testContext(pid, 1, comm), Exit: &pb.Exit{Errorno: errno}, Fd: linux.AT_FDCWD, Pathname: pathname, Argv: argv,
		}))
	}
	connect := func(pid int32, comm string) Snapshot {
		return table.Apply(mustPoint(t, pb.MessageType_MESSAGE_SYSCALL_CONNECT, &pb.Connect{ContextData: testContext(pid, 1, comm), Exit: &pb.Exit{}}))
	}

	table.Apply(execPoint(t, 6, 1, "/bin/sh", "sh"))
	exit := execExit(6, "sh", "/bin/cat", 0, "cat")
	sentry := table.Apply(mustPoint(t, pb.MessageType_MESSAGE_SENTRY_EXEC, &pb.ExecveInfo{
		ContextData: testContext(6, 1, "cat"), BinaryPath: "/usr/bin/busybox", Execfn: "/bin/cat", Argv: []string{"cat"},
		BinaryMode: 0o755, BinaryOverlayfsLower: true,
	}))
	after := connect(6, "cat")
	if exit.Process.ExePath != "/bin/sh" || exit.ExecFallback {
		t.Errorf("the execve exit, sent before the image loads, changed the process: %+v", exit.Process)
	}
	if p := sentry.Process; p.ExePath != "/usr/bin/busybox" || !p.LowerLayer || sentry.ExecFallback || after.ExecFallback {
		t.Errorf("an exec reported by both points was treated as a fallback or lost its details: %+v", p)
	}

	table.Apply(execPoint(t, 7, 1, "/bin/sh", "sh"))
	execExit(7, "sh", "/no/such/xmrig", 0, "/no/such/xmrig", "--donate-level", "1")
	failed := connect(7, "sh")
	if failed.ExecFallback || failed.Process.ExePath != "/bin/sh" || failed.Process.Args() != "" {
		t.Errorf("an exec whose image never loaded was reported as a program change: %+v, fallback %v", failed.Process, failed.ExecFallback)
	}

	execExit(7, "sh", "update", 0, "./update", "-q")
	missed := table.Apply(mustPoint(t, pb.MessageType_MESSAGE_SENTRY_TASK_EXIT, &pb.TaskExit{ContextData: testContext(7, 1, "update")}))
	p := missed.Process
	if !missed.ExecFallback || p.ExePath != "/app/update" || p.Comm != "update" || p.Args() != "-q" || p.HasBinaryInfo {
		t.Errorf("an exec renamed by gVisor whose sentry point was lost must show the new program: %+v, fallback %v", p, missed.ExecFallback)
	}

	table.Apply(execPoint(t, 8, 1, "/bin/sh", "sh"))
	execExit(8, "sh", "/bin/sh", 0, "sh", "-c", "id")
	if same := connect(8, "sh"); same.ExecFallback {
		t.Error("an exec of a program with the same name cannot be confirmed and must not be flagged")
	}
	execExit(8, "sh", "/nope", 2)
	if errored := connect(8, "sh"); errored.ExecFallback || errored.Process.ExePath != "/bin/sh" {
		t.Error("an execve that failed at the syscall changed the process or was flagged")
	}

	execExit(8, "sh", "/bin/ls", 0, "ls")
	table.Apply(mustPoint(t, pb.MessageType_MESSAGE_SENTRY_CLONE, &pb.CloneInfo{ContextData: testContext(8, 1, "sh"), CreatedThreadGroupId: 9, CreatedThreadId: 9}))
	if child := connect(9, "ls"); child.ExecFallback {
		t.Error("a child inherited its parent's pending exec")
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

func TestProcessTablePendingExecAcrossThreads(t *testing.T) {
	ctxOf := func(tgid, tid int32, comm string) *pb.ContextData {
		ctx := testContext(tgid, 1, comm)
		ctx.ThreadId = tid
		return ctx
	}
	apply := func(table *ProcessTable, ctx *pb.ContextData, msg *pb.Execve) Snapshot {
		if msg != nil {
			msg.ContextData = ctx
			return table.Apply(mustPoint(t, pb.MessageType_MESSAGE_SYSCALL_EXECVE, msg))
		}
		return table.Apply(mustPoint(t, pb.MessageType_MESSAGE_SYSCALL_CONNECT, &pb.Connect{ContextData: ctx, Exit: &pb.Exit{}}))
	}

	threads := NewProcessTable(defaultMaxTrackedProcess)
	threads.Apply(execPoint(t, 10, 1, "/usr/bin/java", "java"))
	apply(threads, ctxOf(10, 12, "worker-2"), &pb.Execve{Exit: &pb.Exit{}, Pathname: "/tmp/xmrig", Argv: []string{"xmrig", "-o", "pool:3333"}})
	for _, sibling := range []*pb.ContextData{ctxOf(10, 10, "java"), ctxOf(10, 11, "worker-1")} {
		if snap := apply(threads, sibling, nil); snap.ExecFallback {
			t.Errorf("a sibling thread running during the image load resolved the exec: %+v", sibling)
		}
	}
	if snap := apply(threads, ctxOf(10, 10, "xmrig"), nil); !snap.ExecFallback || snap.Process.ExePath != "/tmp/xmrig" {
		t.Errorf("an exec from a non-leader thread was lost to its siblings' events: %+v", snap.Process)
	}

	script := NewProcessTable(defaultMaxTrackedProcess)
	script.Apply(execPoint(t, 20, 1, "/bin/bash", "bash"))
	apply(script, ctxOf(20, 20, "bash"), &pb.Execve{Exit: &pb.Exit{}, Pathname: "/tmp/run.sh", Argv: []string{"/tmp/run.sh"}})
	if snap := apply(script, ctxOf(20, 20, "sh"), nil); !snap.ExecFallback || snap.Process.ExePath != "/tmp/run.sh" || snap.Process.Comm != "sh" {
		t.Errorf("a script exec, named after its interpreter, was not confirmed: %+v", snap.Process)
	}

	fd := NewProcessTable(defaultMaxTrackedProcess)
	fd.Apply(execPoint(t, 30, 1, "/bin/sh", "sh"))
	apply(fd, ctxOf(30, 30, "sh"), &pb.Execve{Exit: &pb.Exit{}, Fd: 3, FdPath: "/tmp/payload", Argv: []string{"kworker"}})
	if snap := apply(fd, ctxOf(30, 30, "3"), nil); !snap.ExecFallback || snap.Process.ExePath != "/tmp/payload" {
		t.Errorf("an fd-only execveat was not confirmed with its fd_path: %+v", snap.Process)
	}
}

func TestProcessTableKeepsGroupWithLiveThreads(t *testing.T) {
	table := NewProcessTable(2)
	table.Apply(execPoint(t, 2, 1, "/usr/bin/server", "server"))
	table.Apply(mustPoint(t, pb.MessageType_MESSAGE_SENTRY_CLONE, &pb.CloneInfo{ContextData: testContext(2, 1, "server"), CreatedThreadGroupId: 2, CreatedThreadId: 5}))
	table.Apply(execPoint(t, 3, 1, "/usr/bin/other", "other"))
	table.Apply(exitPoint(t, 2, 2))
	table.Apply(execPoint(t, 4, 1, "/usr/bin/new", "new"))
	if _, ok := table.lookup(2); !ok {
		t.Error("a group whose leader exited while a known thread runs was evicted first")
	}

	table.Apply(exitPoint(t, 2, 5))
	table.Apply(exitPoint(t, 2, 2))
	table.Apply(execPoint(t, 6, 1, "/usr/bin/later", "later"))
	if _, ok := table.lookup(2); ok {
		t.Error("a group whose last known thread exited was not evicted first")
	}
}

func tableBytesConsistent(t *testing.T, table *ProcessTable) {
	t.Helper()
	var sum int64
	for pid, size := range table.sizes {
		if _, ok := table.lookup(pid); !ok {
			t.Errorf("pid %d has a size but no row", pid)
		}
		sum += size
	}
	if sum != table.bytes {
		t.Errorf("table bytes = %d, rows add up to %d", table.bytes, sum)
	}
}

func TestProcessTableByteCap(t *testing.T) {
	table := NewProcessTable(defaultMaxTrackedProcess)
	table.maxBytes = 64 << 10
	long := strings.Repeat("a", maxArgvBytes)
	const procs = 100
	for pid := int32(2); pid < 2+procs; pid++ {
		table.Apply(execPoint(t, pid, 1, "/bin/x", long))
	}
	if table.bytes > table.maxBytes {
		t.Errorf("table holds %d bytes, cap %d", table.bytes, table.maxBytes)
	}
	if table.Len() >= procs {
		t.Errorf("no row was evicted: len=%d", table.Len())
	}
	if _, ok := table.lookup(1 + procs); !ok {
		t.Error("the most recent process was evicted")
	}
	tableBytesConsistent(t, table)
}

func TestProcessTablesShareBudget(t *testing.T) {
	budget := &processBudget{limit: 256 << 10}
	hostile := newBudgetedProcessTable(defaultMaxTrackedProcess, budget)
	victim := newBudgetedProcessTable(defaultMaxTrackedProcess, budget)
	for _, table := range []*ProcessTable{hostile, victim} {
		table.floorBytes = 32 << 10
	}
	long := strings.Repeat("a", maxArgvBytes)
	for pid := int32(2); pid < 200; pid++ {
		hostile.Apply(execPoint(t, pid, 1, "/bin/x", long))
	}
	if used := budget.used.Load(); used > budget.limit+maxTableRowBytes(t, hostile) {
		t.Errorf("tables hold %d bytes, budget %d", used, budget.limit)
	}
	for pid := int32(2); pid < 6; pid++ {
		victim.Apply(execPoint(t, pid, 1, "/bin/y", long))
	}
	if victim.Len() != 4 {
		t.Errorf("a table under its floor lost rows: len=%d", victim.Len())
	}
	before := hostile.Len()
	hostile.Apply(execPoint(t, 500, 1, "/bin/x", long))
	if used := budget.used.Load(); used > budget.limit {
		t.Errorf("the table over its floor did not give memory back: tables hold %d bytes, budget %d", used, budget.limit)
	}
	if hostile.Len() >= before {
		t.Errorf("the table over its floor lost no rows: len=%d, was %d", hostile.Len(), before)
	}
	tableBytesConsistent(t, hostile)
	tableBytesConsistent(t, victim)
	hostile.release()
	victim.release()
	if used := budget.used.Load(); used != 0 {
		t.Errorf("released tables still hold %d bytes of the budget", used)
	}
}

func maxTableRowBytes(t *testing.T, table *ProcessTable) int64 {
	t.Helper()
	var largest int64
	for _, size := range table.sizes {
		largest = max(largest, size)
	}
	return largest
}

func TestProcessTableAccountsClonesAndSockets(t *testing.T) {
	table := NewProcessTable(defaultMaxTrackedProcess)
	table.Apply(execPoint(t, 2, 1, "/bin/sh", "sh", strings.Repeat("b", 1000)))
	for fd := int64(3); fd < 20; fd++ {
		table.Apply(mustPoint(t, pb.MessageType_MESSAGE_SYSCALL_SOCKET, &pb.Socket{
			ContextData: testContext(2, 1, "sh"), Domain: linux.AF_INET, Type: int32(linux.SOCK_STREAM),
			Exit: &pb.Exit{Result: fd},
		}))
	}
	table.Apply(clonePoint(t, 2, 1, 3, "sh"))
	if table.sizes[3] < table.sizes[2] {
		t.Errorf("the clone's size %d is below its parent's %d", table.sizes[3], table.sizes[2])
	}
	table.Apply(exitPoint(t, 3, 3))
	table.remove(3)
	tableBytesConsistent(t, table)
}
