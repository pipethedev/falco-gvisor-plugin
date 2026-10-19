package gvisor

import (
	"net"
	"reflect"
	"runtime"
	"testing"

	"google.golang.org/protobuf/proto"
	"gvisor.dev/gvisor/pkg/abi/linux"
	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
)

func sockaddrIPv4(ip net.IP, port uint16) []byte {
	b := []byte{byte(linux.AF_INET), 0, byte(port >> 8), byte(port)}
	return append(b, ip.To4()...)
}

func sockaddrIPv6(ip net.IP, port uint16) []byte {
	b := []byte{byte(linux.AF_INET6), 0, byte(port >> 8), byte(port), 0, 0, 0, 0}
	return append(b, ip.To16()...)
}

func sockaddrUnix(path string) []byte {
	return append([]byte{byte(linux.AF_UNIX), 0}, append([]byte(path), 0)...)
}

func eventFor(t *testing.T, msgType pb.MessageType, msg proto.Message) *Event {
	t.Helper()
	table := NewProcessTable(defaultMaxTrackedProcess)
	table.Apply(execPoint(t, 1, 0, "/bin/sh", "sh"))
	table.Apply(execPoint(t, 42, 1, "/usr/bin/curl", "curl", "-s", "http://x"))
	p := mustPoint(t, msgType, msg)
	ctx := EventContext{
		Snapshot: table.Apply(p),
		Container: &ContainerInfo{
			ID: testContainerID, Name: "web", Image: "nginx:1.27",
			Labels: map[string]string{"app": "web"}, PodName: "web-0", PodNamespace: "prod",
			PodLabels: map[string]string{"tier": "front", "app": "web"},
		},
	}
	data, err := EncodeEvent(ctx, p.Raw)
	if err != nil {
		t.Fatal(err)
	}
	evt, err := DecodeEvent(data)
	if err != nil {
		t.Fatal(err)
	}
	return &evt
}

func get(t *testing.T, evt *Event, name string) any {
	t.Helper()
	v, ok := ExtractField(evt, FieldRequest{Name: name})
	if !ok {
		return nil
	}
	return v
}

func TestExtractConnect(t *testing.T) {
	evt := eventFor(t, pb.MessageType_MESSAGE_SYSCALL_CONNECT, &pb.Connect{
		ContextData: testContext(42, 1, "curl"),
		Sysno:       sysnoOf(t, "connect"),
		Exit:        &pb.Exit{Result: -111, Errorno: 111},
		Address:     sockaddrIPv4(net.IPv4(169, 254, 169, 254), 80),
	})
	want := map[string]any{
		fieldEvtType:     "connect",
		fieldEvtFailed:   true,
		fieldFDName:      "169.254.169.254:80",
		fieldFDType:      FDTypeIPv4,
		fieldFDTypeChar:  "4",
		fieldFDSIP:       net.IP{169, 254, 169, 254},
		fieldFDRIP:       net.IP{169, 254, 169, 254},
		fieldFDSPort:     uint64(80),
		fieldFDRPort:     uint64(80),
		fieldGvisorPoint: "syscall/connect/exit",
		fieldGvisorSysno: sysnoOf(t, "connect"),
		fieldProcName:    "curl",
		fieldProcPName:   "sh",
		fieldProcCmdline: "curl -s http://x",
		fieldProcPid:     uint64(42),
		fieldProcPpid:    uint64(1),
		fieldUserUID:     uint64(1000),
	}
	for name, v := range want {
		if got := get(t, evt, name); !reflect.DeepEqual(got, v) {
			t.Errorf("%s = %#v, want %#v", name, got, v)
		}
	}
	if res := get(t, evt, fieldEvtRes); res == evtResSuccess || res == nil {
		t.Errorf("evt.res = %v for failed connect", res)
	}
	for _, absent := range []string{fieldFDDirectory, fieldEvtArgFlags, fieldEvtIsOpenRead, fieldGvisorExitStatus} {
		if v := get(t, evt, absent); v != nil {
			t.Errorf("%s should be absent, got %v", absent, v)
		}
	}
}

func TestExtractIPOwnedByEvent(t *testing.T) {
	evt := eventFor(t, pb.MessageType_MESSAGE_SYSCALL_CONNECT, &pb.Connect{
		ContextData: testContext(42, 1, "curl"), Exit: &pb.Exit{}, Address: sockaddrIPv4(net.IPv4(169, 254, 169, 254), 80),
	})
	first := get(t, evt, fieldFDRIP).(net.IP)
	runtime.GC()
	second := get(t, evt, fieldFDRIP).(net.IP)
	sip := get(t, evt, fieldFDSIP).(net.IP)
	if &first[0] != &second[0] || &first[0] != &evt.fd.rip[0] || !sip.Equal(first) {
		t.Fatal("ipaddr values must point into memory owned by the cached event, not fresh per-call allocations: the SDK hands the slice's address to Falco without copying it")
	}
}

func TestExtractConnectIPv6AndUnix(t *testing.T) {
	ip6 := net.ParseIP("fd00:ec2::254")
	evt := eventFor(t, pb.MessageType_MESSAGE_SYSCALL_CONNECT, &pb.Connect{
		ContextData: testContext(42, 1, "curl"), Exit: &pb.Exit{}, Address: sockaddrIPv6(ip6, 80),
	})
	if got := get(t, evt, fieldFDRIP); !ip6.Equal(got.(net.IP)) || get(t, evt, fieldFDName) != "[fd00:ec2::254]:80" {
		t.Errorf("ipv6: rip=%v name=%v", got, get(t, evt, fieldFDName))
	}
	if get(t, evt, fieldEvtRes) != evtResSuccess {
		t.Errorf("evt.res = %v", get(t, evt, fieldEvtRes))
	}

	evt = eventFor(t, pb.MessageType_MESSAGE_SYSCALL_CONNECT, &pb.Connect{
		ContextData: testContext(42, 1, "curl"), Exit: &pb.Exit{}, Address: sockaddrUnix("/var/run/docker.sock"),
	})
	if get(t, evt, fieldFDName) != "/var/run/docker.sock" || get(t, evt, fieldFDType) != FDTypeUnix || get(t, evt, fieldFDRIP) != nil {
		t.Errorf("unix connect: name=%v type=%v", get(t, evt, fieldFDName), get(t, evt, fieldFDType))
	}
}

func TestExtractOpen(t *testing.T) {
	evt := eventFor(t, pb.MessageType_MESSAGE_SYSCALL_OPEN, &pb.Open{
		ContextData: testContext(42, 1, "sh"),
		Sysno:       sysnoOf(t, "openat"),
		Exit:        &pb.Exit{Result: 3},
		Fd:          linux.AT_FDCWD,
		Pathname:    "authorized_keys",
		Flags:       linux.O_WRONLY | linux.O_CREAT | linux.O_TRUNC,
	})
	ctxCwd := testContext(42, 1, "sh").GetCwd()
	want := map[string]any{
		fieldFDName:         ctxCwd + "/authorized_keys",
		fieldFDNameRaw:      "authorized_keys",
		fieldFDDirectory:    ctxCwd,
		fieldFDFilename:     "authorized_keys",
		fieldFDType:         FDTypeFile,
		fieldEvtIsOpenWrite: true,
		fieldEvtIsOpenRead:  false,
		fieldEvtArgFlags:    "O_WRONLY|O_CREAT|O_TRUNC",
		fieldEvtRes:         evtResSuccess,
	}
	for name, v := range want {
		if got := get(t, evt, name); !reflect.DeepEqual(got, v) {
			t.Errorf("%s = %#v, want %#v", name, got, v)
		}
	}

	evt = eventFor(t, pb.MessageType_MESSAGE_SYSCALL_OPEN, &pb.Open{
		ContextData: testContext(42, 1, "sh"), Fd: 5, FdPath: "/root/.ssh", Pathname: "id_rsa",
	})
	if get(t, evt, fieldFDName) != "/root/.ssh/id_rsa" {
		t.Errorf("dirfd-relative path = %v", get(t, evt, fieldFDName))
	}

	evt = eventFor(t, pb.MessageType_MESSAGE_SYSCALL_OPEN, &pb.Open{
		ContextData: testContext(42, 1, "sh"), Fd: 5, Pathname: "id_rsa",
	})
	if get(t, evt, fieldFDName) != nil || get(t, evt, fieldFDFilename) != nil || get(t, evt, fieldFDNameRaw) != "id_rsa" {
		t.Errorf("unresolvable dirfd path must leave fd.name unset: name=%v raw=%v", get(t, evt, fieldFDName), get(t, evt, fieldFDNameRaw))
	}
}

func TestExtractOpenPathIsNeitherReadNorWrite(t *testing.T) {
	evt := eventFor(t, pb.MessageType_MESSAGE_SYSCALL_OPEN, &pb.Open{
		ContextData: testContext(42, 1, "app"), Exit: &pb.Exit{Result: 3}, Fd: linux.AT_FDCWD,
		Pathname: "/var/run/secrets/kubernetes.io/serviceaccount/token", Flags: linux.O_PATH | linux.O_CLOEXEC,
	})
	if get(t, evt, fieldEvtIsOpenRead) != false || get(t, evt, fieldEvtIsOpenWrite) != false {
		t.Errorf("O_PATH open: read=%v write=%v, want both false", get(t, evt, fieldEvtIsOpenRead), get(t, evt, fieldEvtIsOpenWrite))
	}
	if got := get(t, evt, fieldEvtArgFlags); got != "O_RDONLY|O_CLOEXEC|O_PATH" {
		t.Errorf("flags = %v", got)
	}
}

func TestExtractConnectL4FromTrackedSocket(t *testing.T) {
	table := NewProcessTable(defaultMaxTrackedProcess)
	table.Apply(execPoint(t, 1, 0, "/bin/sh", "sh"))
	table.Apply(mustPoint(t, pb.MessageType_MESSAGE_SYSCALL_SOCKET, &pb.Socket{ContextData: testContext(1, 0, "sh"), Exit: &pb.Exit{Result: 7}, Domain: linux.AF_INET, Type: int32(linux.SOCK_STREAM)}))
	table.Apply(mustPoint(t, pb.MessageType_MESSAGE_SYSCALL_SOCKET, &pb.Socket{ContextData: testContext(1, 0, "sh"), Exit: &pb.Exit{Result: 8}, Domain: linux.AF_INET, Type: int32(linux.SOCK_DGRAM)}))
	table.Apply(clonePoint(t, 1, 0, 2, "sh"))
	connect := func(pid int32, fd int64) any {
		p := mustPoint(t, pb.MessageType_MESSAGE_SYSCALL_CONNECT, &pb.Connect{ContextData: testContext(pid, 1, "sh"), Exit: &pb.Exit{}, Fd: fd, Address: sockaddrIPv4(net.IPv4(10, 0, 0, 1), 3333)})
		data, err := EncodeEvent(EventContext{Snapshot: table.Apply(p)}, p.Raw)
		if err != nil {
			t.Fatal(err)
		}
		evt, err := DecodeEvent(data)
		if err != nil {
			t.Fatal(err)
		}
		return get(t, &evt, fieldFDL4Proto)
	}
	if got := connect(1, 7); got != "tcp" {
		t.Errorf("connect on a TCP socket: l4proto = %v", got)
	}
	if got := connect(1, 8); got != "udp" {
		t.Errorf("connect on a UDP socket: l4proto = %v", got)
	}
	if got := connect(2, 7); got != "tcp" {
		t.Errorf("a forked child's inherited socket lost its protocol: %v", got)
	}
	if got := connect(1, 99); got != nil {
		t.Errorf("connect on an untracked fd must leave l4proto unknown, got %v", got)
	}
}

func TestL4ProtoOnlyForIPSockets(t *testing.T) {
	cases := []struct {
		domain int32
		typ    linux.SockType
		want   string
	}{
		{linux.AF_INET, linux.SOCK_STREAM, "tcp"},
		{linux.AF_INET6, linux.SOCK_DGRAM, "udp"},
		{linux.AF_INET, linux.SOCK_RAW, "raw"},
		{linux.AF_UNIX, linux.SOCK_STREAM, ""},
		{linux.AF_UNIX, linux.SOCK_DGRAM, ""},
		{linux.AF_NETLINK, linux.SOCK_RAW, ""},
	}
	for _, c := range cases {
		if got := l4ProtoOf(c.domain, int32(c.typ)); got != c.want {
			t.Errorf("l4ProtoOf(%d, %d) = %q, want %q", c.domain, c.typ, got, c.want)
		}
	}
}

func TestExtractSocketAndPtrace(t *testing.T) {
	evt := eventFor(t, pb.MessageType_MESSAGE_SYSCALL_SOCKET, &pb.Socket{
		ContextData: testContext(42, 1, "nmap"), Exit: &pb.Exit{Result: 3},
		Domain: linux.AF_PACKET, Type: int32(linux.SOCK_RAW) | linux.SOCK_CLOEXEC,
	})
	if get(t, evt, fieldEvtArgDomain) != "AF_PACKET" || get(t, evt, fieldEvtArgType) != "SOCK_RAW" || get(t, evt, fieldFDL4Proto) != nil {
		t.Errorf("socket: domain=%v type=%v", get(t, evt, fieldEvtArgDomain), get(t, evt, fieldEvtArgType))
	}

	evt = eventFor(t, pb.MessageType_MESSAGE_SYSCALL_PTRACE, &pb.Ptrace{
		ContextData: testContext(42, 1, "gdb"), Exit: &pb.Exit{}, Request: linux.PTRACE_ATTACH, Pid: 7,
	})
	if get(t, evt, fieldEvtArgRequest) != "PTRACE_ATTACH" {
		t.Errorf("ptrace request = %v", get(t, evt, fieldEvtArgRequest))
	}
}

func TestExtractSetuid(t *testing.T) {
	ctx := testContext(42, 1, "curl")
	ctx.Credentials = &pb.Credentials{}
	evt := eventFor(t, pb.MessageType_MESSAGE_SYSCALL_SETID, &pb.Setid{ContextData: ctx, Sysno: sysnoOf(t, "setuid"), Exit: &pb.Exit{}, Id: 0})
	want := map[string]any{
		fieldEvtType:       "setuid",
		fieldEvtArgUID:     uint64(0),
		fieldGvisorPrevUID: uint64(1000),
		fieldUserUID:       uint64(0),
		fieldEvtArgGID:     nil,
	}
	for name, v := range want {
		if got := get(t, evt, name); !reflect.DeepEqual(got, v) {
			t.Errorf("%s = %#v, want %#v", name, got, v)
		}
	}

	evt = eventFor(t, pb.MessageType_MESSAGE_SYSCALL_SETRESID, &pb.Setresid{ContextData: testContext(42, 1, "curl"), Sysno: sysnoOf(t, "setresuid"), Exit: &pb.Exit{}, Rid: 4294967295, Eid: 0, Sid: 4294967295})
	if get(t, evt, fieldEvtArgEUID) != uint64(0) || get(t, evt, fieldEvtArgRUID) != uint64(4294967295) || get(t, evt, fieldEvtArgEGID) != nil {
		t.Errorf("setresuid args: euid=%v ruid=%v egid=%v", get(t, evt, fieldEvtArgEUID), get(t, evt, fieldEvtArgRUID), get(t, evt, fieldEvtArgEGID))
	}

	fresh := eventFor(t, pb.MessageType_MESSAGE_SYSCALL_SETID, &pb.Setid{ContextData: testContext(77, 1, "new"), Sysno: sysnoOf(t, "setuid"), Exit: &pb.Exit{}})
	if get(t, fresh, fieldGvisorPrevUID) != nil {
		t.Error("prev_uid must be absent for a process seen for the first time")
	}
}

func TestExtractExecAndContainer(t *testing.T) {
	evt := eventFor(t, pb.MessageType_MESSAGE_SENTRY_EXEC, &pb.ExecveInfo{
		ContextData:          testContext(43, 42, "x"),
		BinaryPath:           "/tmp/xmrig",
		Argv:                 []string{"/tmp/xmrig", "-o", "stratum+tcp://pool:3333"},
		BinaryOverlayfsUpper: true,
		BinaryMode:           linux.S_IFREG | 0o755,
		Stdin:                &pb.FdInfo{Socket: &pb.SocketInfo{Family: linux.AF_INET}},
		PipeInputProc:        &pb.PipeProcInfo{ContextData: &pb.ContextData{ProcessName: "curl"}},
	})
	want := map[string]any{
		fieldGvisorStdinPipeProc: "curl",
		fieldEvtType:             evtTypeSentryExecve,
		fieldProcName:            "xmrig",
		fieldProcExe:             "/tmp/xmrig",
		fieldProcExePath:         "/tmp/xmrig",
		fieldProcArgs:            "-o stratum+tcp://pool:3333",
		fieldProcUpperLayer:      true,
		fieldProcFromMemfd:       false,
		fieldProcStdinType:       FDTypeIPv4,
		fieldProcPName:           "curl",
		fieldProcPExePath:        "/usr/bin/curl",
		fieldGvisorANames:        []string{"curl", "sh"},
		fieldContainerID:         testContainerID[:shortIDLen],
		fieldContainerFullID:     testContainerID,
		fieldContainerName:       "web",
		fieldContainerImage:      "nginx:1.27",
		fieldK8sPodName:          "web-0",
		fieldK8sNsName:           "prod",
		fieldGvisorPoint:         "sentry/execve",
		fieldGvisorIsExecSession: false,
	}
	for name, v := range want {
		if got := get(t, evt, name); !reflect.DeepEqual(got, v) {
			t.Errorf("%s = %#v, want %#v", name, got, v)
		}
	}
	for _, absent := range []string{fieldEvtRes, fieldEvtFailed, fieldGvisorSysno, fieldFDName} {
		if v := get(t, evt, absent); v != nil {
			t.Errorf("%s should be absent on sentry/execve, got %v", absent, v)
		}
	}

	cases := []struct {
		req  FieldRequest
		want any
	}{
		{FieldRequest{Name: fieldProcAName, ArgIndex: 0}, "xmrig"},
		{FieldRequest{Name: fieldProcAName, ArgIndex: 2}, "sh"},
		{FieldRequest{Name: fieldProcAExePath, ArgIndex: 1}, "/usr/bin/curl"},
		{FieldRequest{Name: fieldProcAName, ArgIndex: 5}, nil},
		{FieldRequest{Name: fieldContainerLabel, ArgKey: "app"}, "web"},
		{FieldRequest{Name: fieldContainerLabel, ArgKey: "missing"}, nil},
		{FieldRequest{Name: fieldK8sPodLabel, ArgKey: "tier"}, "front"},
	}
	for _, tc := range cases {
		got, ok := ExtractField(evt, tc.req)
		if !ok {
			got = nil
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%+v = %#v, want %#v", tc.req, got, tc.want)
		}
	}
}

func TestExtractWithoutMetadata(t *testing.T) {
	p := mustPoint(t, pb.MessageType_MESSAGE_SENTRY_TASK_EXIT, &pb.TaskExit{ContextData: testContext(9, 1, "sh"), ExitStatus: 256})
	data, err := EncodeEvent(EventContext{Snapshot: NewProcessTable(1).Apply(p)}, p.Raw)
	if err != nil {
		t.Fatal(err)
	}
	evt, err := DecodeEvent(data)
	if err != nil {
		t.Fatal(err)
	}
	if get(t, &evt, fieldContainerName) != nil || get(t, &evt, fieldContainerID) != testContainerID[:shortIDLen] {
		t.Error("container id must come from gVisor even without runtime metadata")
	}
	if get(t, &evt, fieldGvisorExitStatus) != uint64(256) || get(t, &evt, fieldProcPName) != nil {
		t.Errorf("exit=%v pname=%v", get(t, &evt, fieldGvisorExitStatus), get(t, &evt, fieldProcPName))
	}
}

func TestExtractBinaryFlagsNeedBinaryInfo(t *testing.T) {
	evt := eventFor(t, pb.MessageType_MESSAGE_SENTRY_EXEC, &pb.ExecveInfo{
		ContextData: testContext(43, 42, "x"), BinaryPath: "/tmp/tool", Argv: []string{"tool"},
	})
	for _, name := range []string{fieldProcUpperLayer, fieldProcLowerLayer, fieldProcFromMemfd} {
		if v := get(t, evt, name); v != nil {
			t.Errorf("%s = %v for an exec without binary_info; want absent", name, v)
		}
	}
}

func TestExtractEmptyAncestorFieldsAbsent(t *testing.T) {
	table := NewProcessTable(defaultMaxTrackedProcess)
	table.Apply(mustPoint(t, pb.MessageType_MESSAGE_SYSCALL_CONNECT, &pb.Connect{ContextData: testContext(1, 0, ""), Exit: &pb.Exit{}}))
	p := mustPoint(t, pb.MessageType_MESSAGE_SENTRY_EXEC, &pb.ExecveInfo{ContextData: testContext(2, 1, "sh"), BinaryPath: "/bin/sh", Argv: []string{"sh"}})
	data, err := EncodeEvent(EventContext{Snapshot: table.Apply(p)}, p.Raw)
	if err != nil {
		t.Fatal(err)
	}
	evt, err := DecodeEvent(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, req := range []FieldRequest{{Name: fieldProcPName}, {Name: fieldProcPExePath}, {Name: fieldProcAName, ArgIndex: 1}, {Name: fieldProcAExePath, ArgIndex: 1}} {
		if v, ok := ExtractField(&evt, req); ok {
			t.Errorf("%+v = %#v for a parent with no name or path; want absent", req, v)
		}
	}
}

func TestExtractUnknownProcessValuesAbsent(t *testing.T) {
	ctx := testContext(9, 1, "")
	ctx.Credentials = nil
	ctx.Cwd = ""
	p := mustPoint(t, pb.MessageType_MESSAGE_SYSCALL_CONNECT, &pb.Connect{ContextData: ctx, Exit: &pb.Exit{}, Address: sockaddrIPv4(net.IPv4(10, 0, 0, 1), 80)})
	data, err := EncodeEvent(EventContext{Snapshot: NewProcessTable(1).Apply(p)}, p.Raw)
	if err != nil {
		t.Fatal(err)
	}
	evt, err := DecodeEvent(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{fieldUserUID, fieldGroupGID, fieldProcExePath, fieldProcExe, fieldProcArgs, fieldProcCwd, fieldProcName, fieldProcCmdline} {
		if v := get(t, &evt, name); v != nil {
			t.Errorf("%s = %#v for a process seen without exec or credentials; want absent", name, v)
		}
	}
	if get(t, &evt, fieldProcPid) != uint64(9) {
		t.Error("pid must stay present")
	}
}

func TestExtractStats(t *testing.T) {
	data, err := EncodeStats(StatsSnapshot{Connections: 3, Events: 10, EventsPerSecond: 12.7, DropChannelFull: 2, DropSandbox: 1, AttachFailures: 1})
	if err != nil {
		t.Fatal(err)
	}
	evt, err := DecodeEvent(data)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		fieldEvtType:              evtTypeStats,
		fieldStatsConnections:     uint64(3),
		fieldStatsEventsPerSecond: uint64(12),
		fieldStatsDrops:           uint64(3),
		fieldStatsAttachFailures:  uint64(1),
		fieldProcName:             nil,
	}
	for name, v := range want {
		if got := get(t, &evt, name); !reflect.DeepEqual(got, v) {
			t.Errorf("%s = %#v, want %#v", name, got, v)
		}
	}
	if Describe(&evt) != evtTypeStats {
		t.Errorf("describe = %q", Describe(&evt))
	}
}

func TestEveryFieldHasExtractorAndType(t *testing.T) {
	samples := []*Event{
		eventFor(t, pb.MessageType_MESSAGE_SYSCALL_CONNECT, &pb.Connect{ContextData: testContext(42, 1, "c"), Exit: &pb.Exit{}, Address: sockaddrIPv4(net.IPv4(1, 2, 3, 4), 1)}),
		eventFor(t, pb.MessageType_MESSAGE_SYSCALL_OPEN, &pb.Open{ContextData: testContext(42, 1, "c"), Exit: &pb.Exit{}, Pathname: "/etc/x"}),
		eventFor(t, pb.MessageType_MESSAGE_SYSCALL_SOCKET, &pb.Socket{ContextData: testContext(42, 1, "c"), Exit: &pb.Exit{}, Domain: linux.AF_INET, Type: int32(linux.SOCK_STREAM)}),
		eventFor(t, pb.MessageType_MESSAGE_SYSCALL_PTRACE, &pb.Ptrace{ContextData: testContext(42, 1, "c"), Exit: &pb.Exit{}}),
		eventFor(t, pb.MessageType_MESSAGE_SENTRY_EXEC, &pb.ExecveInfo{ContextData: testContext(42, 1, "c"), BinaryPath: "/x", BinarySha256: []byte{1}, BinaryMode: linux.S_IFREG | 0o755, Stdin: &pb.FdInfo{Mode: linux.S_IFIFO}, Stdout: &pb.FdInfo{Mode: linux.S_IFIFO}, Stderr: &pb.FdInfo{Mode: linux.S_IFIFO}, PipeInputProc: &pb.PipeProcInfo{ContextData: &pb.ContextData{ProcessName: "wget"}}}),
		eventFor(t, pb.MessageType_MESSAGE_SENTRY_TASK_EXIT, &pb.TaskExit{ContextData: testContext(42, 1, "c")}),
		eventFor(t, pb.MessageType_MESSAGE_SYSCALL_SETID, &pb.Setid{ContextData: testContext(42, 1, "c"), Sysno: sysnoOf(t, "setuid"), Exit: &pb.Exit{}}),
		eventFor(t, pb.MessageType_MESSAGE_SYSCALL_SETID, &pb.Setid{ContextData: testContext(42, 1, "c"), Sysno: sysnoOf(t, "setgid"), Exit: &pb.Exit{}}),
		eventFor(t, pb.MessageType_MESSAGE_SYSCALL_SETRESID, &pb.Setresid{ContextData: testContext(42, 1, "c"), Sysno: sysnoOf(t, "setresuid"), Exit: &pb.Exit{}}),
		eventFor(t, pb.MessageType_MESSAGE_SYSCALL_SETRESID, &pb.Setresid{ContextData: testContext(42, 1, "c"), Sysno: sysnoOf(t, "setresgid"), Exit: &pb.Exit{}}),
	}
	statsData, err := EncodeStats(StatsSnapshot{})
	if err != nil {
		t.Fatal(err)
	}
	stats, err := DecodeEvent(statsData)
	if err != nil {
		t.Fatal(err)
	}
	samples = append(samples, &stats)

	goTypes := map[string]reflect.Type{
		typeString: reflect.TypeFor[string](),
		typeUint64: reflect.TypeFor[uint64](),
		typeBool:   reflect.TypeFor[bool](),
		typeIPAddr: reflect.TypeFor[net.IP](),
	}
	seen := map[string]bool{}
	for _, def := range Fields() {
		if seen[def.Name] {
			t.Errorf("duplicate field %s", def.Name)
		}
		seen[def.Name] = true
		_, isPoint := pointExtractors[def.Name]
		_, isStats := statsExtractors[def.Name]
		if !isPoint && !isStats {
			t.Errorf("field %s has no extractor", def.Name)
			continue
		}
		want := goTypes[def.Type]
		if def.IsList {
			want = reflect.SliceOf(want)
		}
		extracted := false
		for _, evt := range samples {
			v, ok := ExtractField(evt, FieldRequest{Name: def.Name, ArgIndex: 1, ArgKey: "app"})
			if !ok {
				continue
			}
			extracted = true
			if reflect.TypeOf(v) != want {
				t.Errorf("field %s declared %s but extracted %T", def.Name, def.Type, v)
			}
		}
		if !extracted {
			t.Errorf("field %s never extracted from samples", def.Name)
		}
		if def.Desc == "" {
			t.Errorf("field %s has no description", def.Name)
		}
	}
	for name := range pointExtractors {
		if !seen[name] {
			t.Errorf("extractor %s is not declared", name)
		}
	}
}

func TestDescribe(t *testing.T) {
	evt := eventFor(t, pb.MessageType_MESSAGE_SYSCALL_CONNECT, &pb.Connect{
		ContextData: testContext(42, 1, "curl"), Sysno: sysnoOf(t, "connect"), Exit: &pb.Exit{}, Address: sockaddrIPv4(net.IPv4(10, 0, 0, 1), 443),
	})
	want := "syscall/connect/exit pid=42 proc=curl fd=10.0.0.1:443 container=" + testContainerID[:shortIDLen]
	if got := Describe(evt); got != want {
		t.Errorf("Describe = %q, want %q", got, want)
	}
}

func TestExtractCreatOnAMD64(t *testing.T) {
	const amd64Creat = 85
	table := NewProcessTable(defaultMaxTrackedProcess)
	table.Apply(execPoint(t, 7, 1, "/bin/sh", "sh"))
	p := mustPoint(t, pb.MessageType_MESSAGE_SYSCALL_OPEN, &pb.Open{
		ContextData: testContext(7, 1, "sh"), Exit: &pb.Exit{Result: 3}, Sysno: amd64Creat,
		Fd: linux.AT_FDCWD, Pathname: "/etc/cron.d/job", Flags: linux.O_WRONLY | linux.O_CREAT | linux.O_TRUNC,
	})
	data, err := EncodeEvent(EventContext{Snapshot: table.Apply(p), Arch: "amd64"}, p.Raw)
	if err != nil {
		t.Fatal(err)
	}
	evt, err := DecodeEvent(data)
	if err != nil {
		t.Fatal(err)
	}
	if typ, name, write := get(t, &evt, fieldEvtType), get(t, &evt, fieldFDName), get(t, &evt, fieldEvtIsOpenWrite); typ != "creat" || name != "/etc/cron.d/job" || write != true {
		t.Errorf("creat: evt.type=%v fd.name=%v is_open_write=%v", typ, name, write)
	}
}

func TestResolvePathCleansAbsolutePaths(t *testing.T) {
	cases := []struct {
		pathname, dirPath, want string
		dirfd                   int64
	}{
		{"/tmp/../etc/cron.d/job", "", "/etc/cron.d/job", linux.AT_FDCWD},
		{"/var/tmp/../run/secrets/token", "", "/var/run/secrets/token", linux.AT_FDCWD},
		{"/etc/./passwd", "", "/etc/passwd", linux.AT_FDCWD},
		{"../etc/shadow", "", "/etc/shadow", linux.AT_FDCWD},
		{"job", "/etc/cron.d", "/etc/cron.d/job", 5},
		{"", "", "", linux.AT_FDCWD},
	}
	for _, c := range cases {
		if got := resolvePath(c.pathname, c.dirfd, c.dirPath, "/app"); got != c.want {
			t.Errorf("resolvePath(%q) = %q, want %q", c.pathname, got, c.want)
		}
	}
}
