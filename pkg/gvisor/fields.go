package gvisor

// FieldArg describes the argument a field accepts.
type FieldArg int

// Field argument kinds.
const (
	ArgNone FieldArg = iota
	ArgIndex
	ArgKey
)

// FieldDef describes one extractable field.
type FieldDef struct {
	Name   string
	Type   string
	Desc   string
	IsList bool
	Arg    FieldArg
}

const (
	typeString = "string"
	typeUint64 = "uint64"
	typeBool   = "bool"
	typeIPAddr = "ipaddr"
)

const (
	fieldEvtType        = "evt.type"
	fieldEvtRes         = "evt.res"
	fieldEvtFailed      = "evt.failed"
	fieldEvtIsOpenRead  = "evt.is_open_read"
	fieldEvtIsOpenWrite = "evt.is_open_write"
	fieldEvtArgFlags    = "evt.arg.flags"
	fieldEvtArgDomain   = "evt.arg.domain"
	fieldEvtArgType     = "evt.arg.type"
	fieldEvtArgRequest  = "evt.arg.request"
	fieldEvtArgUID      = "evt.arg.uid"
	fieldEvtArgGID      = "evt.arg.gid"
	fieldEvtArgRUID     = "evt.arg.ruid"
	fieldEvtArgEUID     = "evt.arg.euid"
	fieldEvtArgSUID     = "evt.arg.suid"
	fieldEvtArgRGID     = "evt.arg.rgid"
	fieldEvtArgEGID     = "evt.arg.egid"
	fieldEvtArgSGID     = "evt.arg.sgid"

	fieldFDName      = "fd.name"
	fieldFDNameRaw   = "fd.nameraw"
	fieldFDDirectory = "fd.directory"
	fieldFDFilename  = "fd.filename"
	fieldFDType      = "fd.type"
	fieldFDTypeChar  = "fd.typechar"
	fieldFDSIP       = "fd.sip"
	fieldFDSPort     = "fd.sport"
	fieldFDRIP       = "fd.rip"
	fieldFDRPort     = "fd.rport"
	fieldFDL4Proto   = "fd.l4proto"

	fieldProcPid         = "proc.pid"
	fieldProcPpid        = "proc.ppid"
	fieldProcName        = "proc.name"
	fieldProcExe         = "proc.exe"
	fieldProcExePath     = "proc.exepath"
	fieldProcArgs        = "proc.args"
	fieldProcCmdline     = "proc.cmdline"
	fieldProcCwd         = "proc.cwd"
	fieldProcTTY         = "proc.tty"
	fieldProcPName       = "proc.pname"
	fieldProcPExePath    = "proc.pexepath"
	fieldProcPCmdline    = "proc.pcmdline"
	fieldProcAName       = "proc.aname"
	fieldProcAExePath    = "proc.aexepath"
	fieldProcUpperLayer  = "proc.is_exe_upper_layer"
	fieldProcLowerLayer  = "proc.is_exe_lower_layer"
	fieldProcFromMemfd   = "proc.is_exe_from_memfd"
	fieldProcStdinType   = "proc.stdin.type"
	fieldProcStdoutType  = "proc.stdout.type"
	fieldProcStderrType  = "proc.stderr.type"
	fieldProcSHA256      = "proc.sha256"
	fieldUserUID         = "user.uid"
	fieldGroupGID        = "group.gid"
	fieldContainerID     = "container.id"
	fieldContainerFullID = "container.full_id"
	fieldContainerName   = "container.name"
	fieldContainerImage  = "container.image"
	fieldContainerLabel  = "container.label"
	fieldK8sPodName      = "k8s.pod.name"
	fieldK8sNsName       = "k8s.ns.name"
	fieldK8sPodLabel     = "k8s.pod.label"

	fieldGvisorContainerID   = "gvisor.container_id"
	fieldGvisorIsExecSession = "gvisor.is_exec_session"
	fieldGvisorSysno         = "gvisor.sysno"
	fieldGvisorPoint         = "gvisor.point"
	fieldGvisorANames        = "gvisor.anames"
	fieldGvisorExitStatus    = "gvisor.exit_status"
	fieldGvisorStdinPipeProc = "gvisor.stdin_pipe_proc"
	fieldGvisorPrevUID       = "gvisor.prev_uid"

	fieldStatsConnections     = "gvisor.stats.connections"
	fieldStatsEventsPerSecond = "gvisor.stats.events_per_second"
	fieldStatsDrops           = "gvisor.stats.drops"
	fieldStatsDropsInterval   = "gvisor.stats.drops_interval"
	fieldStatsDropChannelFull = "gvisor.stats.drops_channel_full"
	fieldStatsDropQueueShare  = "gvisor.stats.drops_queue_share"
	fieldStatsDropTruncated   = "gvisor.stats.drops_truncated"
	fieldStatsDropDecodeError = "gvisor.stats.drops_decode_error"
	fieldStatsDropSandbox     = "gvisor.stats.drops_sandbox"
	fieldStatsAttachAttempts  = "gvisor.stats.attach_attempts"
	fieldStatsAttachFailures  = "gvisor.stats.attach_failures"
	fieldStatsQueueBytes      = "gvisor.stats.queue_bytes"
	fieldStatsUnmonitored     = "gvisor.stats.unmonitored_sandboxes"
	fieldStatsAttacherFailed  = "gvisor.stats.attacher_failed"
	fieldStatsPeerRejected    = "gvisor.stats.peer_rejected"
	fieldStatsPanics          = "gvisor.stats.panics"
)

func field(name, typ, desc string) FieldDef {
	return FieldDef{Name: name, Type: typ, Desc: desc}
}

func fieldWithArg(name, desc string, arg FieldArg) FieldDef {
	f := field(name, typeString, desc)
	f.Arg = arg
	return f
}

var fieldDefs = []FieldDef{
	field(fieldEvtType, typeString, "Syscall name (e.g. connect, execve) or sentry point: container_start, sentry_clone, sentry_execve, task_exit, exit_notify_parent, gvisor_stats."),
	field(fieldEvtRes, typeString, "SUCCESS, or the errno name (e.g. ENOENT) when the syscall failed. Only on syscall exit points."),
	field(fieldEvtFailed, typeBool, "True when the syscall returned an error."),
	field(fieldEvtIsOpenRead, typeBool, "True for open events whose access mode allows reading."),
	field(fieldEvtIsOpenWrite, typeBool, "True for open events whose access mode allows writing."),
	field(fieldEvtArgFlags, typeString, "Open flags rendered like Falco, e.g. O_WRONLY|O_CREAT|O_TRUNC."),
	field(fieldEvtArgDomain, typeString, "Socket domain, e.g. AF_INET, AF_PACKET."),
	field(fieldEvtArgType, typeString, "Socket type, e.g. SOCK_STREAM, SOCK_RAW."),
	field(fieldEvtArgRequest, typeString, "ptrace request, e.g. PTRACE_ATTACH."),
	field(fieldEvtArgUID, typeUint64, "setuid: requested uid."),
	field(fieldEvtArgGID, typeUint64, "setgid: requested gid."),
	field(fieldEvtArgRUID, typeUint64, "setresuid: requested real uid (4294967295 means unchanged)."),
	field(fieldEvtArgEUID, typeUint64, "setresuid: requested effective uid (4294967295 means unchanged)."),
	field(fieldEvtArgSUID, typeUint64, "setresuid: requested saved uid (4294967295 means unchanged)."),
	field(fieldEvtArgRGID, typeUint64, "setresgid: requested real gid (4294967295 means unchanged)."),
	field(fieldEvtArgEGID, typeUint64, "setresgid: requested effective gid (4294967295 means unchanged)."),
	field(fieldEvtArgSGID, typeUint64, "setresgid: requested saved gid (4294967295 means unchanged)."),

	field(fieldFDName, typeString, "File path for open/execve, ip:port of the remote endpoint for connect/accept, local endpoint for bind/listen, or unix socket path."),
	field(fieldFDNameRaw, typeString, "Path exactly as passed to the syscall, before fd_path resolution."),
	field(fieldFDDirectory, typeString, "Directory part of fd.name for file events."),
	field(fieldFDFilename, typeString, "Base name of fd.name for file events."),
	field(fieldFDType, typeString, "file, ipv4, ipv6, unix or netlink."),
	field(fieldFDTypeChar, typeString, "One-character fd type: f, 4, 6, u, n."),
	field(fieldFDSIP, typeIPAddr, "Server IP: the connect target, or the bound address for bind/listen."),
	field(fieldFDSPort, typeUint64, "Server port."),
	field(fieldFDRIP, typeIPAddr, "Remote IP: the connect target or the accepted peer."),
	field(fieldFDRPort, typeUint64, "Remote port."),
	field(fieldFDL4Proto, typeString, "tcp, udp or raw when the socket type is known: on socket and listen, and on connect when the socket() call that created the fd was seen."),

	field(fieldProcPid, typeUint64, "Thread-group id inside the sandbox."),
	field(fieldProcPpid, typeUint64, "Parent thread-group id inside the sandbox."),
	field(fieldProcName, typeString, "Process name (comm, up to 15 characters)."),
	field(fieldProcExe, typeString, "First command-line argument (argv[0])."),
	field(fieldProcExePath, typeString, "Full path of the executable."),
	field(fieldProcArgs, typeString, "Command-line arguments after argv[0], space separated."),
	field(fieldProcCmdline, typeString, "proc.name followed by proc.args."),
	field(fieldProcCwd, typeString, "Current working directory."),
	field(fieldProcTTY, typeUint64, "Approximate controlling terminal: pts device number when stdio is a /dev/pts/N, 1 for other terminals, 0 for none."),
	field(fieldProcPName, typeString, "Parent process name."),
	field(fieldProcPExePath, typeString, "Parent executable path."),
	field(fieldProcPCmdline, typeString, "Parent command line."),
	fieldWithArg(fieldProcAName, "Name of the Nth ancestor: [0] is the process, [1] its parent, up to [8].", ArgIndex),
	fieldWithArg(fieldProcAExePath, "Executable path of the Nth ancestor.", ArgIndex),
	field(fieldProcUpperLayer, typeBool, "True when the executable was written to the container's upper (writable) layer."),
	field(fieldProcLowerLayer, typeBool, "True when the executable exists on the container image (overlay lower) layer. False for files created at runtime, including on tmpfs mounts such as /dev/shm and the /tmp tmpfs runsc mounts over an empty image /tmp."),
	field(fieldProcFromMemfd, typeBool, "True when the executable is a memfd (fileless execution)."),
	field(fieldProcStdinType, typeString, "fd type of stdin at exec: file, directory, pipe, unix, ipv4, ipv6."),
	field(fieldProcStdoutType, typeString, "fd type of stdout at exec."),
	field(fieldProcStderrType, typeString, "fd type of stderr at exec."),
	field(fieldProcSHA256, typeString, "SHA-256 of the executable, hex encoded (requires binary_sha256 on sentry/execve)."),
	field(fieldUserUID, typeUint64, "Effective user id."),
	field(fieldGroupGID, typeUint64, "Effective group id."),

	field(fieldContainerID, typeString, "Container id truncated to 12 characters."),
	field(fieldContainerFullID, typeString, "Full container id."),
	field(fieldContainerName, typeString, "Container name from the runtime; empty until metadata is resolved."),
	field(fieldContainerImage, typeString, "Container image from the runtime; empty until metadata is resolved."),
	fieldWithArg(fieldContainerLabel, "Container label value, filtered by labelAllowlist.", ArgKey),
	field(fieldK8sPodName, typeString, "Kubernetes pod name (cri provider)."),
	field(fieldK8sNsName, typeString, "Kubernetes namespace (cri provider)."),
	fieldWithArg(fieldK8sPodLabel, "Kubernetes pod label value (cri provider), filtered by labelAllowlist.", ArgKey),

	field(fieldGvisorContainerID, typeString, "Container id reported by gVisor."),
	field(fieldGvisorIsExecSession, typeBool, "True when the process descends from a 'runsc exec' (docker/kubectl exec) session."),
	field(fieldGvisorSysno, typeUint64, "Raw syscall number for syscall points."),
	field(fieldGvisorPoint, typeString, "gVisor trace point, e.g. syscall/connect/exit or sentry/execve."),
	{Name: fieldGvisorANames, Type: typeString, IsList: true, Desc: "Names of all known ancestors, nearest first; use with intersects / in."},
	field(fieldGvisorExitStatus, typeUint64, "Exit status for task_exit and exit_notify_parent points."),
	field(fieldGvisorPrevUID, typeUint64, "setuid-family events: the effective uid the process had before the call. Absent if the process had not been seen before."),
	field(fieldGvisorStdinPipeProc, typeString, "Name of the process writing to this process's stdin pipe at exec, e.g. curl in curl | sh. Set only if the writer is still running when the reader execs (gVisor inspects live siblings), and requires pipe_proc_info on sentry/execve."),

	field(fieldStatsConnections, typeUint64, "gvisor_stats: live sandbox connections."),
	field(fieldStatsEventsPerSecond, typeUint64, "gvisor_stats: events per second since the previous stats event."),
	field(fieldStatsDrops, typeUint64, "gvisor_stats: total dropped points."),
	field(fieldStatsDropsInterval, typeUint64, "gvisor_stats: points dropped since the previous gvisor_stats event."),
	field(fieldStatsDropChannelFull, typeUint64, "gvisor_stats: points dropped because the event queue's total budget (maxQueueBytes) was full."),
	field(fieldStatsDropQueueShare, typeUint64, "gvisor_stats: points dropped because one sandbox used its fair share of the event queue (maxQueueBytes divided by connected sandboxes)."),
	field(fieldStatsDropTruncated, typeUint64, "gvisor_stats: points dropped for exceeding maxEventSize."),
	field(fieldStatsDropDecodeError, typeUint64, "gvisor_stats: points dropped as undecodable."),
	field(fieldStatsDropSandbox, typeUint64, "gvisor_stats: points the sandbox reported dropping on its side."),
	field(fieldStatsAttachAttempts, typeUint64, "gvisor_stats: attach attempts."),
	field(fieldStatsAttachFailures, typeUint64, "gvisor_stats: failed attach attempts."),
	field(fieldStatsQueueBytes, typeUint64, "gvisor_stats: bytes of events waiting for Falco (bounded by maxQueueBytes)."),
	field(fieldStatsUnmonitored, typeUint64, "gvisor_stats: running sandboxes the last attacher sweep found unconnected and failed to attach."),
	field(fieldStatsPanics, typeUint64, "gvisor_stats: panics recovered inside the plugin (each is a bug; the affected point or fetch is dropped)."),
	field(fieldStatsPeerRejected, typeUint64, "gvisor_stats: connections refused because the peer was neither root nor Falco's user."),
	field(fieldStatsAttacherFailed, typeBool, "gvisor_stats: true when the last attacher sweep could not list sandboxes (runsc or its state root unreachable)."),
}

// Fields returns the extractable field definitions.
func Fields() []FieldDef {
	return append([]FieldDef(nil), fieldDefs...)
}
