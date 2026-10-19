package gvisor

import (
	"encoding/hex"
	"path"
	"strconv"
	"strings"

	"gvisor.dev/gvisor/pkg/abi/linux"
	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
)

const (
	maxCommLen        = 15
	maxArgvBytes      = 4096
	ptsPrefix         = "/dev/pts/"
	ttyPrefix         = "/dev/tty"
	consolePath       = "/dev/console"
	fdPathPrefix      = "/dev/fd/"
	ptsMajor          = 136
	devMinorBits      = 8
	devMinorLowMask   = 0xff
	devMinorHighShift = 12
	ttyUnknownNumber  = 1
)

// File descriptor type names, matching Falco's fd.type values.
const (
	FDTypeFile      = "file"
	FDTypeDirectory = "directory"
	FDTypeIPv4      = "ipv4"
	FDTypeIPv6      = "ipv6"
	FDTypeUnix      = "unix"
	FDTypePipe      = "pipe"
	FDTypeNetlink   = "netlink"
	FDTypeMemfd     = "memfd"
)

// ProcessInfo is an immutable view of a sandboxed process.
type ProcessInfo struct {
	Pid           int32    `json:"pid"`
	Ppid          int32    `json:"ppid"`
	ExePath       string   `json:"exepath,omitempty"`
	InvokedPath   string   `json:"invoked,omitempty"`
	Argv          []string `json:"argv,omitempty"`
	Cwd           string   `json:"cwd,omitempty"`
	Comm          string   `json:"comm,omitempty"`
	UID           uint32   `json:"uid"`
	GID           uint32   `json:"gid"`
	HasCreds      bool     `json:"creds,omitempty"`
	StartTimeNs   int64    `json:"start,omitempty"`
	IsExecSession bool     `json:"execsess,omitempty"`
	SHA256        string   `json:"sha256,omitempty"`
	UpperLayer    bool     `json:"upper,omitempty"`
	LowerLayer    bool     `json:"lower,omitempty"`
	HasBinaryInfo bool     `json:"binfo,omitempty"`
	FromMemfd     bool     `json:"memfd,omitempty"`
	StdinType     string   `json:"stdin,omitempty"`
	StdoutType    string   `json:"stdout,omitempty"`
	StderrType    string   `json:"stderr,omitempty"`
	TTY           uint32   `json:"tty,omitempty"`
	StdinPipeComm string   `json:"stdinpipe,omitempty"`
	// pending is the exec announced by the latest execve/execveat exit,
	// until the process's next event shows whether it happened.
	pending *pendingExec
	// threads counts the group's other threads whose creation was seen and
	// whose exit was not, so a leader exit can tell whether the group lives on.
	threads int
}

// pendingExec is an exec whose syscall exit was seen. gVisor reports that
// exit as successful before it loads the new image, so it only says the
// exec started: loading can still fail (a missing file during a PATH
// search, a bad binary). While the image loads, other threads of the
// process keep running under their old names; they are killed only after
// the sentry/execve point is sent, and the exec'ing thread is renamed after
// that.
type pendingExec struct {
	invoked string
	argv    []string
	// comm is the name gVisor gives the task when the file is a binary:
	// the base name of the path, or the fd number for an fd-only execveat.
	// A script gets its interpreter's name instead.
	comm string
	// tid and oldComm identify the exec'ing thread and its name at the exit.
	tid     int32
	oldComm string
}

// execOutcome is what a later event shows about a pending exec.
type execOutcome int

const (
	execUnknown execOutcome = iota
	execHappened
	execFailed
)

// Exe returns argv[0], or the exe path when argv is unknown.
func (p ProcessInfo) Exe() string {
	if len(p.Argv) > 0 {
		return p.Argv[0]
	}
	return p.ExePath
}

// Args returns the arguments after argv[0] joined by spaces.
func (p ProcessInfo) Args() string {
	if len(p.Argv) < 2 {
		return ""
	}
	return strings.Join(p.Argv[1:], " ")
}

// Cmdline returns the process name followed by its arguments.
func (p ProcessInfo) Cmdline() string {
	if args := p.Args(); args != "" {
		return p.Comm + " " + args
	}
	return p.Comm
}

func (p *ProcessInfo) applyContext(ctx *pb.ContextData) {
	p.Pid = ctx.GetThreadGroupId()
	if ppid := ctx.GetParentThreadGroupId(); ppid != 0 {
		p.Ppid = ppid
	}
	if cwd := ctx.GetCwd(); cwd != "" {
		p.Cwd = cwd
	}
	if comm := ctx.GetProcessName(); comm != "" {
		p.Comm = truncateComm(comm)
	}
	if creds := ctx.GetCredentials(); creds != nil {
		p.UID = creds.GetEffectiveUid()
		p.GID = creds.GetEffectiveGid()
		p.HasCreds = true
	}
	if ctx.GetIsExecSession() {
		p.IsExecSession = true
	}
	if p.StartTimeNs == 0 {
		p.StartTimeNs = ctx.GetThreadGroupStartTimeNs()
	}
}

func (p *ProcessInfo) applyExec(info *pb.ExecveInfo) {
	p.threads = 0
	p.ExePath = info.GetBinaryPath()
	p.InvokedPath = resolvePath(invokedPath(info), linux.AT_FDCWD, "", p.Cwd)
	p.Argv = budgetArgv(info.GetArgv())
	p.Comm = truncateComm(path.Base(invokedPath(info)))
	p.HasBinaryInfo = info.GetBinaryMode() != 0
	p.SHA256 = hex.EncodeToString(info.GetBinarySha256())
	p.UpperLayer = info.GetBinaryOverlayfsUpper()
	p.LowerLayer = info.GetBinaryOverlayfsLower()
	p.FromMemfd = info.GetBinaryInMemfd()
	p.StdinType = fdType(info.GetStdin())
	p.StdoutType = fdType(info.GetStdout())
	p.StderrType = fdType(info.GetStderr())
	p.TTY = ttyOf(info.GetStdin(), info.GetStdout(), info.GetStderr())
	p.StdinPipeComm = truncateComm(info.GetPipeInputProc().GetContextData().GetProcessName())
}

// applySyscallExec records the exec announced by an execve/execveat exit
// without changing the row: whether it happened is only known from a later
// event (see resolve).
func (p *ProcessInfo) applySyscallExec(m *pb.Execve, ctx *pb.ContextData) {
	name := m.GetPathname()
	invoked := resolvePath(name, m.GetFd(), m.GetFdPath(), p.Cwd)
	if name == "" {
		name = strconv.FormatInt(m.GetFd(), 10)
		invoked = m.GetFdPath()
		if invoked == "" {
			invoked = fdPathPrefix + name
		}
	}
	p.pending = &pendingExec{
		invoked: invoked,
		argv:    budgetArgv(m.GetArgv()),
		comm:    truncateComm(path.Base(name)),
		tid:     ctx.GetThreadId(),
		oldComm: ctx.GetProcessName(),
	}
}

// resolve reports what an event from thread tid named comm shows about the
// exec. The task carrying the new binary's name, or the exec'ing thread
// itself renamed (a script, named after its interpreter), shows it
// happened; the exec'ing thread carrying on under its old name shows it
// failed (an exec of a program with the same name looks the same and is not
// confirmed). Events from other threads under other names say nothing.
func (e *pendingExec) resolve(tid int32, comm string) execOutcome {
	switch {
	case comm == "":
		return execUnknown
	case comm == e.comm && comm != e.oldComm:
		return execHappened
	case tid != e.tid:
		return execUnknown
	case comm != e.oldComm:
		return execHappened
	default:
		return execFailed
	}
}

// commitExec moves the row to a confirmed exec whose sentry/execve point was
// lost. Binary-level details (layer flags, hash, stdio) only come with that
// point, so they are left unknown.
func (p *ProcessInfo) commitExec(e *pendingExec, comm string) {
	*p = ProcessInfo{
		Pid:           p.Pid,
		Ppid:          p.Ppid,
		Cwd:           p.Cwd,
		UID:           p.UID,
		GID:           p.GID,
		HasCreds:      p.HasCreds,
		StartTimeNs:   p.StartTimeNs,
		IsExecSession: p.IsExecSession,
		TTY:           p.TTY,
		ExePath:       e.invoked,
		InvokedPath:   e.invoked,
		Argv:          e.argv,
		Comm:          comm,
	}
}

func invokedPath(info *pb.ExecveInfo) string {
	if execfn := info.GetExecfn(); execfn != "" {
		return execfn
	}
	return info.GetBinaryPath()
}

func (p *ProcessInfo) applyStart(start *pb.Start) {
	p.Argv = budgetArgv(start.GetArgs())
	if len(p.Argv) > 0 {
		p.ExePath = p.Argv[0]
		p.Comm = truncateComm(path.Base(p.Argv[0]))
	}
	if cwd := start.GetCwd(); cwd != "" {
		p.Cwd = cwd
	}
	if start.GetTerminal() {
		p.TTY = ttyUnknownNumber
	}
}

func (p ProcessInfo) clone() ProcessInfo {
	c := p
	c.pending = nil
	c.threads = 0
	c.Argv = append([]string(nil), p.Argv...)
	return c
}

func truncateComm(comm string) string {
	if len(comm) > maxCommLen {
		return comm[:maxCommLen]
	}
	return comm
}

func budgetArgv(argv []string) []string {
	budget := maxArgvBytes
	out := make([]string, 0, len(argv))
	for _, arg := range argv {
		if budget <= 0 {
			break
		}
		if len(arg) > budget {
			arg = arg[:budget]
		}
		out = append(out, arg)
		budget -= len(arg) + 1
	}
	return out
}

func fdType(fd *pb.FdInfo) string {
	if fd == nil {
		return ""
	}
	if sock := fd.GetSocket(); sock != nil {
		return socketFamilyType(sock.GetFamily())
	}
	switch fd.GetMode() & linux.S_IFMT {
	case linux.S_IFSOCK:
		return FDTypeUnix
	case linux.S_IFIFO:
		return FDTypePipe
	case linux.S_IFDIR:
		return FDTypeDirectory
	case 0:
		return ""
	default:
		return FDTypeFile
	}
}

func socketFamilyType(family uint32) string {
	switch family {
	case linux.AF_INET:
		return FDTypeIPv4
	case linux.AF_INET6:
		return FDTypeIPv6
	case linux.AF_UNIX:
		return FDTypeUnix
	case linux.AF_NETLINK:
		return FDTypeNetlink
	default:
		return ""
	}
}

func encodeDev(major, minor uint32) uint32 {
	return minor&devMinorLowMask | major<<devMinorBits | (minor&^devMinorLowMask)<<devMinorHighShift
}

func ttyOf(fds ...*pb.FdInfo) uint32 {
	for _, fd := range fds {
		name := fd.GetPath()
		switch {
		case strings.HasPrefix(name, ptsPrefix):
			if minor, err := strconv.ParseUint(strings.TrimPrefix(name, ptsPrefix), 10, 32); err == nil {
				return encodeDev(ptsMajor, uint32(minor))
			}
			return ttyUnknownNumber
		case strings.HasPrefix(name, ttyPrefix), name == consolePath:
			return ttyUnknownNumber
		}
	}
	return 0
}
