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
}

// pendingExec is an exec whose syscall exit was seen. gVisor reports that
// exit as successful before it loads the new image, so it only says the
// exec started: loading can still fail (a missing file during a PATH
// search, a bad binary). comm is the name gVisor gives the task if the
// image loads.
type pendingExec struct {
	invoked string
	argv    []string
	comm    string
}

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
// without changing the row: whether it happened is only known from the
// process's next event (see ProcessTable.Apply).
func (p *ProcessInfo) applySyscallExec(m *pb.Execve) {
	name := m.GetPathname()
	if name == "" {
		name = strconv.FormatInt(m.GetFd(), 10)
	}
	p.pending = &pendingExec{
		invoked: resolvePath(m.GetPathname(), m.GetFd(), m.GetFdPath(), p.Cwd),
		argv:    budgetArgv(m.GetArgv()),
		comm:    truncateComm(path.Base(name)),
	}
}

// confirms reports whether an event whose context names the task comm
// shows that the pending exec replaced the process: gVisor renamed the task
// to the new program. An exec of a program with the same name cannot be
// told apart from a failed one, so it is never confirmed.
func (e *pendingExec) confirms(previousComm, comm string) bool {
	return e.comm != "" && comm == e.comm && previousComm != e.comm
}

// commitExec moves the row to a confirmed exec whose sentry/execve point was
// lost. Binary-level details (layer flags, hash, stdio) only come with that
// point, so they are left unknown.
func (p *ProcessInfo) commitExec(e *pendingExec) {
	exe := e.invoked
	if exe == "" {
		exe = e.comm
	}
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
		ExePath:       exe,
		InvokedPath:   e.invoked,
		Argv:          e.argv,
		Comm:          e.comm,
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
