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
	FromMemfd     bool     `json:"memfd,omitempty"`
	StdinType     string   `json:"stdin,omitempty"`
	StdoutType    string   `json:"stdout,omitempty"`
	StderrType    string   `json:"stderr,omitempty"`
	TTY           uint32   `json:"tty,omitempty"`
	StdinPipeComm string   `json:"stdinpipe,omitempty"`
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
	if comm := ctx.GetProcessName(); comm != "" && p.Comm == "" {
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
	p.Argv = budgetArgv(info.GetArgv(), maxArgvBytes)
	p.Comm = truncateComm(path.Base(invokedPath(info)))
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

func invokedPath(info *pb.ExecveInfo) string {
	if execfn := info.GetExecfn(); execfn != "" {
		return execfn
	}
	return info.GetBinaryPath()
}

func (p *ProcessInfo) applyStart(start *pb.Start) {
	p.Argv = budgetArgv(start.GetArgs(), maxArgvBytes)
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
	c.Argv = append([]string(nil), p.Argv...)
	return c
}

func truncateComm(comm string) string {
	if len(comm) > maxCommLen {
		return comm[:maxCommLen]
	}
	return comm
}

func budgetArgv(argv []string, budget int) []string {
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
