// Package fixture turns human-readable rule test fixtures into gVisor
// remote-sink packets and checks Falco alerts against their expectations.
package fixture

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	"gvisor.dev/gvisor/pkg/abi/linux"
	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
	"gvisor.dev/gvisor/pkg/sentry/seccheck/sinks/remote/wire"

	"github.com/falcosecurity/plugins/plugins/gvisor/pkg/gvisor"
)

const (
	pointExec      = "sentry/execve"
	pointClone     = "sentry/clone"
	pointTaskExit  = "sentry/task_exit"
	pointStart     = "container/start"
	pointConnect   = "syscall/connect"
	pointOpenat    = "syscall/openat"
	pointSocket    = "syscall/socket"
	pointPtrace    = "syscall/ptrace"
	pointSetuid    = "syscall/setuid"
	pointSetresuid = "syscall/setresuid"
	unixAddrPrefix = "unix:"
	flagSeparator  = "|"
	baseTimeNs     = 1_700_000_000_000_000_000
	stepNs         = int64(time.Millisecond)
)

var (
	errUnknownPoint = errors.New("unknown point")
	errUnknownName  = errors.New("unknown symbolic value")
)

var fdTypeModes = map[string]uint32{
	gvisor.FDTypeFile:      linux.S_IFREG,
	gvisor.FDTypeDirectory: linux.S_IFDIR,
	gvisor.FDTypePipe:      linux.S_IFIFO,
	gvisor.FDTypeUnix:      linux.S_IFSOCK,
}

var fdTypeFamilies = map[string]uint32{
	gvisor.FDTypeIPv4: linux.AF_INET,
	gvisor.FDTypeIPv6: linux.AF_INET6,
}

var openFlags = map[string]uint32{
	"O_RDONLY": linux.O_RDONLY,
	"O_WRONLY": linux.O_WRONLY,
	"O_RDWR":   linux.O_RDWR,
	"O_CREAT":  linux.O_CREAT,
	"O_TRUNC":  linux.O_TRUNC,
	"O_APPEND": linux.O_APPEND,
}

var socketDomains = map[string]int32{
	"AF_UNIX":    linux.AF_UNIX,
	"AF_INET":    linux.AF_INET,
	"AF_INET6":   linux.AF_INET6,
	"AF_PACKET":  linux.AF_PACKET,
	"AF_NETLINK": linux.AF_NETLINK,
}

var socketTypes = map[string]int32{
	"SOCK_STREAM": int32(linux.SOCK_STREAM),
	"SOCK_DGRAM":  int32(linux.SOCK_DGRAM),
	"SOCK_RAW":    int32(linux.SOCK_RAW),
	"SOCK_PACKET": int32(linux.SOCK_PACKET),
}

var ptraceRequests = map[string]int64{
	"PTRACE_ATTACH":   linux.PTRACE_ATTACH,
	"PTRACE_SEIZE":    linux.PTRACE_SEIZE,
	"PTRACE_TRACEME":  linux.PTRACE_TRACEME,
	"PTRACE_POKETEXT": linux.PTRACE_POKETEXT,
}

// Fixture is one rule test case: a sequence of sandbox events and the rules
// expected to fire. An empty Expect means no rule may fire.
type Fixture struct {
	Description string   `json:"description"`
	Expect      []string `json:"expect"`
	Events      []Event  `json:"events"`

	Name        string `json:"-"`
	ContainerID string `json:"-"`
}

// Event is one trace point in fixture form.
type Event struct {
	Point string `json:"point"`
	Pid   int32  `json:"pid"`
	Ppid  int32  `json:"ppid"`
	Comm  string `json:"comm"`
	UID   uint32 `json:"uid"`
	Cwd   string `json:"cwd"`

	Exe           string   `json:"exe"`
	Argv          []string `json:"argv"`
	UpperLayer    bool     `json:"upper_layer"`
	LowerLayer    bool     `json:"lower_layer"`
	Memfd         bool     `json:"memfd"`
	Stdin         string   `json:"stdin"`
	Stdout        string   `json:"stdout"`
	StdinPipeProc string   `json:"stdin_pipe_proc"`
	StdinPath     string   `json:"stdin_path"`
	ExecSession   bool     `json:"exec_session"`

	Child   int32  `json:"child"`
	Addr    string `json:"addr"`
	Path    string `json:"path"`
	Flags   string `json:"flags"`
	Domain  string `json:"domain"`
	Type    string `json:"type"`
	Request string `json:"request"`
	Errno   int64  `json:"errno"`
	ID      uint32 `json:"id"`
	RID     uint32 `json:"rid"`
	EID     uint32 `json:"eid"`
	SID     uint32 `json:"sid"`
}

// Load reads a fixture file. The container id is derived from the file
// name so alerts can be attributed to it.
func Load(path string) (Fixture, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Fixture{}, fmt.Errorf("read fixture: %w", err)
	}
	var f Fixture
	if err := json.Unmarshal(data, &f); err != nil {
		return Fixture{}, fmt.Errorf("decode fixture %s: %w", path, err)
	}
	f.Name = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	sum := sha256.Sum256([]byte(f.Name))
	f.ContainerID = hex.EncodeToString(sum[:])
	return f, nil
}

// Packets encodes the fixture as remote-sink messages.
func (f Fixture) Packets() ([][]byte, error) {
	packets := make([][]byte, 0, len(f.Events))
	for i, e := range f.Events {
		msgType, msg, err := e.message(f.ContainerID, baseTimeNs+int64(i)*stepNs)
		if err != nil {
			return nil, fmt.Errorf("%s event %d: %w", f.Name, i, err)
		}
		pkt, err := encode(msgType, msg)
		if err != nil {
			return nil, err
		}
		packets = append(packets, pkt)
	}
	return packets, nil
}

func (e Event) context(containerID string, timeNs int64) *pb.ContextData {
	cwd := e.Cwd
	if cwd == "" {
		cwd = "/"
	}
	return &pb.ContextData{
		TimeNs:              timeNs,
		ThreadId:            e.Pid,
		ThreadGroupId:       e.Pid,
		ParentThreadGroupId: e.Ppid,
		ContainerId:         containerID,
		ProcessName:         e.Comm,
		Cwd:                 cwd,
		Credentials:         &pb.Credentials{RealUid: e.UID, EffectiveUid: e.UID, RealGid: e.UID, EffectiveGid: e.UID},
		IsExecSession:       e.ExecSession,
	}
}

func (e Event) message(containerID string, timeNs int64) (pb.MessageType, proto.Message, error) {
	ctx := e.context(containerID, timeNs)
	exit := &pb.Exit{Errorno: e.Errno}
	switch e.Point {
	case pointStart:
		return pb.MessageType_MESSAGE_CONTAINER_START, &pb.Start{ContextData: ctx, Id: containerID, Args: e.Argv, Cwd: ctx.Cwd}, nil
	case pointExec:
		return pb.MessageType_MESSAGE_SENTRY_EXEC, e.exec(ctx), nil
	case pointClone:
		return pb.MessageType_MESSAGE_SENTRY_CLONE, &pb.CloneInfo{ContextData: ctx, CreatedThreadGroupId: e.Child, CreatedThreadId: e.Child}, nil
	case pointTaskExit:
		return pb.MessageType_MESSAGE_SENTRY_TASK_EXIT, &pb.TaskExit{ContextData: ctx}, nil
	case pointConnect:
		addr, err := sockaddr(e.Addr)
		if err != nil {
			return 0, nil, err
		}
		return syscallMsg(pb.MessageType_MESSAGE_SYSCALL_CONNECT, "connect", func(nr uint64) proto.Message {
			return &pb.Connect{ContextData: ctx, Exit: exit, Sysno: nr, Address: addr}
		})
	case pointOpenat:
		flags, err := parseFlags(e.Flags)
		if err != nil {
			return 0, nil, err
		}
		return syscallMsg(pb.MessageType_MESSAGE_SYSCALL_OPEN, "openat", func(nr uint64) proto.Message {
			return &pb.Open{ContextData: ctx, Exit: exit, Sysno: nr, Fd: linux.AT_FDCWD, Pathname: e.Path, Flags: flags}
		})
	case pointSocket:
		domain, okD := socketDomains[e.Domain]
		typ, okT := socketTypes[e.Type]
		if !okD || !okT {
			return 0, nil, fmt.Errorf("%w: socket %s/%s", errUnknownName, e.Domain, e.Type)
		}
		return syscallMsg(pb.MessageType_MESSAGE_SYSCALL_SOCKET, "socket", func(nr uint64) proto.Message {
			return &pb.Socket{ContextData: ctx, Exit: exit, Sysno: nr, Domain: domain, Type: typ}
		})
	case pointPtrace:
		req, ok := ptraceRequests[e.Request]
		if !ok {
			return 0, nil, fmt.Errorf("%w: ptrace %s", errUnknownName, e.Request)
		}
		return syscallMsg(pb.MessageType_MESSAGE_SYSCALL_PTRACE, "ptrace", func(nr uint64) proto.Message {
			return &pb.Ptrace{ContextData: ctx, Exit: exit, Sysno: nr, Request: req}
		})
	case pointSetuid:
		return syscallMsg(pb.MessageType_MESSAGE_SYSCALL_SETID, "setuid", func(nr uint64) proto.Message {
			return &pb.Setid{ContextData: ctx, Exit: exit, Sysno: nr, Id: e.ID}
		})
	case pointSetresuid:
		return syscallMsg(pb.MessageType_MESSAGE_SYSCALL_SETRESID, "setresuid", func(nr uint64) proto.Message {
			return &pb.Setresid{ContextData: ctx, Exit: exit, Sysno: nr, Rid: e.RID, Eid: e.EID, Sid: e.SID}
		})
	default:
		return 0, nil, fmt.Errorf("%w: %q", errUnknownPoint, e.Point)
	}
}

func (e Event) exec(ctx *pb.ContextData) *pb.ExecveInfo {
	info := &pb.ExecveInfo{
		ContextData:          ctx,
		BinaryPath:           e.Exe,
		Argv:                 e.Argv,
		BinaryOverlayfsUpper: e.UpperLayer,
		BinaryOverlayfsLower: e.LowerLayer,
		BinaryInMemfd:        e.Memfd,
		Stdin:                fdInfo(e.Stdin),
		Stdout:               fdInfo(e.Stdout),
	}
	if e.StdinPath != "" {
		if info.Stdin == nil {
			info.Stdin = &pb.FdInfo{Mode: linux.S_IFCHR}
		}
		info.Stdin.Path = e.StdinPath
	}
	if e.StdinPipeProc != "" {
		info.PipeInputProc = &pb.PipeProcInfo{ContextData: &pb.ContextData{ProcessName: e.StdinPipeProc}}
	}
	return info
}

func syscallMsg(msgType pb.MessageType, name string, build func(uint64) proto.Message) (pb.MessageType, proto.Message, error) {
	nr, ok := gvisor.SyscallNumber(name)
	if !ok {
		return 0, nil, fmt.Errorf("%w: syscall %s", errUnknownName, name)
	}
	return msgType, build(nr), nil
}

func fdInfo(kind string) *pb.FdInfo {
	if kind == "" {
		return nil
	}
	if family, ok := fdTypeFamilies[kind]; ok {
		return &pb.FdInfo{Mode: linux.S_IFSOCK, Socket: &pb.SocketInfo{Family: family}}
	}
	return &pb.FdInfo{Mode: fdTypeModes[kind]}
}

func parseFlags(spec string) (uint32, error) {
	var flags uint32
	if spec == "" {
		return flags, nil
	}
	for _, name := range strings.Split(spec, flagSeparator) {
		bit, ok := openFlags[name]
		if !ok {
			return 0, fmt.Errorf("%w: flag %s", errUnknownName, name)
		}
		flags |= bit
	}
	return flags, nil
}

func sockaddr(addr string) ([]byte, error) {
	if path, ok := strings.CutPrefix(addr, unixAddrPrefix); ok {
		out := binary.LittleEndian.AppendUint16(nil, linux.AF_UNIX)
		return append(append(out, path...), 0), nil
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("address %q: %w", addr, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("port in %q: %w", addr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("%w: ip %q", errUnknownName, host)
	}
	if v4 := ip.To4(); v4 != nil {
		out := binary.LittleEndian.AppendUint16(nil, linux.AF_INET)
		out = binary.BigEndian.AppendUint16(out, uint16(port))
		return append(out, v4...), nil
	}
	out := binary.LittleEndian.AppendUint16(nil, linux.AF_INET6)
	out = binary.BigEndian.AppendUint16(out, uint16(port))
	out = append(out, 0, 0, 0, 0)
	return append(out, ip.To16()...), nil
}

func encode(msgType pb.MessageType, msg proto.Message) ([]byte, error) {
	payload, err := proto.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("marshal %s: %w", msgType, err)
	}
	hdr := wire.Header{HeaderSize: wire.HeaderStructSize, MessageType: uint16(msgType)}
	out := make([]byte, wire.HeaderStructSize, wire.HeaderStructSize+len(payload))
	hdr.MarshalBytes(out)
	return append(out, payload...), nil
}
