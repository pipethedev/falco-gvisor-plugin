package gvisor

import (
	"strconv"
	"strings"

	"gvisor.dev/gvisor/pkg/abi/linux"
)

const (
	flagSeparator                = "|"
	sockTypeMask  linux.SockType = 0xf
	evtResSuccess                = "SUCCESS"
	errnoPrefix                  = "E"
)

type flagName struct {
	bit  uint32
	name string
}

var openFlagNames = []flagName{
	{linux.O_CREAT, "O_CREAT"},
	{linux.O_EXCL, "O_EXCL"},
	{linux.O_NOCTTY, "O_NOCTTY"},
	{linux.O_TRUNC, "O_TRUNC"},
	{linux.O_APPEND, "O_APPEND"},
	{linux.O_NONBLOCK, "O_NONBLOCK"},
	{linux.O_DSYNC, "O_DSYNC"},
	{linux.O_DIRECT, "O_DIRECT"},
	{linux.O_LARGEFILE, "O_LARGEFILE"},
	{linux.O_DIRECTORY, "O_DIRECTORY"},
	{linux.O_NOFOLLOW, "O_NOFOLLOW"},
	{linux.O_NOATIME, "O_NOATIME"},
	{linux.O_CLOEXEC, "O_CLOEXEC"},
	{linux.O_PATH, "O_PATH"},
}

var accessModeNames = map[uint32]string{
	linux.O_RDONLY: "O_RDONLY",
	linux.O_WRONLY: "O_WRONLY",
	linux.O_RDWR:   "O_RDWR",
}

var socketDomainNames = map[int32]string{
	linux.AF_UNIX:    "AF_UNIX",
	linux.AF_INET:    "AF_INET",
	linux.AF_INET6:   "AF_INET6",
	linux.AF_NETLINK: "AF_NETLINK",
	linux.AF_PACKET:  "AF_PACKET",
}

var socketTypeNames = map[linux.SockType]string{
	linux.SOCK_STREAM:    "SOCK_STREAM",
	linux.SOCK_DGRAM:     "SOCK_DGRAM",
	linux.SOCK_RAW:       "SOCK_RAW",
	linux.SOCK_SEQPACKET: "SOCK_SEQPACKET",
	linux.SOCK_PACKET:    "SOCK_PACKET",
}

var ptraceRequestNames = map[int64]string{
	linux.PTRACE_TRACEME:  "PTRACE_TRACEME",
	linux.PTRACE_PEEKTEXT: "PTRACE_PEEKTEXT",
	linux.PTRACE_PEEKDATA: "PTRACE_PEEKDATA",
	linux.PTRACE_POKETEXT: "PTRACE_POKETEXT",
	linux.PTRACE_POKEDATA: "PTRACE_POKEDATA",
	linux.PTRACE_CONT:     "PTRACE_CONT",
	linux.PTRACE_ATTACH:   "PTRACE_ATTACH",
	linux.PTRACE_DETACH:   "PTRACE_DETACH",
	linux.PTRACE_SEIZE:    "PTRACE_SEIZE",
}

func openFlagsString(flags uint32) string {
	parts := []string{accessModeNames[flags&linux.O_ACCMODE]}
	for _, f := range openFlagNames {
		if flags&f.bit == f.bit {
			parts = append(parts, f.name)
		}
	}
	return strings.Join(parts, flagSeparator)
}

func isOpenRead(flags uint32) bool {
	mode := flags & linux.O_ACCMODE
	return mode == linux.O_RDONLY || mode == linux.O_RDWR
}

func isOpenWrite(flags uint32) bool {
	mode := flags & linux.O_ACCMODE
	return mode == linux.O_WRONLY || mode == linux.O_RDWR
}

func socketDomainString(domain int32) string {
	if name, ok := socketDomainNames[domain]; ok {
		return name
	}
	return strconv.FormatInt(int64(domain), 10)
}

func socketTypeString(typ int32) string {
	base := linux.SockType(typ) & sockTypeMask
	if name, ok := socketTypeNames[base]; ok {
		return name
	}
	return strconv.FormatInt(int64(base), 10)
}

func ptraceRequestString(req int64) string {
	if name, ok := ptraceRequestNames[req]; ok {
		return name
	}
	return strconv.FormatInt(req, 10)
}

func l4ProtoOf(typ int32) string {
	switch linux.SockType(typ) & sockTypeMask {
	case linux.SOCK_STREAM:
		return "tcp"
	case linux.SOCK_DGRAM:
		return "udp"
	case linux.SOCK_RAW:
		return "raw"
	default:
		return ""
	}
}

func uintString(v uint64) string {
	return strconv.FormatUint(v, 10)
}
