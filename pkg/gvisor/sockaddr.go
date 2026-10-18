package gvisor

import (
	"encoding/binary"
	"net"
	"strings"

	"gvisor.dev/gvisor/pkg/abi/linux"
)

const (
	sockaddrFamilyLen = 2
	sockaddrPortEnd   = 4
	sockaddrIPv4End   = 8
	sockaddrIPv6Start = 8
	sockaddrIPv6End   = 24
	abstractPrefix    = "@"
)

// Sockaddr is a decoded Linux socket address.
type Sockaddr struct {
	Family uint16
	IP     net.IP
	Port   uint16
	Path   string
}

func parseSockaddr(raw []byte) (Sockaddr, bool) {
	if len(raw) < sockaddrFamilyLen {
		return Sockaddr{}, false
	}
	family := binary.LittleEndian.Uint16(raw)
	switch family {
	case linux.AF_INET:
		if len(raw) < sockaddrIPv4End {
			return Sockaddr{}, false
		}
		return Sockaddr{
			Family: family,
			Port:   binary.BigEndian.Uint16(raw[sockaddrFamilyLen:sockaddrPortEnd]),
			IP:     net.IP(append([]byte(nil), raw[sockaddrPortEnd:sockaddrIPv4End]...)),
		}, true
	case linux.AF_INET6:
		if len(raw) < sockaddrIPv6End {
			return Sockaddr{}, false
		}
		return Sockaddr{
			Family: family,
			Port:   binary.BigEndian.Uint16(raw[sockaddrFamilyLen:sockaddrPortEnd]),
			IP:     net.IP(append([]byte(nil), raw[sockaddrIPv6Start:sockaddrIPv6End]...)),
		}, true
	case linux.AF_UNIX:
		return Sockaddr{Family: family, Path: unixPath(raw[sockaddrFamilyLen:])}, true
	default:
		return Sockaddr{Family: family}, true
	}
}

func unixPath(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	if raw[0] == 0 {
		return abstractPrefix + strings.TrimRight(string(raw[1:]), "\x00")
	}
	if end := strings.IndexByte(string(raw), 0); end >= 0 {
		return string(raw[:end])
	}
	return string(raw)
}

// Endpoint renders the address as Falco does: ip:port, [ip6]:port or a path.
func (s Sockaddr) Endpoint() string {
	if s.Family == linux.AF_UNIX {
		return s.Path
	}
	if s.IP == nil {
		return ""
	}
	return net.JoinHostPort(s.IP.String(), uintString(uint64(s.Port)))
}

func (s Sockaddr) fdType() string {
	return socketFamilyType(uint32(s.Family))
}
