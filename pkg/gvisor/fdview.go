package gvisor

import (
	"net"
	"path"

	"gvisor.dev/gvisor/pkg/abi/linux"
	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
)

var fdTypeChars = map[string]string{
	FDTypeFile:      "f",
	FDTypeDirectory: "d",
	FDTypeIPv4:      "4",
	FDTypeIPv6:      "6",
	FDTypeUnix:      "u",
	FDTypeNetlink:   "n",
	FDTypePipe:      "p",
}

// fdView is the file descriptor information a point exposes.
type fdView struct {
	name    string
	nameRaw string
	typ     string
	isFile  bool
	sip     net.IP
	sport   uint16
	rip     net.IP
	rport   uint16
	l4proto string
}

func fdViewOf(p Point) (fdView, bool) {
	cwd := p.Context().GetCwd()
	switch m := p.Msg.(type) {
	case *pb.Open:
		return fileView(m.GetPathname(), m.GetFd(), m.GetFdPath(), cwd), true
	case *pb.Execve:
		return fileView(m.GetPathname(), m.GetFd(), m.GetFdPath(), cwd), true
	case *pb.Connect:
		sa, ok := parseSockaddr(m.GetAddress())
		if !ok {
			return fdView{}, false
		}
		v := socketView(sa)
		v.sip, v.sport, v.rip, v.rport = normalizeIP(sa.IP), sa.Port, normalizeIP(sa.IP), sa.Port
		return v, true
	case *pb.Accept:
		sa, ok := parseSockaddr(m.GetAddress())
		if !ok {
			return fdView{}, false
		}
		v := socketView(sa)
		v.rip, v.rport = normalizeIP(sa.IP), sa.Port
		return v, true
	case *pb.Bind:
		sa, ok := parseSockaddr(m.GetAddress())
		if !ok {
			return fdView{}, false
		}
		v := socketView(sa)
		v.sip, v.sport = normalizeIP(sa.IP), sa.Port
		return v, true
	case *pb.Listen:
		v := fdView{typ: socketFamilyType(uint32(m.GetSocketFamily())), l4proto: l4ProtoOf(m.GetSocketFamily(), m.GetSocketType())}
		if sa, ok := parseSockaddr(m.GetAddress()); ok {
			v.name, v.nameRaw = sa.Endpoint(), sa.Endpoint()
			v.sip, v.sport = normalizeIP(sa.IP), sa.Port
		}
		return v, true
	case *pb.Socket:
		return fdView{typ: socketFamilyType(uint32(m.GetDomain())), l4proto: l4ProtoOf(m.GetDomain(), m.GetType())}, true
	default:
		return fdView{}, false
	}
}

func fileView(pathname string, dirfd int64, dirPath, cwd string) fdView {
	return fdView{
		name:    resolvePath(pathname, dirfd, dirPath, cwd),
		nameRaw: pathname,
		typ:     FDTypeFile,
		isFile:  true,
	}
}

func socketView(sa Sockaddr) fdView {
	endpoint := sa.Endpoint()
	return fdView{name: endpoint, nameRaw: endpoint, typ: sa.fdType()}
}

func resolvePath(pathname string, dirfd int64, dirPath, cwd string) string {
	if pathname == "" || path.IsAbs(pathname) {
		return pathname
	}
	base := cwd
	if dirfd != linux.AT_FDCWD {
		base = dirPath
	}
	if base == "" {
		return ""
	}
	return path.Join(base, pathname)
}

func normalizeIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip
}
