//go:build !linux

package gvisor

import "net"

func peerCred(*net.UnixConn) (pid int32, uid uint32, ok bool) {
	return 0, 0, false
}
