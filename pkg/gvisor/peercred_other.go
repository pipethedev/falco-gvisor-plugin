//go:build !linux

package gvisor

import "net"

func peerPID(*net.UnixConn) int32 {
	return 0
}
