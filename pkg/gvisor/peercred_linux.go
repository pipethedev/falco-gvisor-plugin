package gvisor

import (
	"net"

	"golang.org/x/sys/unix"
)

func peerPID(conn *net.UnixConn) int32 {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0
	}
	var pid int32
	_ = raw.Control(func(fd uintptr) {
		if cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED); err == nil {
			pid = cred.Pid
		}
	})
	return pid
}
