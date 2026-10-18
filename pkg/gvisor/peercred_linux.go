package gvisor

import (
	"net"

	"golang.org/x/sys/unix"
)

func peerCred(conn *net.UnixConn) (pid int32, uid uint32, ok bool) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, 0, false
	}
	_ = raw.Control(func(fd uintptr) {
		if cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED); err == nil {
			pid, uid, ok = cred.Pid, cred.Uid, true
		}
	})
	return pid, uid, ok
}
