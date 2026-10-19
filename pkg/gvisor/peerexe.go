package gvisor

import (
	"os"
	"strconv"
)

const procRoot = "/proc"

// peerExe returns the executable of a process as seen through /proc, or ""
// when it cannot be read (other PID namespace, process gone, no /proc).
func peerExe(pid int32) string {
	if pid <= 0 {
		return ""
	}
	exe, err := os.Readlink(procRoot + "/" + strconv.Itoa(int(pid)) + "/exe")
	if err != nil {
		return ""
	}
	return exe
}
