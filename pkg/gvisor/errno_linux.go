package gvisor

import (
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

func errnoName(errno int64) string {
	if name := unix.ErrnoName(syscall.Errno(errno)); name != "" {
		return name
	}
	return errnoPrefix + strconv.FormatInt(errno, 10)
}
