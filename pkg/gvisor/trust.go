package gvisor

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

const (
	rootUID        = 0
	otherWriteMode = 0o002
)

var (
	errUntrustedPeer      = errors.New("peer uid not allowed")
	errUntrustedSocketDir = errors.New("untrusted socket directory")
)

// allowedPeer reports whether a connecting process may act as a sandbox
// sink: runsc runs as root, and Falco's own user is allowed for tests and
// single-user setups.
func allowedPeer(uid uint32, self int) bool {
	return uid == rootUID || int64(uid) == int64(self)
}

// checkSocketDir rejects socket directories another user could use to swap
// or intercept the socket: symlinks, world-writable directories and
// directories owned by someone other than root or Falco's user.
func checkSocketDir(dir string, self int) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("stat socket directory: %w", err)
	}
	if info.Mode()&fs.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%w: %s is not a directory", errUntrustedSocketDir, dir)
	}
	if info.Mode().Perm()&otherWriteMode != 0 {
		return fmt.Errorf("%w: %s is writable by other users", errUntrustedSocketDir, dir)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && !allowedPeer(st.Uid, self) {
		return fmt.Errorf("%w: %s is owned by uid %d", errUntrustedSocketDir, dir, st.Uid)
	}
	return nil
}
