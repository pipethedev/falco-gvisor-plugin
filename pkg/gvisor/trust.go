package gvisor

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	rootUID        = 0
	rootGID        = 0
	otherWriteMode = 0o002
	groupWriteMode = 0o020
)

const (
	runscExeName     = "runsc"
	deletedExeSuffix = " (deleted)"
)

var (
	errUntrustedPeer      = errors.New("peer uid not allowed")
	errNoPeerCredentials  = errors.New("peer credentials unavailable")
	errPeerNotRunsc       = errors.New("peer executable is not runsc")
	errUntrustedSocketDir = errors.New("untrusted socket directory")
)

// allowedPeer reports whether a connecting process may act as a sandbox
// sink: runsc runs as root, and Falco's own user is allowed for tests and
// single-user setups.
func allowedPeer(uid uint32, self int) bool {
	return uid == rootUID || int64(uid) == int64(self)
}

// checkSocketDir rejects socket directories another user could use to swap
// or intercept the socket: symlinks, world-writable directories,
// group-writable directories whose group is not root, and directories
// owned by someone other than root or Falco's user.
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
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if !allowedPeer(st.Uid, self) {
		return fmt.Errorf("%w: %s is owned by uid %d", errUntrustedSocketDir, dir, st.Uid)
	}
	if info.Mode().Perm()&groupWriteMode != 0 && st.Gid != rootGID {
		return fmt.Errorf("%w: %s is writable by group %d", errUntrustedSocketDir, dir, st.Gid)
	}
	return nil
}

// isRunscExe reports whether a /proc/<pid>/exe target is a runsc binary,
// including one replaced on disk since it started (an upgrade).
func isRunscExe(exe string) bool {
	return exe != "" && filepath.Base(strings.TrimSuffix(exe, deletedExeSuffix)) == runscExeName
}

// checkPeer decides whether a connecting process may act as a sandbox sink.
func checkPeer(pid int32, uid uint32, credOK bool, self int, requireRunsc bool) error {
	if !credOK {
		return errNoPeerCredentials
	}
	if !allowedPeer(uid, self) {
		return errUntrustedPeer
	}
	if requireRunsc && !isRunscExe(peerExe(pid)) {
		return errPeerNotRunsc
	}
	return nil
}
