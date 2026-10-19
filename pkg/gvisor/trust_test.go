package gvisor

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

const untrustedTestGID = 12345

func TestAllowedPeer(t *testing.T) {
	const self = 1000
	cases := map[uint32]bool{0: true, self: true, 1001: false, 65534: false}
	for uid, want := range cases {
		if got := allowedPeer(uid, self); got != want {
			t.Errorf("allowedPeer(%d) = %v, want %v", uid, got, want)
		}
	}
}

func TestCheckSocketDir(t *testing.T) {
	self := os.Geteuid()
	base := t.TempDir()

	good := filepath.Join(base, "good")
	if err := os.Mkdir(good, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := checkSocketDir(good, self); err != nil {
		t.Errorf("private directory rejected: %v", err)
	}

	open := filepath.Join(base, "open")
	if err := os.Mkdir(open, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := checkSocketDir(open, self); !errors.Is(err, errUntrustedSocketDir) {
		t.Errorf("world-writable directory accepted: %v", err)
	}

	group := filepath.Join(base, "group")
	if err := os.Mkdir(group, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(group, 0o770); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(group); err == nil {
		if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Gid == rootGID {
			if err := os.Chown(group, -1, untrustedTestGID); err != nil {
				t.Skipf("cannot give the test directory a non-root group: %v", err)
			}
		}
	}
	if err := checkSocketDir(group, self); !errors.Is(err, errUntrustedSocketDir) {
		t.Errorf("group-writable directory with a non-root group accepted: %v", err)
	}

	link := filepath.Join(base, "link")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	if err := checkSocketDir(link, self); !errors.Is(err, errUntrustedSocketDir) {
		t.Errorf("symlinked directory accepted: %v", err)
	}

	if err := checkSocketDir(good, self+1); self != rootUID && !errors.Is(err, errUntrustedSocketDir) {
		t.Errorf("directory owned by another user accepted: %v", err)
	}
}

func TestCheckPeer(t *testing.T) {
	self := os.Geteuid()
	cases := []struct {
		name    string
		credOK  bool
		uid     uint32
		runsc   bool
		wantErr error
	}{
		{"no credentials", false, 0, false, errNoPeerCredentials},
		{"other user", true, uint32(self) + 1, false, errUntrustedPeer},
		{"root", true, rootUID, false, nil},
		{"self", true, uint32(self), false, nil},
		{"not runsc", true, uint32(self), true, errPeerNotRunsc},
	}
	for _, tc := range cases {
		err := checkPeer(int32(os.Getpid()), tc.uid, tc.credOK, self, tc.runsc)
		if tc.wantErr == nil && err != nil || tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
			if tc.name == "other user" && self == rootUID {
				continue
			}
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.wantErr)
		}
	}
}

func TestIsRunscExe(t *testing.T) {
	cases := map[string]bool{
		"/usr/bin/runsc":                    true,
		"/usr/local/bin/runsc (deleted)":    true,
		"/usr/bin/runsc-evil":               false,
		"/tmp/runsc.sh":                     false,
		"/usr/bin/containerd-shim-runsc-v1": false,
		"":                                  false,
	}
	for exe, want := range cases {
		if got := isRunscExe(exe); got != want {
			t.Errorf("isRunscExe(%q) = %v, want %v", exe, got, want)
		}
	}
}
