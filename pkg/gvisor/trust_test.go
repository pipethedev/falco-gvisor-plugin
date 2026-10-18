package gvisor

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

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
