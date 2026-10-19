package gvisor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
)

const (
	maxCommandOutput = 16 << 20
	maxCommandStderr = 64 << 10
)

var errOutputTruncated = errors.New("command output exceeds the size limit")

// Runner executes external commands. onStart receives the child PID once
// the process is running.
type Runner interface {
	Run(ctx context.Context, onStart func(pid int32), name string, args ...string) ([]byte, error)
}

// execRunner runs real commands. Output beyond outputLimit (maxCommandOutput
// when zero) makes Run fail, so a cut-off runsc list is never parsed as a
// complete one.
type execRunner struct {
	outputLimit int
}

// limitedBuffer keeps at most limit bytes. The buffer is a named field, not
// embedded: an embedded bytes.Buffer would expose ReadFrom, which io.Copy
// (used by os/exec) prefers over Write, bypassing the limit.
type limitedBuffer struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	room := b.limit - b.buf.Len()
	if room < len(p) {
		b.truncated = true
	}
	if room > 0 {
		b.buf.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

func (b *limitedBuffer) Bytes() []byte {
	return b.buf.Bytes()
}

// Run implements Runner.
func (r execRunner) Run(ctx context.Context, onStart func(pid int32), name string, args ...string) ([]byte, error) {
	limit := r.outputLimit
	if limit == 0 {
		limit = maxCommandOutput
	}
	cmd := exec.CommandContext(ctx, name, args...)
	stdout := &limitedBuffer{limit: limit}
	stderr := &limitedBuffer{limit: maxCommandStderr}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %s: %w", name, err)
	}
	if onStart != nil {
		onStart(int32(cmd.Process.Pid))
	}
	if err := cmd.Wait(); err != nil {
		return stdout.Bytes(), fmt.Errorf("%s %v: %w: %s", name, args, err, bytes.TrimSpace(stderr.Bytes()))
	}
	if stdout.truncated {
		return nil, fmt.Errorf("%s %v: %w (%d bytes)", name, args, errOutputTruncated, limit)
	}
	return stdout.Bytes(), nil
}
