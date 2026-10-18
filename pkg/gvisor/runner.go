package gvisor

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
)

const maxCommandOutput = 64 << 10

// Runner executes external commands. onStart receives the child PID once
// the process is running.
type Runner interface {
	Run(ctx context.Context, onStart func(pid int32), name string, args ...string) ([]byte, error)
}

type execRunner struct{}

type limitedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := b.limit - b.Len(); room > 0 {
		b.Buffer.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

// Run implements Runner.
func (execRunner) Run(ctx context.Context, onStart func(pid int32), name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	stdout := &limitedBuffer{limit: maxCommandOutput}
	stderr := &limitedBuffer{limit: maxCommandOutput}
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
	return stdout.Bytes(), nil
}
