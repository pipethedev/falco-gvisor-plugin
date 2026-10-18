//go:build linux

package gvisor

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
)

func testSourceConfig(t *testing.T) Config {
	t.Helper()
	cfg := DefaultConfig()
	cfg.SocketPath = filepath.Join(t.TempDir(), "gvisor.sock")
	cfg.MetadataProvider = providerNone
	cfg.AttachOnOpen = false
	cfg.AttachIntervalSeconds = 0
	cfg.StatsIntervalSeconds = 0
	return cfg
}

func TestSourceDeliversThroughQueue(t *testing.T) {
	src, err := StartSource(testSourceConfig(t), &fakeRunner{list: "[]"})
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()

	if _, err := src.Next(context.Background(), shortWait); !errors.Is(err, ErrNoEvent) {
		t.Fatalf("empty source err = %v", err)
	}
	conn := connectSandbox(t, src.server.socketPath)
	send(t, conn, mustPacket(t, pb.MessageType_MESSAGE_SENTRY_EXEC, &pb.ExecveInfo{
		ContextData: testContext(1, 0, "sh"), BinaryPath: "/bin/sh", Argv: []string{"sh"},
	}))
	queued, err := src.Next(context.Background(), testWait)
	if err != nil {
		t.Fatal(err)
	}
	evt, err := DecodeEvent(queued.Data)
	if err != nil || evt.Context.Process.Comm != "sh" {
		t.Fatalf("decoded %+v, %v", evt.Context.Process, err)
	}
	if queued.Time.UnixNano() != testContext(1, 0, "sh").GetTimeNs() {
		t.Errorf("event time %v does not carry the gVisor timestamp", queued.Time)
	}
}

func TestSourceOpenCloseCycles(t *testing.T) {
	cfg := testSourceConfig(t)
	for range 3 {
		src, err := StartSource(cfg, &fakeRunner{list: "[]"})
		if err != nil {
			t.Fatalf("reopen on the same socket: %v", err)
		}
		connectSandbox(t, cfg.SocketPath)
		src.Close()
		src.Close()
		if _, err := src.Next(context.Background(), shortWait); !errors.Is(err, ErrSourceClosed) {
			t.Fatalf("Next after close err = %v", err)
		}
	}
}

func TestSourceFloodingSandboxDoesNotStarveOthers(t *testing.T) {
	cfg := testSourceConfig(t)
	cfg.MaxEventSize = minMaxEventSize
	cfg.MaxQueueBytes = minMaxQueueBytes
	src, err := StartSource(cfg, &fakeRunner{list: "[]"})
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()

	noisy := connectSandbox(t, cfg.SocketPath)
	quiet := connectSandbox(t, cfg.SocketPath)
	waitFor(t, "both connections", func() bool { return src.stats.Connections.Load() == 2 })

	const floodEvents = 6000
	for i := range floodEvents {
		ctx := testContext(int32(i%500+2), 1, "flood")
		send(t, noisy, mustPacket(t, pb.MessageType_MESSAGE_SENTRY_EXEC, &pb.ExecveInfo{ContextData: ctx, BinaryPath: "/bin/true", Argv: []string{"true"}}))
	}
	waitFor(t, "share drops", func() bool { return src.stats.DropQueueShare.Load() > 0 })

	quietCtx := testContext(7, 1, "quiet")
	quietCtx.ContainerId = "quietcontainer000000000000000000000000000000000000000000000000000"
	send(t, quiet, mustPacket(t, pb.MessageType_MESSAGE_SENTRY_EXEC, &pb.ExecveInfo{ContextData: quietCtx, BinaryPath: "/bin/id", Argv: []string{"id"}}))
	waitFor(t, "quiet event processed", func() bool {
		return src.stats.Events.Load()+src.stats.DropQueueShare.Load()+src.stats.DropChannelFull.Load() >= floodEvents+1
	})

	for {
		queued, err := src.Next(context.Background(), shortWait)
		if err != nil {
			t.Fatalf("the quiet sandbox's event was dropped while another sandbox flooded the queue (share drops=%d, full drops=%d)",
				src.stats.DropQueueShare.Load(), src.stats.DropChannelFull.Load())
		}
		evt, err := DecodeEvent(queued.Data)
		if err == nil && evt.Context.Process.Comm == "id" {
			return
		}
	}
}
