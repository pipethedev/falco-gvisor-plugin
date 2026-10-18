package gvisor

import (
	"sync/atomic"
	"time"
)

// Stats holds plugin counters. All fields are safe for concurrent use.
type Stats struct {
	Connections          atomic.Int64
	TotalConnections     atomic.Uint64
	Events               atomic.Uint64
	DropChannelFull      atomic.Uint64
	DropTruncated        atomic.Uint64
	DropDecodeError      atomic.Uint64
	DropUnsupported      atomic.Uint64
	DropContextSize      atomic.Uint64
	DropSandbox          atomic.Uint64
	HandshakeRejected    atomic.Uint64
	PeerRejected         atomic.Uint64
	AttachAttempts       atomic.Uint64
	AttachFailures       atomic.Uint64
	QueueBytes           atomic.Int64
	UnmonitoredSandboxes atomic.Int64
	AttacherFailed       atomic.Bool
}

// StatsSnapshot is a point-in-time copy of Stats with derived rates.
type StatsSnapshot struct {
	Connections          int64   `json:"connections"`
	TotalConnections     uint64  `json:"total_connections"`
	Events               uint64  `json:"events"`
	EventsPerSecond      float64 `json:"events_per_second"`
	DropChannelFull      uint64  `json:"drops_channel_full"`
	DropTruncated        uint64  `json:"drops_truncated"`
	DropDecodeError      uint64  `json:"drops_decode_error"`
	DropUnsupported      uint64  `json:"drops_unsupported"`
	DropContextSize      uint64  `json:"drops_context_size"`
	DropSandbox          uint64  `json:"drops_sandbox"`
	HandshakeRejected    uint64  `json:"handshake_rejected"`
	PeerRejected         uint64  `json:"peer_rejected"`
	AttachAttempts       uint64  `json:"attach_attempts"`
	AttachFailures       uint64  `json:"attach_failures"`
	QueueBytes           int64   `json:"queue_bytes"`
	UnmonitoredSandboxes int64   `json:"unmonitored_sandboxes"`
	AttacherFailed       bool    `json:"attacher_failed"`
	TimeNs               int64   `json:"time_ns"`
}

// Snapshot copies the counters and computes the event rate since prev.
func (s *Stats) Snapshot(prev StatsSnapshot, now time.Time) StatsSnapshot {
	snap := StatsSnapshot{
		Connections:          s.Connections.Load(),
		TotalConnections:     s.TotalConnections.Load(),
		Events:               s.Events.Load(),
		DropChannelFull:      s.DropChannelFull.Load(),
		DropTruncated:        s.DropTruncated.Load(),
		DropDecodeError:      s.DropDecodeError.Load(),
		DropUnsupported:      s.DropUnsupported.Load(),
		DropContextSize:      s.DropContextSize.Load(),
		DropSandbox:          s.DropSandbox.Load(),
		HandshakeRejected:    s.HandshakeRejected.Load(),
		PeerRejected:         s.PeerRejected.Load(),
		AttachAttempts:       s.AttachAttempts.Load(),
		AttachFailures:       s.AttachFailures.Load(),
		QueueBytes:           s.QueueBytes.Load(),
		UnmonitoredSandboxes: s.UnmonitoredSandboxes.Load(),
		AttacherFailed:       s.AttacherFailed.Load(),
		TimeNs:               now.UnixNano(),
	}
	if prev.TimeNs > 0 && snap.TimeNs > prev.TimeNs {
		elapsed := time.Duration(snap.TimeNs - prev.TimeNs).Seconds()
		snap.EventsPerSecond = float64(snap.Events-prev.Events) / elapsed
	}
	return snap
}

// TotalDrops returns the sum of all drop counters.
func (s StatsSnapshot) TotalDrops() uint64 {
	return s.DropChannelFull + s.DropTruncated + s.DropDecodeError + s.DropUnsupported + s.DropContextSize + s.DropSandbox
}
