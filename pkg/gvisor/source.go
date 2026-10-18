package gvisor

import (
	"context"
	"errors"
	"sync"
	"time"
)

const minQueueShareEvents = 2

// Source runs everything behind an open event source: the socket server,
// the attacher, the metadata cache and the stats reporter.
type Source struct {
	queue    *eventQueue
	stats    *Stats
	server   *Server
	metadata *MetadataCache
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	once     sync.Once
}

// StartSource starts listening and attaching. Events, including periodic
// gvisor_stats events, are buffered in a byte-bounded queue read with Next.
func StartSource(cfg Config, runner Runner) (*Source, error) {
	fetcher, err := NewMetadataFetcher(cfg)
	if err != nil {
		return nil, err
	}
	stats := &Stats{}
	src := &Source{
		queue:    newEventQueue(cfg.MaxQueueBytes, minQueueShareEvents*int(MaxPluginEventSize(cfg)), stats),
		stats:    stats,
		metadata: NewMetadataCache(fetcher, cfg.metadataCacheTTL(), cfg.LabelAllowlist),
	}
	src.server = NewServer(cfg, src.queue.push, src.metadata, src.stats)
	if err := src.server.Start(); err != nil {
		return nil, errors.Join(err, src.metadata.Close())
	}

	ctx, cancel := context.WithCancel(context.Background())
	src.cancel = cancel
	attacher := NewAttacher(cfg, runner, src.server, src.stats)
	src.wg.Go(func() { attacher.Run(ctx, cfg.AttachOnOpen, cfg.attachInterval()) })
	if interval := cfg.statsInterval(); interval > 0 {
		src.wg.Go(func() { src.reportStats(ctx, interval) })
	}
	return src, nil
}

// NewExecRunner returns the Runner that executes real commands.
func NewExecRunner() Runner {
	return execRunner{}
}

// Next returns the oldest queued event, waiting up to wait. It returns
// ErrNoEvent on timeout and ErrSourceClosed once the source is closed and
// drained.
func (s *Source) Next(ctx context.Context, wait time.Duration) (QueuedEvent, error) {
	return s.queue.pop(ctx, wait)
}

// Stats exposes the source counters.
func (s *Source) Stats() *Stats {
	return s.stats
}

// Close stops all goroutines, releases the socket and closes the queue. It
// is idempotent.
func (s *Source) Close() {
	s.once.Do(func() {
		s.cancel()
		if err := s.server.Close(); err != nil {
			logger.Printf("close server: %v", err)
		}
		s.wg.Wait()
		if err := s.metadata.Close(); err != nil {
			logger.Printf("close metadata: %v", err)
		}
		s.queue.close()
	})
}

func (s *Source) reportStats(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	prev := s.stats.Snapshot(StatsSnapshot{}, time.Now())
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			snap := s.stats.Snapshot(prev, now)
			prev = snap
			s.publishStats(snap, now)
		}
	}
}

func (s *Source) publishStats(snap StatsSnapshot, now time.Time) {
	logger.Printf("stats: connections=%d events/s=%.1f queue_bytes=%d drops=%d (queue_full=%d queue_share=%d truncated=%d decode=%d unsupported=%d oversize=%d sandbox=%d) attach_failures=%d/%d unmonitored=%d attacher_failed=%t peer_rejected=%d",
		snap.Connections, snap.EventsPerSecond, snap.QueueBytes, snap.TotalDrops(), snap.DropChannelFull, snap.DropQueueShare, snap.DropTruncated,
		snap.DropDecodeError, snap.DropUnsupported, snap.DropContextSize, snap.DropSandbox, snap.AttachFailures, snap.AttachAttempts, snap.UnmonitoredSandboxes, snap.AttacherFailed, snap.PeerRejected)
	data, err := EncodeStats(snap)
	if err != nil {
		logger.Printf("stats event: %v", err)
		return
	}
	if err := s.queue.push(statsOwner, data, now); err != nil {
		s.stats.DropChannelFull.Add(1)
	}
}
