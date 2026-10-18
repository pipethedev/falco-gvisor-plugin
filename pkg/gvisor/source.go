package gvisor

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Source runs everything behind an open event source: the socket server,
// the attacher, the metadata cache and the stats reporter.
type Source struct {
	emit     EmitFunc
	stats    *Stats
	server   *Server
	metadata *MetadataCache
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	once     sync.Once
}

// StartSource starts listening and attaching. Events, including periodic
// gvisor_stats events, are handed to emit.
func StartSource(cfg Config, emit EmitFunc, runner Runner) (*Source, error) {
	fetcher, err := NewMetadataFetcher(cfg)
	if err != nil {
		return nil, err
	}
	src := &Source{
		emit:     emit,
		stats:    &Stats{},
		metadata: NewMetadataCache(fetcher, cfg.metadataCacheTTL(), cfg.LabelAllowlist),
	}
	src.server = NewServer(cfg, emit, src.metadata, src.stats)
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

// Stats exposes the source counters.
func (s *Source) Stats() *Stats {
	return s.stats
}

// Close stops all goroutines and releases the socket. It is idempotent and
// emit is never called after it returns.
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
	logger.Printf("stats: connections=%d events/s=%.1f drops=%d (channel_full=%d truncated=%d decode=%d unsupported=%d oversize=%d sandbox=%d) attach_failures=%d/%d",
		snap.Connections, snap.EventsPerSecond, snap.TotalDrops(), snap.DropChannelFull, snap.DropTruncated,
		snap.DropDecodeError, snap.DropUnsupported, snap.DropContextSize, snap.DropSandbox, snap.AttachFailures, snap.AttachAttempts)
	data, err := EncodeStats(snap)
	if err != nil {
		logger.Printf("stats event: %v", err)
		return
	}
	if !s.emit(data, now) {
		s.stats.DropChannelFull.Add(1)
	}
}
