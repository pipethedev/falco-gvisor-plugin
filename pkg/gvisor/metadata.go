package gvisor

import (
	"context"
	"fmt"
	"sync"
	"time"
)

const (
	metadataFetchTimeout = 2 * time.Second
	metadataNegativeTTL  = 30 * time.Second
	metadataConcurrency  = 4
	metadataMaxEntries   = 8192
)

// MetadataFetcher retrieves container metadata from a container runtime.
type MetadataFetcher interface {
	Fetch(ctx context.Context, containerID string) (*ContainerInfo, error)
	Close() error
}

type metadataEntry struct {
	info    *ContainerInfo
	expires time.Time
}

// MetadataCache resolves container metadata asynchronously and caches it.
// Lookup never blocks: unknown containers return nil until a fetch completes.
type MetadataCache struct {
	fetcher   MetadataFetcher
	ttl       time.Duration
	allowlist map[string]struct{}
	now       func() time.Time
	maxItems  int
	stats     *Stats

	ctx    context.Context
	cancel context.CancelFunc
	sem    chan struct{}
	wg     sync.WaitGroup

	mu       sync.Mutex
	entries  map[string]metadataEntry
	inflight map[string]chan struct{}
}

// NewMetadataCache returns a cache over fetcher. A nil fetcher disables
// metadata and every lookup returns nil.
func NewMetadataCache(fetcher MetadataFetcher, ttl time.Duration, allowlist []string, stats *Stats) *MetadataCache {
	ctx, cancel := context.WithCancel(context.Background())
	allowed := make(map[string]struct{}, len(allowlist))
	for _, key := range allowlist {
		allowed[key] = struct{}{}
	}
	return &MetadataCache{
		fetcher:   fetcher,
		ttl:       ttl,
		allowlist: allowed,
		now:       time.Now,
		maxItems:  metadataMaxEntries,
		stats:     stats,
		ctx:       ctx,
		cancel:    cancel,
		sem:       make(chan struct{}, metadataConcurrency),
		entries:   make(map[string]metadataEntry),
		inflight:  make(map[string]chan struct{}),
	}
}

// NewMetadataFetcher builds the fetcher selected by the config, or nil for
// the none provider.
func NewMetadataFetcher(cfg Config) (MetadataFetcher, error) {
	switch cfg.MetadataProvider {
	case providerDocker:
		return NewDockerFetcher(cfg.DockerSocket), nil
	case providerCRI:
		return NewCRIFetcher(cfg.CRISocket)
	case providerNone:
		return nil, nil
	default:
		return nil, fmt.Errorf("unknown metadata provider %q", cfg.MetadataProvider)
	}
}

// Lookup implements ContainerResolver.
func (m *MetadataCache) Lookup(containerID string) *ContainerInfo {
	if m.fetcher == nil || containerID == "" {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.entries[containerID]
	if ok && m.now().Before(entry.expires) {
		return entry.info
	}
	m.scheduleLocked(containerID)
	return entry.info
}

// Close cancels pending fetches, waits for them and closes the fetcher.
func (m *MetadataCache) Close() error {
	m.cancel()
	m.wg.Wait()
	if m.fetcher == nil {
		return nil
	}
	return m.fetcher.Close()
}

func (m *MetadataCache) scheduleLocked(containerID string) {
	if _, busy := m.inflight[containerID]; busy || m.ctx.Err() != nil {
		return
	}
	select {
	case m.sem <- struct{}{}:
	default:
		return
	}
	m.inflight[containerID] = make(chan struct{})
	m.wg.Add(1)
	go m.fetch(containerID)
}

func (m *MetadataCache) fetch(containerID string) {
	defer m.wg.Done()
	defer func() { <-m.sem }()

	ctx, cancel := context.WithTimeout(m.ctx, metadataFetchTimeout)
	defer cancel()
	var info *ContainerInfo
	var err error
	if perr := guard(m.stats, "metadata fetch", func() { info, err = m.fetcher.Fetch(ctx, containerID) }); perr != nil {
		info, err = nil, perr
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	close(m.inflight[containerID])
	delete(m.inflight, containerID)
	if err != nil {
		logger.Printf("container metadata for %s: %v", shortID(containerID), err)
		previous := m.entries[containerID].info
		m.entries[containerID] = metadataEntry{info: previous, expires: m.now().Add(metadataNegativeTTL)}
		m.pruneLocked()
		return
	}
	m.entries[containerID] = metadataEntry{info: m.filter(info), expires: m.now().Add(m.ttl)}
	m.pruneLocked()
}

func (m *MetadataCache) pruneLocked() {
	if len(m.entries) <= m.maxItems {
		return
	}
	now := m.now()
	for id, entry := range m.entries {
		if now.After(entry.expires) {
			delete(m.entries, id)
		}
	}
	for len(m.entries) > m.maxItems {
		var oldestID string
		var oldest time.Time
		for id, entry := range m.entries {
			if oldestID == "" || entry.expires.Before(oldest) {
				oldestID, oldest = id, entry.expires
			}
		}
		delete(m.entries, oldestID)
	}
}

func (m *MetadataCache) filter(info *ContainerInfo) *ContainerInfo {
	filtered := *info
	filtered.Labels = m.filterLabels(info.Labels)
	filtered.PodLabels = m.filterLabels(info.PodLabels)
	return &filtered
}

func (m *MetadataCache) filterLabels(labels map[string]string) map[string]string {
	if len(labels) == 0 {
		return nil
	}
	out := make(map[string]string, len(labels))
	for k, v := range labels {
		if _, ok := m.allowlist[k]; ok || len(m.allowlist) == 0 {
			out[k] = v
		}
	}
	return out
}
