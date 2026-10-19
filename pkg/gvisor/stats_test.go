package gvisor

import (
	"testing"
	"time"
)

func TestStatsDropsInterval(t *testing.T) {
	stats := &Stats{}
	first := stats.Snapshot(StatsSnapshot{}, time.Unix(100, 0))
	if first.DropsInterval != 0 {
		t.Errorf("first snapshot interval drops = %d", first.DropsInterval)
	}
	stats.DropTruncated.Add(2)
	stats.DropQueueShare.Add(1)
	second := stats.Snapshot(first, time.Unix(160, 0))
	if second.DropsInterval != 3 || second.TotalDrops() != 3 {
		t.Errorf("interval=%d total=%d", second.DropsInterval, second.TotalDrops())
	}
	third := stats.Snapshot(second, time.Unix(220, 0))
	if third.DropsInterval != 0 {
		t.Errorf("drops counted again in a quiet interval: %d", third.DropsInterval)
	}
}
