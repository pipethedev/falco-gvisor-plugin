package main

import (
	"errors"
	"sync"
	"testing"

	"github.com/falcosecurity/plugins/plugins/gvisor/pkg/gvisor"
)

func TestEventCacheConcurrent(t *testing.T) {
	cache := newEventCache()
	var loads sync.Map
	const workers, events = 8, 200
	var wg sync.WaitGroup
	for w := range workers {
		wg.Go(func() {
			for i := range events {
				num := uint64(i % (cachedEvents / 2))
				evt, err := cache.get(num, func() (*gvisor.Event, error) {
					loads.Store(num, w)
					return &gvisor.Event{Point: gvisor.Point{Dropped: uint32(num)}}, nil
				})
				if err != nil || evt.Point.Dropped != uint32(num) {
					t.Errorf("event %d: got %+v, %v", num, evt, err)
					return
				}
			}
		})
	}
	wg.Wait()
	if n := len(cache.entries); n > cachedEvents || n != len(cache.order) {
		t.Errorf("cache holds %d entries (%d ordered), cap %d", n, len(cache.order), cachedEvents)
	}
}

func TestEventCacheKeepsRecentEventsAndErrors(t *testing.T) {
	cache := newEventCache()
	first, _ := cache.get(1, func() (*gvisor.Event, error) { return &gvisor.Event{}, nil })
	for num := uint64(2); num < cachedEvents; num++ {
		_, _ = cache.get(num, func() (*gvisor.Event, error) { return &gvisor.Event{}, nil })
	}
	again, _ := cache.get(1, func() (*gvisor.Event, error) { t.Fatal("recent event decoded twice"); return nil, nil })
	if again != first {
		t.Error("a recent event was not kept referenced")
	}

	boom := errors.New("bad payload")
	if _, err := cache.get(999, func() (*gvisor.Event, error) { return nil, boom }); !errors.Is(err, boom) {
		t.Errorf("decode error not returned: %v", err)
	}
	if _, err := cache.get(999, func() (*gvisor.Event, error) { return nil, nil }); !errors.Is(err, boom) {
		t.Error("decode error not cached for the event")
	}
}
