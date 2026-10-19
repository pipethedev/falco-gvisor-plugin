package main

import (
	"sync"

	"github.com/falcosecurity/plugins/plugins/gvisor/pkg/gvisor"
)

// cachedEvents is how many decoded events stay referenced. Falco may call
// extract_fields and event_to_string from several threads, and values
// handed to it (ipaddr bytes in particular) must stay valid until its next
// call; keeping recent events referenced covers every in-flight call.
const cachedEvents = 64

type cachedEvent struct {
	evt *gvisor.Event
	err error
}

// eventCache maps event numbers to decoded events, safe for concurrent use.
type eventCache struct {
	mu      sync.Mutex
	entries map[uint64]cachedEvent
	order   []uint64
}

func newEventCache() *eventCache {
	return &eventCache{entries: make(map[uint64]cachedEvent, cachedEvents)}
}

// get returns the decoded event for num, decoding it with load on a miss.
// load runs under the lock on purpose: concurrent misses for the same event
// then share one decoded copy instead of each holding its own, whose ipaddr
// bytes Falco might still be reading. Extraction is synchronous, so this
// serialisation costs nothing today; do not move load outside the lock.
func (c *eventCache) get(num uint64, load func() (*gvisor.Event, error)) (*gvisor.Event, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if hit, ok := c.entries[num]; ok {
		return hit.evt, hit.err
	}
	evt, err := load()
	if len(c.order) >= cachedEvents {
		delete(c.entries, c.order[0])
		c.order = c.order[1:]
	}
	c.entries[num] = cachedEvent{evt: evt, err: err}
	c.order = append(c.order, num)
	return evt, err
}
