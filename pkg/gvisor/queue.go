package gvisor

import (
	"context"
	"errors"
	"sync"
	"time"
)

const (
	statsOwner = 0
	compactMin = 1024
)

var (
	// ErrNoEvent is returned by Next when no event arrived within the wait.
	ErrNoEvent = errors.New("no event available")
	// ErrSourceClosed is returned by Next once the source has been closed.
	ErrSourceClosed = errors.New("source closed")
	// ErrQueueFull is returned when the queue's total byte budget is spent.
	ErrQueueFull = errors.New("event queue full")
	// ErrQueueShare is returned when one sandbox connection has used its
	// fair share of the queue's byte budget.
	ErrQueueShare = errors.New("sandbox share of the event queue exhausted")
)

// QueuedEvent is one encoded plugin event waiting for Falco.
type QueuedEvent struct {
	Data  []byte
	Time  time.Time
	owner uint64
}

// eventQueue is a FIFO bounded by the total size of the queued payloads, so
// bursts of large events cannot grow memory without limit. Each owner (a
// sandbox connection) may hold at most an equal share of the budget across
// the connected sandboxes, so one busy sandbox cannot crowd out the others.
// Pushes never block.
type eventQueue struct {
	maxBytes int
	minShare int
	stats    *Stats

	mu         sync.Mutex
	items      []QueuedEvent
	head       int
	bytes      int
	ownerBytes map[uint64]int
	closed     bool
	ready      chan struct{}
}

func newEventQueue(maxBytes, minShare int, stats *Stats) *eventQueue {
	return &eventQueue{
		maxBytes:   maxBytes,
		minShare:   minShare,
		stats:      stats,
		ownerBytes: make(map[uint64]int),
		ready:      make(chan struct{}, 1),
	}
}

func (q *eventQueue) share() int {
	conns := max(int(q.stats.Connections.Load()), 1)
	return max(q.maxBytes/conns, q.minShare)
}

func (q *eventQueue) push(owner uint64, data []byte, ts time.Time) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return ErrSourceClosed
	}
	if q.bytes+len(data) > q.maxBytes {
		return ErrQueueFull
	}
	if owner != statsOwner && q.ownerBytes[owner]+len(data) > q.share() {
		return ErrQueueShare
	}
	q.items = append(q.items, QueuedEvent{Data: data, Time: ts, owner: owner})
	q.bytes += len(data)
	q.ownerBytes[owner] += len(data)
	q.stats.QueueBytes.Store(int64(q.bytes))
	select {
	case q.ready <- struct{}{}:
	default:
	}
	return nil
}

func (q *eventQueue) pop(ctx context.Context, wait time.Duration) (QueuedEvent, error) {
	if evt, ok, err := q.tryPop(); ok || err != nil {
		return evt, err
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		select {
		case <-q.ready:
		case <-timer.C:
			return QueuedEvent{}, ErrNoEvent
		case <-ctx.Done():
			return QueuedEvent{}, ctx.Err()
		}
		if evt, ok, err := q.tryPop(); ok || err != nil {
			return evt, err
		}
	}
}

func (q *eventQueue) tryPop() (QueuedEvent, bool, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.head == len(q.items) {
		if q.closed {
			return QueuedEvent{}, false, ErrSourceClosed
		}
		return QueuedEvent{}, false, nil
	}
	evt := q.items[q.head]
	q.items[q.head] = QueuedEvent{}
	q.head++
	q.bytes -= len(evt.Data)
	if remaining := q.ownerBytes[evt.owner] - len(evt.Data); remaining > 0 {
		q.ownerBytes[evt.owner] = remaining
	} else {
		delete(q.ownerBytes, evt.owner)
	}
	q.stats.QueueBytes.Store(int64(q.bytes))
	q.compact()
	return evt, true, nil
}

// compact reclaims the slots before head once they make up half the backing
// array, so a queue that never drains completely keeps an array
// proportional to its live depth instead of growing with every push.
func (q *eventQueue) compact() {
	switch {
	case q.head == len(q.items):
		q.items, q.head = q.items[:0], 0
	case q.head >= compactMin && 2*q.head >= len(q.items):
		live := copy(q.items, q.items[q.head:])
		clear(q.items[live:])
		q.items, q.head = q.items[:live], 0
	}
}

func (q *eventQueue) close() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.closed = true
	select {
	case q.ready <- struct{}{}:
	default:
	}
}
