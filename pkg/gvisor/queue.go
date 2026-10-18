package gvisor

import (
	"context"
	"errors"
	"sync"
	"time"
)

var (
	// ErrNoEvent is returned by Next when no event arrived within the wait.
	ErrNoEvent = errors.New("no event available")
	// ErrSourceClosed is returned by Next once the source has been closed.
	ErrSourceClosed = errors.New("source closed")
)

// QueuedEvent is one encoded plugin event waiting for Falco.
type QueuedEvent struct {
	Data []byte
	Time time.Time
}

// eventQueue is a FIFO bounded by the total size of the queued payloads, so
// bursts of large events cannot grow memory without limit. Pushes never
// block; they fail when the budget is exhausted.
type eventQueue struct {
	maxBytes int
	stats    *Stats

	mu     sync.Mutex
	items  []QueuedEvent
	head   int
	bytes  int
	closed bool
	ready  chan struct{}
}

func newEventQueue(maxBytes int, stats *Stats) *eventQueue {
	return &eventQueue{maxBytes: maxBytes, stats: stats, ready: make(chan struct{}, 1)}
}

func (q *eventQueue) push(data []byte, ts time.Time) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed || q.bytes+len(data) > q.maxBytes {
		return false
	}
	q.items = append(q.items, QueuedEvent{Data: data, Time: ts})
	q.bytes += len(data)
	q.stats.QueueBytes.Store(int64(q.bytes))
	select {
	case q.ready <- struct{}{}:
	default:
	}
	return true
}

func (q *eventQueue) pop(ctx context.Context, wait time.Duration) (QueuedEvent, error) {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		if evt, ok, err := q.tryPop(); ok || err != nil {
			return evt, err
		}
		select {
		case <-q.ready:
		case <-timer.C:
			return QueuedEvent{}, ErrNoEvent
		case <-ctx.Done():
			return QueuedEvent{}, ctx.Err()
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
	q.stats.QueueBytes.Store(int64(q.bytes))
	if q.head == len(q.items) {
		q.items, q.head = q.items[:0], 0
	}
	return evt, true, nil
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
