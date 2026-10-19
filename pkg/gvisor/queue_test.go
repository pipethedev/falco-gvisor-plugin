package gvisor

import (
	"context"
	"errors"
	"testing"
	"time"
)

const (
	shortWait = 20 * time.Millisecond
	ownerA    = 1
	ownerB    = 2
)

func TestQueueByteBudget(t *testing.T) {
	stats := &Stats{}
	q := newEventQueue(10, 1, stats)
	if err := q.push(ownerA, make([]byte, 6), time.Unix(1, 0)); err != nil {
		t.Fatalf("push within budget: %v", err)
	}
	if err := q.push(ownerA, make([]byte, 5), time.Unix(2, 0)); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("push over budget err = %v", err)
	}
	if err := q.push(ownerA, make([]byte, 4), time.Unix(3, 0)); err != nil {
		t.Fatalf("push filling the budget exactly: %v", err)
	}
	if got := stats.QueueBytes.Load(); got != 10 {
		t.Errorf("queue bytes = %d", got)
	}
	first, err := q.pop(context.Background(), shortWait)
	if err != nil || first.Time != time.Unix(1, 0) {
		t.Fatalf("pop = %v, %v; want the first event", first.Time, err)
	}
	if got := stats.QueueBytes.Load(); got != 4 {
		t.Errorf("queue bytes after pop = %d", got)
	}
	if err := q.push(ownerA, make([]byte, 6), time.Unix(4, 0)); err != nil {
		t.Errorf("budget not released by pop: %v", err)
	}
}

func TestQueueFairShare(t *testing.T) {
	stats := &Stats{}
	stats.Connections.Store(2)
	q := newEventQueue(100, 10, stats)
	pushed := 0
	for q.push(ownerA, make([]byte, 10), time.Now()) == nil {
		pushed++
	}
	if pushed != 5 {
		t.Errorf("a flooding sandbox queued %d events, want its share of 5", pushed)
	}
	if err := q.push(ownerA, make([]byte, 10), time.Now()); !errors.Is(err, ErrQueueShare) {
		t.Errorf("over-share push err = %v", err)
	}
	if err := q.push(ownerB, make([]byte, 10), time.Now()); err != nil {
		t.Errorf("a second sandbox was starved by the first: %v", err)
	}
	if err := q.push(statsOwner, make([]byte, 10), time.Now()); err != nil {
		t.Errorf("stats events must only be bounded by the total budget: %v", err)
	}
	if _, err := q.pop(context.Background(), shortWait); err != nil {
		t.Fatal(err)
	}
	if err := q.push(ownerA, make([]byte, 10), time.Now()); err != nil {
		t.Errorf("share not released by pop: %v", err)
	}

	stats.Connections.Store(50)
	small := newEventQueue(100, 30, stats)
	if err := small.push(ownerA, make([]byte, 25), time.Now()); err != nil {
		t.Errorf("minimum share not honoured with many connections: %v", err)
	}
}

func TestQueueFIFOAndWait(t *testing.T) {
	q := newEventQueue(1<<20, 1, &Stats{})
	if _, err := q.pop(context.Background(), shortWait); !errors.Is(err, ErrNoEvent) {
		t.Fatalf("empty pop err = %v", err)
	}
	go func() {
		time.Sleep(shortWait / 2)
		for i := range 3 {
			_ = q.push(ownerA, []byte{byte(i)}, time.Unix(int64(i), 0))
		}
	}()
	for i := range 3 {
		evt, err := q.pop(context.Background(), testWait)
		if err != nil || evt.Data[0] != byte(i) {
			t.Fatalf("pop %d = %v, %v", i, evt.Data, err)
		}
	}
}

func TestQueueCloseAndCancel(t *testing.T) {
	q := newEventQueue(1<<20, 1, &Stats{})
	_ = q.push(ownerA, []byte{1}, time.Now())
	q.close()
	if err := q.push(ownerA, []byte{2}, time.Now()); !errors.Is(err, ErrSourceClosed) {
		t.Errorf("push after close err = %v, want ErrSourceClosed (not a drop)", err)
	}
	if _, err := q.pop(context.Background(), shortWait); err != nil {
		t.Errorf("queued event lost on close: %v", err)
	}
	if _, err := q.pop(context.Background(), testWait); !errors.Is(err, ErrSourceClosed) {
		t.Errorf("pop after drain err = %v", err)
	}

	open := newEventQueue(1<<20, 1, &Stats{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := open.pop(ctx, testWait); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled pop err = %v", err)
	}
}

func TestQueueStaysBoundedWhileNeverEmpty(t *testing.T) {
	const (
		depth  = 64
		rounds = 200 * compactMin
	)
	q := newEventQueue(1<<20, 1, &Stats{})
	for i := range depth {
		if err := q.push(ownerA, make([]byte, 8), time.Unix(int64(i), 0)); err != nil {
			t.Fatal(err)
		}
	}
	for i := range rounds {
		if err := q.push(ownerA, make([]byte, 8), time.Unix(int64(depth+i), 0)); err != nil {
			t.Fatalf("push %d: %v", i, err)
		}
		evt, ok, err := q.tryPop()
		if !ok || err != nil || evt.Time != time.Unix(int64(i), 0) {
			t.Fatalf("pop %d = %v, %v, %v; want FIFO order", i, evt.Time, ok, err)
		}
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if live := len(q.items) - q.head; live != depth {
		t.Errorf("live depth = %d, want %d", live, depth)
	}
	if limit := 4 * (depth + compactMin); cap(q.items) > limit {
		t.Errorf("backing array grew to %d slots for a live depth of %d", cap(q.items), depth)
	}
}
