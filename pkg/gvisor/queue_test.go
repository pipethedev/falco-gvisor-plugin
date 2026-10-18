package gvisor

import (
	"context"
	"errors"
	"testing"
	"time"
)

const shortWait = 20 * time.Millisecond

func TestQueueByteBudget(t *testing.T) {
	stats := &Stats{}
	q := newEventQueue(10, stats)
	if !q.push(make([]byte, 6), time.Unix(1, 0)) {
		t.Fatal("push within budget rejected")
	}
	if q.push(make([]byte, 5), time.Unix(2, 0)) {
		t.Fatal("push over budget accepted")
	}
	if !q.push(make([]byte, 4), time.Unix(3, 0)) {
		t.Fatal("push filling the budget exactly rejected")
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
	if !q.push(make([]byte, 6), time.Unix(4, 0)) {
		t.Error("budget not released by pop")
	}
}

func TestQueueFIFOAndWait(t *testing.T) {
	q := newEventQueue(1<<20, &Stats{})
	if _, err := q.pop(context.Background(), shortWait); !errors.Is(err, ErrNoEvent) {
		t.Fatalf("empty pop err = %v", err)
	}
	go func() {
		time.Sleep(shortWait / 2)
		for i := range 3 {
			q.push([]byte{byte(i)}, time.Unix(int64(i), 0))
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
	q := newEventQueue(1<<20, &Stats{})
	q.push([]byte{1}, time.Now())
	q.close()
	if q.push([]byte{2}, time.Now()) {
		t.Error("push after close accepted")
	}
	if _, err := q.pop(context.Background(), shortWait); err != nil {
		t.Errorf("queued event lost on close: %v", err)
	}
	if _, err := q.pop(context.Background(), testWait); !errors.Is(err, ErrSourceClosed) {
		t.Errorf("pop after drain err = %v", err)
	}

	open := newEventQueue(1<<20, &Stats{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := open.pop(ctx, testWait); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled pop err = %v", err)
	}
}
