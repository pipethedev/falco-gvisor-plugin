package gvisor

import (
	"bytes"
	"time"
)

const (
	maxHeldEvents    = 4096
	holdPollInterval = 10 * time.Millisecond
)

type heldEvent struct {
	point       Point
	ctx         EventContext
	containerID string
}

// metadataHold buffers a connection's events, in order, while the metadata
// of containers seen for the first time is fetched. The connection keeps
// reading meanwhile, so gVisor's non-blocking writes are never refused.
type metadataHold struct {
	events     []heldEvent
	bytes      int64
	until      time.Time
	waitingFor []string
}

func (h *metadataHold) active() bool {
	return len(h.events) > 0
}

func (s *Server) handlePoint(sc *sandboxConn, table *ProcessTable, point Point) {
	ctx := EventContext{Snapshot: table.Apply(point), Arch: point.Arch}
	containerID := pointContainerID(point)
	isNew := containerID != "" && sc.addContainer(containerID)
	pending := isNew && s.metadataWait > 0 && s.resolver.Lookup(containerID) == nil
	if (sc.hold.active() || pending) && s.holdEvent(sc, heldEvent{point: point, ctx: ctx, containerID: containerID}, pending) {
		return
	}
	if containerID != "" {
		ctx.Container = s.resolver.Lookup(containerID)
	}
	s.emitEvent(sc, ctx, point)
}

// holdEvent adds an event to the connection's hold and reports whether it
// did. The payloads held by all connections together are limited to
// maxHeldBytes; when an event does not fit, the hold is flushed and the
// event is left to be emitted directly, after the events held before it.
func (s *Server) holdEvent(sc *sandboxConn, held heldEvent, pending bool) bool {
	size := int64(len(held.point.Raw))
	if !s.reserveHeld(size) {
		s.flushHold(sc)
		return false
	}
	if !sc.hold.active() {
		sc.hold.until = time.Now().Add(s.metadataWait)
	}
	if pending {
		sc.hold.waitingFor = append(sc.hold.waitingFor, held.containerID)
	}
	held.point.Raw = bytes.Clone(held.point.Raw)
	held.point.header = nil
	sc.hold.events = append(sc.hold.events, held)
	sc.hold.bytes += size
	if len(sc.hold.events) >= maxHeldEvents {
		s.flushHold(sc)
	}
	return true
}

func (s *Server) reserveHeld(size int64) bool {
	for {
		held := s.heldBytes.Load()
		if held+size > s.maxHeldBytes {
			return false
		}
		if s.heldBytes.CompareAndSwap(held, held+size) {
			return true
		}
	}
}

func (s *Server) holdReady(sc *sandboxConn) bool {
	if time.Now().After(sc.hold.until) {
		return true
	}
	for _, id := range sc.hold.waitingFor {
		if s.resolver.Lookup(id) == nil {
			return false
		}
	}
	return true
}

func (s *Server) flushHold(sc *sandboxConn) {
	s.heldBytes.Add(-sc.hold.bytes)
	events := sc.hold.events
	sc.hold = metadataHold{}
	for _, held := range events {
		if held.containerID != "" {
			held.ctx.Container = s.resolver.Lookup(held.containerID)
		}
		s.emitEvent(sc, held.ctx, held.point)
	}
}

// holdDeadline is the read deadline that lets a quiet connection flush its
// hold: the next poll for metadata, but no later than the hold's end.
func (s *Server) holdDeadline(sc *sandboxConn) time.Time {
	poll := time.Now().Add(holdPollInterval)
	if sc.hold.until.Before(poll) {
		return sc.hold.until
	}
	return poll
}
