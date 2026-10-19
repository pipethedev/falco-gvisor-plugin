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
// of a container seen for the first time is fetched. The connection keeps
// reading meanwhile, so gVisor's non-blocking writes are never refused.
type metadataHold struct {
	events     []heldEvent
	until      time.Time
	waitingFor string
}

func (h *metadataHold) active() bool {
	return len(h.events) > 0
}

func (s *Server) handlePoint(sc *sandboxConn, table *ProcessTable, point Point) {
	ctx := EventContext{Snapshot: table.Apply(point), Arch: point.Arch}
	containerID := pointContainerID(point)
	isNew := containerID != "" && sc.addContainer(containerID)
	if sc.hold.active() || (isNew && s.metadataWait > 0 && s.resolver.Lookup(containerID) == nil) {
		s.holdEvent(sc, heldEvent{point: point, ctx: ctx, containerID: containerID})
		return
	}
	if containerID != "" {
		ctx.Container = s.resolver.Lookup(containerID)
	}
	s.emitEvent(sc, ctx, point)
}

func (s *Server) holdEvent(sc *sandboxConn, held heldEvent) {
	if !sc.hold.active() {
		sc.hold.until = time.Now().Add(s.metadataWait)
		sc.hold.waitingFor = held.containerID
	}
	held.point.Raw = bytes.Clone(held.point.Raw)
	held.point.header = nil
	sc.hold.events = append(sc.hold.events, held)
	if len(sc.hold.events) >= maxHeldEvents {
		s.flushHold(sc)
	}
}

func (s *Server) holdReady(sc *sandboxConn) bool {
	return time.Now().After(sc.hold.until) || s.resolver.Lookup(sc.hold.waitingFor) != nil
}

func (s *Server) flushHold(sc *sandboxConn) {
	for _, held := range sc.hold.events {
		if held.containerID != "" {
			held.ctx.Container = s.resolver.Lookup(held.containerID)
		}
		s.emitEvent(sc, held.ctx, held.point)
	}
	sc.hold = metadataHold{}
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
