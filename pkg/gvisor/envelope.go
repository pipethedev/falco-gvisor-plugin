package gvisor

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
)

const (
	envelopeMagic   = "GVP1"
	statsMagic      = "GVS1"
	envelopeLenSize = 4
	envelopeHdrSize = len(envelopeMagic) + envelopeLenSize
	maxContextBytes = 32 << 10
)

var (
	errNotEnvelope     = errors.New("not a gvisor plugin event")
	errContextTooLarge = errors.New("event context exceeds size cap")
)

// EventContext is the enrichment stored in front of each gVisor packet.
type EventContext struct {
	Snapshot
	Container *ContainerInfo `json:"ctr,omitempty"`
}

// Event is a decoded plugin event: either enrichment plus the original
// point, or a stats event when Stats is set.
type Event struct {
	Context EventContext
	Point   Point
	Stats   *StatsSnapshot
}

// EncodeStats builds the payload of a gvisor_stats event.
func EncodeStats(snap StatsSnapshot) ([]byte, error) {
	encoded, err := json.Marshal(snap)
	if err != nil {
		return nil, fmt.Errorf("encode stats: %w", err)
	}
	return append([]byte(statsMagic), encoded...), nil
}

// EncodeEvent builds the opaque plugin event payload
// magic | u32 context length | context JSON | original gVisor packet.
func EncodeEvent(ctx EventContext, packet []byte) ([]byte, error) {
	encoded, err := encodeContext(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, envelopeHdrSize+len(encoded)+len(packet))
	out = append(out, envelopeMagic...)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(encoded)))
	out = append(out, encoded...)
	return append(out, packet...), nil
}

// DecodeEvent parses a payload produced by EncodeEvent or EncodeStats.
func DecodeEvent(data []byte) (Event, error) {
	if len(data) >= len(statsMagic) && string(data[:len(statsMagic)]) == statsMagic {
		var snap StatsSnapshot
		if err := json.Unmarshal(data[len(statsMagic):], &snap); err != nil {
			return Event{}, fmt.Errorf("decode stats: %w", err)
		}
		return Event{Stats: &snap}, nil
	}
	if len(data) < envelopeHdrSize || string(data[:len(envelopeMagic)]) != envelopeMagic {
		return Event{}, errNotEnvelope
	}
	ctxLen := int(binary.LittleEndian.Uint32(data[len(envelopeMagic):envelopeHdrSize]))
	if ctxLen > len(data)-envelopeHdrSize {
		return Event{}, fmt.Errorf("%w: context length %d out of range", errNotEnvelope, ctxLen)
	}
	body := data[envelopeHdrSize:]
	var ctx EventContext
	if err := json.Unmarshal(body[:ctxLen], &ctx); err != nil {
		return Event{}, fmt.Errorf("decode event context: %w", err)
	}
	point, err := DecodePoint(body[ctxLen:])
	if err != nil {
		return Event{}, err
	}
	return Event{Context: ctx, Point: point}, nil
}

func encodeContext(ctx EventContext) ([]byte, error) {
	reducers := []func(*EventContext) bool{
		dropAncestorArgv,
		dropFarthestAncestor,
		dropContainerLabels,
		dropProcessArgv,
	}
	for {
		encoded, err := json.Marshal(ctx)
		if err != nil {
			return nil, fmt.Errorf("encode event context: %w", err)
		}
		if len(encoded) <= maxContextBytes {
			return encoded, nil
		}
		if !reduceOnce(&ctx, reducers) {
			return nil, fmt.Errorf("%w: %d bytes", errContextTooLarge, len(encoded))
		}
	}
}

func reduceOnce(ctx *EventContext, reducers []func(*EventContext) bool) bool {
	for _, reduce := range reducers {
		if reduce(ctx) {
			return true
		}
	}
	return false
}

func dropAncestorArgv(ctx *EventContext) bool {
	changed := false
	ancestors := make([]ProcessInfo, len(ctx.Ancestors))
	for i, a := range ctx.Ancestors {
		if a.Argv != nil {
			a.Argv = nil
			changed = true
		}
		ancestors[i] = a
	}
	ctx.Ancestors = ancestors
	return changed
}

func dropFarthestAncestor(ctx *EventContext) bool {
	if len(ctx.Ancestors) == 0 {
		return false
	}
	ctx.Ancestors = ctx.Ancestors[:len(ctx.Ancestors)-1]
	return true
}

func dropContainerLabels(ctx *EventContext) bool {
	if ctx.Container == nil || (ctx.Container.Labels == nil && ctx.Container.PodLabels == nil) {
		return false
	}
	trimmed := *ctx.Container
	trimmed.Labels = nil
	trimmed.PodLabels = nil
	ctx.Container = &trimmed
	return true
}

func dropProcessArgv(ctx *EventContext) bool {
	if len(ctx.Process.Argv) <= 1 {
		return false
	}
	ctx.Process.Argv = ctx.Process.Argv[:1]
	return true
}
