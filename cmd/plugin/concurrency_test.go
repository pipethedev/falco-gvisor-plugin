package main

import (
	"bytes"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"unsafe"

	"github.com/falcosecurity/plugins/plugins/gvisor/pkg/gvisor"
	"google.golang.org/protobuf/proto"
	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
	"gvisor.dev/gvisor/pkg/sentry/seccheck/sinks/remote/wire"
)

type fakeEvent struct {
	num  uint64
	data []byte
}

func (e fakeEvent) EventNum() uint64      { return e.num }
func (e fakeEvent) Timestamp() uint64     { return 0 }
func (e fakeEvent) Reader() io.ReadSeeker { return bytes.NewReader(e.data) }

type fakeRequest struct {
	field string
	value any
}

func (r *fakeRequest) FieldID() uint64                   { return 0 }
func (r *fakeRequest) FieldType() uint32                 { return 0 }
func (r *fakeRequest) Field() string                     { return r.field }
func (r *fakeRequest) ArgKey() string                    { return "" }
func (r *fakeRequest) ArgIndex() uint64                  { return 0 }
func (r *fakeRequest) ArgPresent() bool                  { return false }
func (r *fakeRequest) IsList() bool                      { return false }
func (r *fakeRequest) SetValue(v any)                    { r.value = v }
func (r *fakeRequest) SetValueOffset(uint32, uint32)     {}
func (r *fakeRequest) SetPtr(unsafe.Pointer)             {}
func (r *fakeRequest) SetOffsetPtrs(_, _ unsafe.Pointer) {}
func (r *fakeRequest) WantOffset() bool                  { return false }

func connectEvent(t *testing.T, num uint64, comm string, ip net.IP) fakeEvent {
	t.Helper()
	payload, err := proto.Marshal(&pb.Connect{
		ContextData: &pb.ContextData{ThreadGroupId: int32(num), ProcessName: comm, ContainerId: "c0ffee"},
		Exit:        &pb.Exit{},
		Address:     append([]byte{2, 0, 0, 80}, ip.To4()...),
	})
	if err != nil {
		t.Fatal(err)
	}
	hdr := wire.Header{HeaderSize: wire.HeaderStructSize, MessageType: uint16(pb.MessageType_MESSAGE_SYSCALL_CONNECT)}
	pkt := make([]byte, wire.HeaderStructSize)
	hdr.MarshalBytes(pkt)
	ctx := gvisor.EventContext{Snapshot: gvisor.Snapshot{Process: gvisor.ProcessInfo{Pid: int32(num), Comm: comm}}}
	data, err := gvisor.EncodeEvent(ctx, append(pkt, payload...))
	if err != nil {
		t.Fatal(err)
	}
	return fakeEvent{num: num, data: data}
}

func TestConcurrentExtractAndString(t *testing.T) {
	p := &gvisorPlugin{}
	if err := p.Init(""); err != nil {
		t.Fatal(err)
	}
	events := []fakeEvent{
		connectEvent(t, 1, "alpha", net.IPv4(10, 0, 0, 1)),
		connectEvent(t, 2, "bravo", net.IPv4(10, 0, 0, 2)),
		connectEvent(t, 3, "charlie", net.IPv4(10, 0, 0, 3)),
	}
	want := map[uint64]string{1: "alpha", 2: "bravo", 3: "charlie"}

	var wg sync.WaitGroup
	for w := range 8 {
		wg.Go(func() {
			for i := range 300 {
				evt := events[(i+w)%len(events)]
				name := &fakeRequest{field: "proc.name"}
				if err := p.Extract(name, evt); err != nil || name.value != want[evt.num] {
					t.Errorf("event %d: proc.name = %v (%v)", evt.num, name.value, err)
					return
				}
				rip := &fakeRequest{field: "fd.rip"}
				if err := p.Extract(rip, evt); err != nil || !rip.value.(net.IP).Equal(net.IPv4(10, 0, 0, byte(evt.num))) {
					t.Errorf("event %d: fd.rip = %v (%v)", evt.num, rip.value, err)
					return
				}
				s, err := p.String(evt)
				if err != nil || !strings.Contains(s, "proc="+want[evt.num]) {
					t.Errorf("event %d: String = %q (%v)", evt.num, s, err)
					return
				}
			}
		})
	}
	wg.Wait()
}
