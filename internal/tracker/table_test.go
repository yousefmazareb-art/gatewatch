package tracker

import (
	"net/netip"
	"testing"
	"time"

	"gatewatch/internal/model"
)

var (
	client = netip.MustParseAddr("203.0.113.7")
	server = netip.MustParseAddr("198.51.100.1")
	t0     = time.Unix(1_700_000_000, 0)
)

func in(syn, ack, rst bool, ts time.Time) *model.Packet {
	return &model.Packet{Ts: ts, Src: client, Dst: server, SrcPort: 40000, DstPort: 443, SYN: syn, ACK: ack, RST: rst}
}
func synAck(ts time.Time) *model.Packet {
	return &model.Packet{Ts: ts, Src: server, Dst: client, SrcPort: 443, DstPort: 40000, SYN: true, ACK: true}
}

func drain(ch chan Event) []Event {
	var out []Event
	for {
		select {
		case e := <-ch:
			out = append(out, e)
		default:
			return out
		}
	}
}

func TestCompletedHandshake(t *testing.T) {
	ch := make(chan Event, 16)
	tb := New([]uint16{443}, 5*time.Second, ch)
	tb.Observe(in(true, false, false, t0))
	tb.Observe(synAck(t0.Add(time.Millisecond)))
	tb.Observe(in(false, true, false, t0.Add(2*time.Millisecond)))
	ev := drain(ch)
	if len(ev) != 1 || ev[0].Kind != HandshakeOK {
		t.Fatalf("want one HandshakeOK, got %+v", ev)
	}
}

func TestHalfOpenExpires(t *testing.T) {
	ch := make(chan Event, 16)
	tb := New([]uint16{443}, 5*time.Second, ch)
	tb.Observe(in(true, false, false, t0))
	tb.Observe(synAck(t0.Add(time.Millisecond))) // server answered, client never ACKs
	tb.Sweep(t0.Add(2 * time.Second))
	if len(drain(ch)) != 0 {
		t.Fatal("expired too early")
	}
	tb.Sweep(t0.Add(6 * time.Second))
	ev := drain(ch)
	if len(ev) != 1 || ev[0].Kind != HalfOpenExpired {
		t.Fatalf("want one HalfOpenExpired, got %+v", ev)
	}
}

func TestResetMidHandshake(t *testing.T) {
	ch := make(chan Event, 16)
	tb := New([]uint16{443}, 5*time.Second, ch)
	tb.Observe(in(true, false, false, t0))
	tb.Observe(synAck(t0.Add(time.Millisecond)))
	tb.Observe(in(false, false, true, t0.Add(2*time.Millisecond))) // classic SYN-scan teardown
	ev := drain(ch)
	if len(ev) != 1 || ev[0].Kind != ResetBeforeEstablish {
		t.Fatalf("want ResetBeforeEstablish, got %+v", ev)
	}
}
