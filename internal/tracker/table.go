// Package tracker implements a passive TCP handshake state machine.
// It depends only on internal/model, so it is testable without libpcap.
package tracker

import (
	"hash/fnv"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"gatewatch/internal/model"
)

type State uint8

const (
	SynSeen     State = iota // client SYN observed
	SynAckSeen               // server replied, waiting for client ACK
	Established              // client ACK observed: handshake complete
)

type flowKey struct {
	Client                 netip.Addr
	ClientPort, ServerPort uint16
}

type flow struct {
	state State
	since time.Time
}

type EventKind uint8

const (
	HalfOpenExpired      EventKind = iota // SYN (or SYN-ACK) never completed
	HandshakeOK                           // full 3-way handshake observed
	ResetBeforeEstablish                  // client RST mid-handshake (stealth scan signature)
)

func (k EventKind) String() string {
	switch k {
	case HalfOpenExpired:
		return "half_open"
	case HandshakeOK:
		return "handshake_ok"
	case ResetBeforeEstablish:
		return "reset_before_established"
	}
	return "unknown"
}

type Event struct {
	Kind       EventKind
	Client     netip.Addr
	ServerPort uint16
	At         time.Time
}

const (
	numShards        = 64
	maxFlowsPerShard = 50_000 // SYN-flood protection: never grow unbounded
)

var droppedEvents atomic.Uint64 // exposed via DroppedEvents for dashboard metrics

func DroppedEvents() uint64 { return droppedEvents.Load() }

type shard struct {
	mu    sync.Mutex
	flows map[flowKey]*flow
}

type Table struct {
	shards  [numShards]shard
	served  map[uint16]bool
	timeout time.Duration
	events  chan<- Event
}

func New(servedPorts []uint16, halfOpenTimeout time.Duration, out chan<- Event) *Table {
	t := &Table{served: map[uint16]bool{}, timeout: halfOpenTimeout, events: out}
	for _, p := range servedPorts {
		t.served[p] = true
	}
	for i := range t.shards {
		t.shards[i].flows = make(map[flowKey]*flow, 1024)
	}
	return t
}

func (t *Table) shardFor(a netip.Addr) *shard {
	h := fnv.New32a()
	b := a.As16()
	h.Write(b[:])
	return &t.shards[h.Sum32()%numShards]
}

// Observe is called for every decoded packet (the hot path).
func (t *Table) Observe(p *model.Packet) {
	inbound := t.served[p.DstPort] // client -> server
	outbound := t.served[p.SrcPort]
	switch {
	case inbound && !outbound:
		t.onInbound(p)
	case outbound && !inbound:
		t.onOutbound(p)
	}
}

func (t *Table) onInbound(p *model.Packet) {
	k := flowKey{p.Src, p.SrcPort, p.DstPort}
	s := t.shardFor(p.Src)
	s.mu.Lock()
	defer s.mu.Unlock()

	f := s.flows[k]
	switch {
	case p.SYN && !p.ACK:
		if f == nil && len(s.flows) < maxFlowsPerShard {
			s.flows[k] = &flow{state: SynSeen, since: p.Ts}
		}
	case p.RST && f != nil && f.state != Established:
		delete(s.flows, k)
		t.emit(Event{ResetBeforeEstablish, p.Src, p.DstPort, p.Ts})
	case p.ACK && !p.SYN && f != nil && f.state == SynAckSeen:
		f.state = Established
		f.since = p.Ts // reused as "established at" for cleanup
		t.emit(Event{HandshakeOK, p.Src, p.DstPort, p.Ts})
	}
}

func (t *Table) onOutbound(p *model.Packet) {
	k := flowKey{p.Dst, p.DstPort, p.SrcPort}
	s := t.shardFor(p.Dst)
	s.mu.Lock()
	defer s.mu.Unlock()
	if f := s.flows[k]; f != nil && f.state == SynSeen && p.SYN && p.ACK {
		f.state = SynAckSeen
	}
}

// Sweep expires incomplete handshakes. Call on a ticker (e.g. every second).
func (t *Table) Sweep(now time.Time) {
	for i := range t.shards {
		s := &t.shards[i]
		s.mu.Lock()
		for k, f := range s.flows {
			age := now.Sub(f.since)
			switch {
			case f.state != Established && age > t.timeout:
				delete(s.flows, k)
				t.emit(Event{HalfOpenExpired, k.Client, k.ServerPort, now})
			case f.state == Established && age > 30*time.Second:
				delete(s.flows, k)
			}
		}
		s.mu.Unlock()
	}
}

// emit never blocks the capture path: under pressure we drop events, not packets.
func (t *Table) emit(e Event) {
	select {
	case t.events <- e:
	default:
		droppedEvents.Add(1)
	}
}
