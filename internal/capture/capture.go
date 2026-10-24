package capture

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"gatewatch/internal/model"
)

type Config struct {
	Iface    string
	Ports    []uint16 // served ports, e.g. 80, 443
	TLSPorts []uint16 // subset of Ports where we fingerprint ClientHello
	SnapLen  int32    // ~1600 is enough to see a ClientHello; payload is never stored
}

type Handler func(p *model.Packet)

// Run captures until ctx is cancelled. Needs CAP_NET_RAW (or root).
func Run(ctx context.Context, cfg Config, h Handler) error {
	handle, err := pcap.OpenLive(cfg.Iface, cfg.SnapLen, false, 500*time.Millisecond)
	if err != nil {
		return fmt.Errorf("open %s (need CAP_NET_RAW?): %w", cfg.Iface, err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter(buildBPF(cfg.Ports)); err != nil {
		return err
	}

	var (
		eth     layers.Ethernet
		ip4     layers.IPv4
		ip6     layers.IPv6
		tcp     layers.TCP
		decoded []gopacket.LayerType
	)
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp)
	parser.IgnoreUnsupported = true

	tlsPorts := toSet(cfg.TLSPorts)
	gate := newFirstDataGate()

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	src.NoCopy = true // avoid allocations on the hot path

	for {
		select {
		case <-ctx.Done():
			return nil
		case pkt, ok := <-src.Packets():
			if !ok {
				return nil
			}
			if err := parser.DecodeLayers(pkt.Data(), &decoded); err != nil && len(decoded) == 0 {
				continue
			}
			var p model.Packet
			p.Ts = pkt.Metadata().Timestamp
			for _, lt := range decoded {
				switch lt {
				case layers.LayerTypeIPv4:
					p.Src, _ = netip.AddrFromSlice(ip4.SrcIP)
					p.Dst, _ = netip.AddrFromSlice(ip4.DstIP)
				case layers.LayerTypeIPv6:
					p.Src, _ = netip.AddrFromSlice(ip6.SrcIP)
					p.Dst, _ = netip.AddrFromSlice(ip6.DstIP)
				case layers.LayerTypeTCP:
					p.SrcPort, p.DstPort = uint16(tcp.SrcPort), uint16(tcp.DstPort)
					p.SYN, p.ACK, p.RST, p.FIN = tcp.SYN, tcp.ACK, tcp.RST, tcp.FIN
					p.PayloadLen = len(tcp.Payload)
					if p.PayloadLen > 0 && tlsPorts[p.DstPort] &&
						gate.first(p.Src, p.SrcPort, p.DstPort, p.Ts) {
						p.FirstData = tcp.Payload // borrowed view, not copied
					}
				}
			}
			if p.SrcPort != 0 {
				h(&p)
			}
			p.FirstData = nil // nothing retains payload past this point
		}
	}
}

func buildBPF(ports []uint16) string {
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = fmt.Sprintf("port %d", p)
	}
	return "tcp and (" + strings.Join(parts, " or ") + ")"
}

func toSet(ps []uint16) map[uint16]bool {
	m := make(map[uint16]bool, len(ps))
	for _, p := range ps {
		m[p] = true
	}
	return m
}

// firstDataGate remembers which flows we've already offered payload from, so
// only the first data segment (the ClientHello) is ever exposed to the parser.
type firstDataGate struct {
	mu    sync.Mutex
	seen  map[gateKey]time.Time
	clean time.Time
}

type gateKey struct {
	ip         netip.Addr
	srcP, dstP uint16
}

func newFirstDataGate() *firstDataGate {
	return &firstDataGate{seen: make(map[gateKey]time.Time, 4096)}
}

func (g *firstDataGate) first(ip netip.Addr, sp, dp uint16, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if now.Sub(g.clean) > 10*time.Second { // lazy TTL sweep
		for k, t := range g.seen {
			if now.Sub(t) > 60*time.Second {
				delete(g.seen, k)
			}
		}
		g.clean = now
	}
	k := gateKey{ip, sp, dp}
	if _, ok := g.seen[k]; ok {
		return false
	}
	if len(g.seen) < 200_000 { // hard cap: SYN-flood safety
		g.seen[k] = now
	}
	return true
}
