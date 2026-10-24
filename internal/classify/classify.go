// Package classify turns raw events into per-source severity.
// A deliberately simple, transparent baseline: weighted rules.
package classify

import (
	"context"
	"log"
	"net/netip"
	"time"

	"gatewatch/internal/tracker"
)

type Severity string

const (
	Low    Severity = "LOW"
	Medium Severity = "MEDIUM"
	High   Severity = "HIGH"
)

type window struct {
	ok, halfOpen, resets int
	ports                map[uint16]struct{}
	start                time.Time
}

// Score is the heuristic severity matrix. Weights will move into config.
func Score(w *window) (int, Severity) {
	total := w.ok + w.halfOpen + w.resets
	if total < 5 {
		return 0, Low
	}
	score := 0
	if float64(w.halfOpen+w.resets)/float64(total) > 0.5 {
		score += 40
	}
	if len(w.ports) >= 5 {
		score += 30
	}
	if w.halfOpen+w.resets >= 50 {
		score += 20
	}
	switch {
	case score >= 60:
		return score, High
	case score >= 30:
		return score, Medium
	}
	return score, Low
}

// Run consumes tracker events.
// TODO: join with access-log status codes, fingerprints, and the verified-bot
// allowlist before scoring.
func Run(ctx context.Context, events <-chan tracker.Event) {
	wins := map[netip.Addr]*window{}
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-events:
			w := wins[e.Client]
			if w == nil || e.At.Sub(w.start) > time.Minute {
				w = &window{start: e.At, ports: map[uint16]struct{}{}}
				wins[e.Client] = w
			}
			switch e.Kind {
			case tracker.HandshakeOK:
				w.ok++
			case tracker.HalfOpenExpired:
				w.halfOpen++
			case tracker.ResetBeforeEstablish:
				w.resets++
			}
			w.ports[e.ServerPort] = struct{}{}
		case now := <-tick.C:
			for ip, w := range wins {
				if now.Sub(w.start) > time.Minute {
					delete(wins, ip)
					continue
				}
				if s, sev := Score(w); sev != Low {
					log.Printf("[%s] %s score=%d ok=%d half_open=%d resets=%d ports=%d",
						sev, ip, s, w.ok, w.halfOpen, w.resets, len(w.ports))
				}
			}
		}
	}
}
