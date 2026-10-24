package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"gatewatch/internal/capture"
	"gatewatch/internal/classify"
	"gatewatch/internal/model"
	"gatewatch/internal/tlsfp"
	"gatewatch/internal/tracker"
)

func parsePorts(s string) []uint16 {
	var out []uint16
	for _, f := range strings.Split(s, ",") {
		n, err := strconv.ParseUint(strings.TrimSpace(f), 10, 16)
		if err != nil {
			log.Fatalf("bad port %q: %v", f, err)
		}
		out = append(out, uint16(n))
	}
	return out
}

func main() {
	iface := flag.String("iface", "eth0", "network interface to monitor")
	ports := flag.String("ports", "80,443", "served TCP ports")
	tlsPorts := flag.String("tls-ports", "443", "ports to fingerprint (ClientHello only)")
	timeout := flag.Duration("half-open-timeout", 5*time.Second, "time before an unfinished handshake counts as half-open")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	events := make(chan tracker.Event, 8192)
	tbl := tracker.New(parsePorts(*ports), *timeout, events)

	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case now := <-t.C:
				tbl.Sweep(now)
			case <-ctx.Done():
				return
			}
		}
	}()
	go classify.Run(ctx, events)

	log.Printf("gatewatch watching %s ports=%s (headers only; payload never stored)", *iface, *ports)
	err := capture.Run(ctx, capture.Config{
		Iface: *iface, Ports: parsePorts(*ports), TLSPorts: parsePorts(*tlsPorts), SnapLen: 1600,
	}, func(p *model.Packet) {
		tbl.Observe(p)
		if p.FirstData != nil {
			if fp, err := tlsfp.ParseJA3(p.FirstData); err == nil {
				log.Printf("ja3 %s from %s", fp.JA3, p.Src) // TODO: feed classifier + store
			}
		}
	})
	if err != nil {
		log.Fatal(err)
	}
}
