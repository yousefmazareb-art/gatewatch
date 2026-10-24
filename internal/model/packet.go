// Package model holds the tiny types shared between pipeline stages.
// It has no third-party dependencies so every stage is easy to unit test.
package model

import (
	"net/netip"
	"time"
)

// Packet is the only thing that leaves the capture layer: headers, never payload.
type Packet struct {
	Ts                 time.Time
	Src, Dst           netip.Addr
	SrcPort, DstPort   uint16
	SYN, ACK, RST, FIN bool
	PayloadLen         int

	// FirstData is non-nil ONLY for the first client data segment on a TLS port
	// and is valid only for the duration of the handler call. Consumers must
	// parse in place and must not retain or copy it.
	FirstData []byte
}
