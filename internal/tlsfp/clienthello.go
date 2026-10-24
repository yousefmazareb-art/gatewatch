// Package tlsfp extracts a JA3 fingerprint from a TLS ClientHello IN PLACE.
// Only the derived hash/string leaves this package; the input bytes are never
// stored. Stdlib only, so it is easy to test and audit.
package tlsfp

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

var ErrNotClientHello = errors.New("not a TLS ClientHello")

type Fingerprint struct {
	JA3String string
	JA3       string // md5 of JA3String
	// TODO(JA4): add JA4 (sorted extensions; robust to Chrome extension shuffling).
}

func isGREASE(v uint16) bool { return v&0x0f0f == 0x0a0a && byte(v>>8) == byte(v) }

// ParseJA3 parses a raw TCP payload beginning with a TLS record.
func ParseJA3(b []byte) (Fingerprint, error) {
	var fp Fingerprint
	// Record header: type(1)=0x16 handshake, version(2), length(2)
	// Handshake header: type(1)=0x01, length(3)
	if len(b) < 9 || b[0] != 0x16 || b[5] != 0x01 {
		return fp, ErrNotClientHello
	}
	p := 9
	if len(b) < p+2+32+1 {
		return fp, ErrNotClientHello
	}
	version := binary.BigEndian.Uint16(b[p:])
	p += 2 + 32 // client_version, random
	sidLen := int(b[p])
	p += 1 + sidLen
	if len(b) < p+2 {
		return fp, ErrNotClientHello
	}
	csLen := int(binary.BigEndian.Uint16(b[p:]))
	p += 2
	if csLen%2 != 0 || len(b) < p+csLen+1 {
		return fp, ErrNotClientHello
	}
	var ciphers []string
	for i := 0; i < csLen; i += 2 {
		c := binary.BigEndian.Uint16(b[p+i:])
		if !isGREASE(c) {
			ciphers = append(ciphers, strconv.Itoa(int(c)))
		}
	}
	p += csLen
	compLen := int(b[p])
	p += 1 + compLen
	var exts, curves, points []string
	if len(b) >= p+2 {
		extTotal := int(binary.BigEndian.Uint16(b[p:]))
		p += 2
		end := p + extTotal
		if end > len(b) {
			end = len(b) // may be truncated by snaplen; use what we have
		}
		for p+4 <= end {
			et := binary.BigEndian.Uint16(b[p:])
			el := int(binary.BigEndian.Uint16(b[p+2:]))
			p += 4
			if p+el > end {
				break
			}
			body := b[p : p+el]
			p += el
			if isGREASE(et) {
				continue
			}
			exts = append(exts, strconv.Itoa(int(et)))
			switch et {
			case 10: // supported_groups
				for i := 2; i+1 < len(body); i += 2 {
					g := binary.BigEndian.Uint16(body[i:])
					if !isGREASE(g) {
						curves = append(curves, strconv.Itoa(int(g)))
					}
				}
			case 11: // ec_point_formats
				if len(body) >= 1 {
					for _, f := range body[1:] {
						points = append(points, strconv.Itoa(int(f)))
					}
				}
			}
		}
	}
	fp.JA3String = strings.Join([]string{
		strconv.Itoa(int(version)),
		strings.Join(ciphers, "-"),
		strings.Join(exts, "-"),
		strings.Join(curves, "-"),
		strings.Join(points, "-"),
	}, ",")
	sum := md5.Sum([]byte(fp.JA3String))
	fp.JA3 = hex.EncodeToString(sum[:])
	return fp, nil
}
