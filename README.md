# 🛰️ Gatewatch

**Lightweight, privacy-first intrusion detection for your own web server.**
See who is scanning you and which handshakes never finish, without reading user traffic.

> Status: early alpha. Handshake tracking and JA3 parsing exist; JA4, log correlation, store, API and dashboard are on the roadmap.
> Run only on servers you own or are authorized to monitor.

## Why
Wireshark shows everything. Gatewatch watches only the *shape* of traffic: handshakes, timing, TLS fingerprints.
See [docs/PRIVACY.md](docs/PRIVACY.md) for exactly what is and isn't collected.

## Quick start
```bash
make test                # unit tests (no libpcap needed for tracker/tlsfp)
make docker              # or: make build && sudo ./bin/gatewatch -iface eth0
```

## Roadmap
- [x] Half-open / reset-before-established detection
- [x] JA3 ClientHello parsing (in place, nothing stored)
- [ ] JA4, fingerprint database, verified-bot allowlist
- [ ] Access-log correlation (404/403 bursts)
- [ ] SQLite store, REST/SSE API, React dashboard
- [ ] Demo pcap + `make demo`

## License
MIT
