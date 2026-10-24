# Privacy

**Collected:** timestamps, IP addresses, TCP ports, TCP flags, handshake completion state,
TLS ClientHello-derived fingerprints (JA3/JA4), and (planned) web-server status codes from your own access logs.

**Never collected or stored:** request/response bodies, cookies, headers, query strings,
or any application data. After the TLS handshake begins, traffic is encrypted and Gatewatch ignores it.

**The one payload touch:** the first client segment of a TLS connection (the unencrypted ClientHello)
is parsed in memory to compute a fingerprint. Only the fingerprint is kept; the bytes are discarded
immediately. See `internal/tlsfp` and `internal/capture` to audit this.
