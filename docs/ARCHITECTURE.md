# Architecture

capture (headers only) -> tracker (handshake state machine) -> classifier (severity) -> store / API / dashboard
TLS ClientHello -> tlsfp (JA3 now, JA4 next) -> classifier
Access logs (planned) -> classifier

Packages depend only on `internal/model`, which keeps each stage testable without libpcap.
