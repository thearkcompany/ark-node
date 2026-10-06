# ADR-0005: Zero-Copy FastHeader Wire Framing

## Context

The ARK protocol defines a 64-byte `FastHeader` strictly aligned to CPU L1 cache boundaries (`#[repr(C, align(64))]`). Network routing daemons and firewall edge filters need to inspect packet magic bytes, versions, length indicators, and truncated identity hashes (`sender_key_id`) at line rate with zero allocation and zero deserialization overhead.

## Decision

On the network wire (UDP/QUIC datagrams), every ARK frame is prefixed with the raw 64-byte `FastHeader` as its first 64 octets, followed immediately by the Protobuf-encoded `ArkEnvelope` payload container:

```
[ 64-Byte Raw FastHeader ] || [ Protobuf Serialized ArkEnvelope Body ]
```

Nodes read the first 64 bytes directly into stack memory via `bytemuck`, validate protocol magic and flags in nanoseconds, and only proceed to invoke Protobuf parsing if the packet passes initial anti-DoS and routing filters.

## Consequences

### Positive
- True zero-copy inline filtering and anti-amplification validation before entering high-cost serialization layers.
- Optimal CPU cache line utilization on modern multi-core architectures.

### Negative / Trade-offs
- Network parsing code must split the incoming byte buffer at offset 64 before feeding the remainder to the Protobuf decoder.
