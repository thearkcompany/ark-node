# ADR-0004: Post-Quantum Security Architecture for QUIC and Application Envelopes

## Context

Total quantum-resistance requires protecting both the application payload and the underlying transit metadata against "harvest now, decrypt later" adversary models. In traditional QUIC connections using standard TLS 1.3 key exchange (such as X25519 or ECDSA), transit metadata is exposed to future cryptanalytic attacks even if application payloads are independently encrypted.

## Decision

We adopt a two-phase architecture:
1. **Short-Term (v0.1 Prototype)**: Defend the transport boundary using strict ALPN `ark-pqc/v1` over standard Quinn/Rustls, while implementing end-to-end post-quantum security (FN-DSA-512 signatures and ML-KEM-768 key encapsulation) directly inside the `ArkEnvelope` payload container. This accelerates core daemon scaffolding without requiring early forks of QUIC internals.
2. **Protocol Production Target**: Upgrade QUIC handshake cryptography to hybrid post-quantum key exchange (X25519MLKEM768 or pure ML-KEM-768) powered by `aws-lc-rs` within Rustls, ensuring that both transit metadata and application data achieve full quantum immunity.

## Consequences

### Positive
- v0.1 delivers operational nodes rapidly while maintaining cryptographically verified post-quantum payload integrity.
- Clear migration path to native TLS 1.3 PQC handshakes using `aws-lc-rs` without breaking envelope serialization format.

### Negative / Trade-offs
- In v0.1, transport metadata in transit relies on classical TLS 1.3 forward secrecy, whereas payload data is quantum-immune. Full metadata immunity activates upon final QUIC PQC key exchange integration.
