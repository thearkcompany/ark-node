# ADR-0001: Cryptographic Engine and Post-Quantum Provider Selection

## Context

The ARK protocol mandates quantum-resistant cryptography (ACP-02) utilizing FIPS 203 (ML-KEM-768) for key encapsulation and FIPS 206 (FN-DSA-512 / Falcon) for digital signatures. Furthermore, cross-compilation across diverse target architectures (macOS ARM64, Linux x86_64/ARM64, and WebAssembly) requires a battle-tested, high-performance cryptographic provider that minimizes external system toolchain hurdles.

## Decision

We adopt `aws-lc-rs` (AWS Libcrypto for Rust) as the primary cryptographic foundation for TLS and PQC primitives (including hybrid post-quantum key exchange groups such as X25519MLKEM768), supplemented by dedicated pure-Rust or audited Rust-native implementations for FN-DSA-512 and ML-KEM-768 encapsulation routines inside `ark-crypto`.

## Consequences

### Positive
- High-assurance, FIPS-aligned cryptographic primitives with formal verification backing.
- Native integration with Rustls / Quinn via `rustls::crypto::aws_lc_rs` for post-quantum handshake negotiation.
- Elimination of brittle external C/CMake build configurations on developer workstations.

### Negative / Trade-offs
- Requires managing crate dependencies through `aws-lc-rs` and ensuring compatible toolchain versions.
