# ark-node

Universal sovereign daemon for the ARK Sovereign P2P Network (Protocol v1).

`ark-node` is a high-performance, post-quantum resilient peer-to-peer node written in Rust. It implements zero-copy wire framing, lattice-based cryptography, strict anti-replay validation, and drift-bounded peer-median temporal consensus.

---

## Key Capabilities

- **Post-Quantum Cryptography (PQC)**: FN-DSA-512 (FIPS 206 / Falcon) constant-time digital signatures and ML-KEM-768 (FIPS 203) key encapsulation.
- **Zero-Copy Wire Framing**: 64-byte `FastHeader` aligned to CPU L1 cache boundaries (`#[repr(C, align(64))]`) for wire-speed parsing and anti-DoS filtering before Protobuf deserialization.
- **Strict Transport Negotiation**: QUIC over dual-stack IPv4/IPv6 with mandatory ALPN `ark-pqc/v1`, KMAC256 stateless retry cookies, and Encrypted Client Hello (ECH) masking.
- **Time Consensus & Anti-Replay**: User-space Peer-Median-Time (PMT) enforcing $\pm 30\text{s}$ drift bounds alongside fixed-memory ($\le 24\text{ MB}$) Dual Cuckoo Filters.
- **Memory Security**: Sensitive private key material locked in RAM (`mlock` via `LockedBuffer<T>`) and zeroized on drop.

---

## Architecture & Crates

```text
                        ┌────────────────────────┐
                        │      ark-node CLI      │
                        │    (crates/ark-cli)    │
                        └───────────┬────────────┘
                                    │
           ┌────────────────────────┼────────────────────────┐
           ▼                        ▼                        ▼
┌────────────────────┐   ┌────────────────────┐   ┌────────────────────┐
│    ark-protocol    │   │   ark-transport    │   │      ark-time      │
│ FastHeader+Envelope│   │  QUIC Dual-Stack   │   │  PMT + Dual Cuckoo │
└──────────┬─────────┘   └──────────┬─────────┘   └──────────┬─────────┘
           │                        │                        │
           └────────────────────────┼────────────────────────┘
                                    ▼
                         ┌────────────────────┐
                         │     ark-crypto     │
                         │ FN-DSA-512 / ML-KEM│
                         └──────────┬─────────┘
                                    ▼
                         ┌────────────────────┐
                         │      ark-core      │
                         │ Types & Constants  │
                         └────────────────────┘
```

| Crate | Purpose |
|---|---|
| [`ark-core`](crates/ark-core) | Core traits, error primitives, constants (Magic `0x41524B31`, Safe MTU 1280B), and 64-byte `FastHeader`. |
| [`ark-crypto`](crates/ark-crypto) | FN-DSA-512, ML-KEM-768, KMAC256 (`ARK-KMAC256-V1`), and `PersistentIdentity` management. |
| [`ark-protocol`](crates/ark-protocol) | `ArkEnvelope` container, Protobuf wire serialization, and CoreTagMask handling. |
| [`ark-transport`](crates/ark-transport) | QUIC dual-stack UDP socket runtime, strict ALPN enforcement, and stateless retry cookies. |
| [`ark-time`](crates/ark-time) | Peer-Median-Time clock drift evaluator and Dual Cuckoo Filter anti-replay engine. |
| [`ark-cli`](crates/ark-cli) | Unified CLI subcommands (`keygen`, `status`, `ping`) and runtime flag resolution. |

---

## Quickstart

### Prerequisites

- Rust toolchain (`rust-toolchain.toml`, Rust 1.80+ / 2021 edition)
- Protobuf compiler (`protoc`)

### Building

```bash
cargo build --workspace
```

### Running the Node

Start the daemon with default role (server) binding to `0.0.0.0:8443`:

```bash
cargo run --bin ark-node
```

Run with an explicit role and custom bind address:

```bash
cargo run --bin ark-node -- --role server --bind 0.0.0.0:8443
```

---

## CLI Usage

### Generate Node Identity

Generate a fresh FN-DSA-512 and ML-KEM-768 keypair and persist it with strict `0600` permissions:

```bash
cargo run --bin ark-node -- keygen --out ~/.ark/identity.key
```

### Check Node Status

Inspect protocol magic bytes, MTU ceilings, and ALPN identifiers:

```bash
cargo run --bin ark-node -- status
```

### Ping a Peer

Perform a diagnostic probe to a remote peer enforcing ALPN `ark-pqc/v1`:

```bash
cargo run --bin ark-node -- ping --target 127.0.0.1:8443
```

### Identity Resolution Precedence

When running the daemon without subcommands, identity key material resolves in the following order:

1. CLI flag: `--identity <PATH>`
2. Environment variable: `ARK_IDENTITY_KEY=<PATH>`
3. Default path: `~/.ark/identity.key`
4. Fallback: Ephemeral in-memory keypair (non-persisted, ideal for test environments)

---

## Testing

Run the full workspace unit tests:

```bash
cargo test --workspace
```

Run end-to-end integration tests:

```bash
cargo test --test e2e_node
```

---

## Documentation & Standards

- [Glossary](GLOSSARY.md): Canonical protocol definitions (`ArkID`, `FastHeader`, `ALPN`, `Safe MTU`).
- [Architecture Decision Records (ADRs)](docs/adr/):
  - [ADR-0001: Cryptographic Engine & PQC Selection](docs/adr/0001-cryptographic-engine-and-pqc-selection.md)
  - [ADR-0002: Hermetic Protobuf Schema Generation](docs/adr/0002-hermetic-protobuf-schema-generation.md)
  - [ADR-0003: Anti-Replay Saturation Policy](docs/adr/0003-anti-replay-saturation-policy.md)
  - [ADR-0004: Post-Quantum Security Architecture for QUIC](docs/adr/0004-post-quantum-security-architecture-for-quic-and-envelopes.md)
  - [ADR-0005: Zero-Copy FastHeader Wire Framing](docs/adr/0005-zero-copy-fastheader-wire-framing.md)
  - [ADR-0006: Node Identity Management Policy](docs/adr/0006-node-identity-management-and-key-storage-policy.md)
  - [ADR-0007: End-to-End Integration Test Suite](docs/adr/0007-end-to-end-integration-test-suite.md)
- [Agent Guidelines](AGENTS.md): Conventions and triage workflows for automated agents.

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
