# ADR-0015: Unified NodeRuntime Daemon & Inbound Envelope Dispatcher

## Status
Accepted

## Context
With the independent implementation and verification of ARK's modular subsystem engines—`ark-storage` (embedded Fjall LSM with GCP-06 retention classes), `ark-crdt` (Merkle Search Tree distributed KV anti-entropy), `ark-dns` (sovereign radix tree DNS engine & anti-Sybil registrations), `ark-blob` (Cauchy Reed-Solomon sharded distributed blob store with Proof-of-Retrievability), `ark-paas` (sandboxed WebAssembly worker execution pool & dual-pool fuel accounting), `ark-vpn` (PQMT post-quantum mesh tunnel and zero-trust ACL), and `ark-wot` (subjective Web-of-Trust Sybil resistance and reputation)—the top-level `ark-node` binary and `ark-cli` entrypoints remained thin, disconnected shells.

Callers could not run an integrated daemon process that binds a live QUIC listener under ALPN `ark-pqc/v1`, validates zero-copy `FastHeader` frames, deserializes Protobuf `ArkEnvelope` messages, and routes them to subsystem engines based on envelope `kind` and tag masks. Integration tests were forced to manually instantiate individual subsystems rather than exercising the true public seam of the complete sovereign node.

## Decision

1. **Deep Crate Separation (`crates/ark-runtime`)**:
   - Establish a dedicated workspace crate, `crates/ark-runtime`, encapsulating runtime orchestration, network demultiplexing, subsystem dispatch, and lifecycle supervision.
   - Decouple `ark-cli` completely: the CLI and `src/main.rs` become thin argument parsers that delegate daemon lifecycle execution entirely to `NodeRuntimeBuilder` and `NodeHandle`.

2. **Unified Facade Interface (`NodeRuntimeBuilder` and `NodeHandle`)**:
   - `NodeRuntimeBuilder` configures node identity (`Keypair`), listening socket address, node role (`Role::Server`, `Role::Client`, `Role::Relay`, `Role::Bootstrap`), storage directories, and optional subsystem feature toggles.
   - `NodeRuntimeBuilder::spawn(self) -> Result<NodeHandle>` launches the daemon background tasks and returns an asynchronous control handle.
   - `NodeHandle` exposes a clean, minimal public surface:
     - `local_addr(&self) -> SocketAddr`: Bound network socket address (essential for ephemeral localhost integration tests).
     - `status(&self) -> NodeRuntimeStatus`: Current lifecycle state (`Starting`, `Running`, `Draining`, `Stopped`).
     - `shutdown(self) -> Result<()>`: Asynchronously triggers orderly daemon termination, drains active streams, and flushes persistent state.

3. **Lifecycle Supervision & Task Cancellation**:
   - Daemon background tasks (QUIC accept loop, connection handlers, storage background sweepers, PaaS cron/queue runners, WoT cache refreshers) are bound to a root `tokio_util::sync::CancellationToken` and tracked within a `tokio::task::JoinSet`.
   - On `shutdown()`, the token is cancelled, the QUIC endpoint stops accepting incoming connections, active streams are given a grace period to drain, and all tasks in the `JoinSet` are awaited to completion, guaranteeing zero task or socket leakage.
   - LSM keyspaces in `ark-storage` are flushed safely to disk before exit.

4. **Zero-Copy Wire Demux & Inbound Envelope Dispatcher**:
   - Inbound QUIC datagrams and streams are framed using 64-byte `FastHeader` prefix validation before full Protobuf `ArkEnvelope` deserialization (`ark_protocol::wire::WireFrame`).
   - The `EnvelopeDispatcher` inspects the numeric `kind` field and core tag masks, routing envelopes to registered engines:
     - `KIND_KV_MST_SYNC` (0x0006) $\to$ `MstEngine` for CRDT anti-entropy state synchronization.
     - `KIND_DNS_*` (`KIND_DNS_CLAIM_PUBLIC` 0x3000_0002, etc.) $\to$ `SovereignDnsEngine`.
     - `KIND_BLOB_*` (`KIND_BLOB_MANIFEST` 0x1000_0003, `KIND_HOMELAB_ACK` 0x0000_2011, `KIND_DEPIN_CHALLENGE` 0x4000_0002, `KIND_DEPIN_RESPONSE` 0x4000_0003) $\to$ `BlobEngine`.
     - `KIND_PAAS_*` $\to$ `PaasEngine` (`Trigger::EnvelopeReceived`).
     - `KIND_VPN_*` (`KIND_VPN_DATA` 0x0008, `KIND_VPN_HANDSHAKE` 0x0009) $\to$ `VpnEngine` / TUN interface.
     - `KIND_WOT_*` (`KIND_WOT_ATTESTATION` 0x000A, `KIND_WOT_REVOCATION` 0x000B) $\to$ `WotEngine`.
     - General storage envelopes (Retention Classes 1, 2, 3, 4, 5) $\to$ `StorageEngine`.

5. **Role-Based Configuration Matrix**:
   - `Role::Server`: Full sovereign peer node enabling storage engine, CRDT MST sync, DNS engine, and WoT evaluation by default.
   - `Role::Relay`: Lightweight transit node prioritizing FastHeader routing, zero-copy packet forwarding, and bounded storage cache.
   - `Role::Client`: Minimal resource footprint; spins up client QUIC connection pooling, local identity, and on-demand VPN/PaaS workers without running full public DNS/storage services.
   - `Role::Bootstrap`: Specialized discovery and seed relay node.

6. **Hierarchical Fault Isolation**:
   - **Critical Failures** (e.g. fatal QUIC socket binding failure, unrecoverable LSM storage corruption): Trigger orderly node termination returning a descriptive error.
   - **Peripheral Failures** (e.g. unparsable DNS queries, untrusted or malformed WoT signatures, failed PoR challenges, untrusted PaaS worker exceptions/traps): Contained strictly at the connection or request task boundary. They emit structured tracing telemetry and do not crash the daemon or affect other subsystem engines.

## Consequences

### Positive
- Unified runtime seam: Integration tests can spin up 2+ full sovereign nodes in-process on localhost ephemeral ports, communicating over real QUIC and wire framing.
- Decoupled CLI: The binary CLI remains purely responsible for flag parsing, env configuration, and signal handling.
- Deterministic routing: Protocol envelopes are dispatched to subsystems with clean separation of concerns and robust error containment.

### Negative / Trade-offs
- Integration crate dependency footprint: `ark-runtime` brings together storage, transport, protocol, crypto, and all subsystem crates. Workspace build dependencies must be carefully managed.
