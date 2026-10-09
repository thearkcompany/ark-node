# ADR-0017: Deepened Subsystem Ingress Dispatch & Peripheral Fault Isolation

## Status
Accepted

## Context
ADR-0015 established `ark-runtime` and `EnvelopeDispatcher` as the central orchestration and demultiplexing core for the sovereign node daemon. While the initial runtime implementation successfully bound QUIC listeners under ALPN `ark-pqc/v1` and parsed zero-copy `FastHeader` wire frames into Protobuf `ArkEnvelope` structures, its ingress dispatch pipeline retained critical structural limitations:

1. **Passive and Disconnected Subsystem Ingress**:
   - `KIND_DNS_CLAIM_PUBLIC` (0x3000_0002) envelopes were stored directly or subjected only to read-only DNS queries rather than actively registering public domains through `SovereignDnsEngine::register_public_domain`.
   - Web-of-Trust envelopes (`KIND_WOT_ATTESTATION` 0x000A and `KIND_WOT_REVOCATION` 0x000B) bypassed the `WotEngine` state machine, failing to update the local trust graph or synchronize the internalized CRDT Merkle Search Tree (MST).
   - Inbound VPN frames (`KIND_VPN_DATA` 0x0008 and `KIND_VPN_HANDSHAKE` 0x0009) were not forwarded to `VpnEngine::process_inbound_packet`, leaving the mesh tunnel decoupled from the live network listener.

2. **Storage Pollution via Unvalidated Persistence**:
   - The initial dispatcher wrote envelopes directly into durable storage (`StorageEngine::put_envelope`) prior to or independent of subsystem validation.
   - Envelopes with corrupt or forged cryptographic signatures (e.g. invalid FIPS 206 FN-DSA-512 signatures), mismatched issuer identities, or insufficient anti-Sybil Proof-of-Work (lacking 16 leading zero bits) were persistently committed to Fjall LSM and replicated across the Merkle Search Tree.
   - This violated the core peripheral fault isolation guarantee of ADR-0015: untrusted or malicious wire traffic must never corrupt durable node state or exhaust disk resources.

3. **Loss of Peer Transport Locality for Roaming**:
   - The QUIC connection handler dropped the peer's physical network address (`SocketAddr`) before delegating to `EnvelopeDispatcher`.
   - Consequently, `VpnEngine` could not associate inbound packets with the transmitting socket, preventing seamless endpoint roaming and dynamic routing table updates across client network migrations (such as Wi-Fi to cellular transitions).

## Decision

1. **Active Subsystem Ingress Routing**:
   - Route canonical envelope kinds directly to their corresponding autonomous subsystem engines:
     - `KIND_DNS_CLAIM_PUBLIC` (0x3000_0002) $\to$ `SovereignDnsEngine::register_public_domain(&envelope)`: Evaluates 16-bit anti-Sybil PoW, validates Layer 2 escrow contract tags (`TAG_L2_CONTRACT`), updates the in-memory Patricia Trie, and coordinates domain lease epochs.
     - `KIND_WOT_ATTESTATION` (0x000A) and `KIND_WOT_REVOCATION` (0x000B) $\to$ `WotEngine::ingest_envelope(&envelope)`: Extracts `TAG_WOT_PUBKEY`, verifies `issuer_id == SHA3-256(pubkey)`, validates the FIPS 206 FN-DSA-512 signature over the canonical payload, updates `WotStore` LSM keyspaces and Personalized PageRank (PPR) trust graph, and synchronizes the internalized MST CRDT under namespace `ark/wot/v1`.
     - `KIND_VPN_DATA` (0x0008) and `KIND_VPN_HANDSHAKE` (0x0009) $\to$ `VpnEngine::process_inbound_packet(&envelope.payload, remote_addr)`: Decrypts and unpacks PQMT frames, dynamically updates peer physical endpoint mappings, and injects Layer-3 IP packets into the virtual TUN adapter.

2. **Pre-Persistence Validation & Peripheral Fault Isolation**:
   - Enforce a strict validation-before-persistence barrier across all ingress paths.
   - Subsystem cryptographic verification, anti-Sybil validation, and domain rule checks must succeed before durable persistence:
     - Envelopes that fail subsystem validation (malformed payloads, invalid signatures, mismatched issuer IDs, failed PoW challenges, or missing escrow bonds) are rejected immediately at the boundary.
     - Rejected envelopes are never written to `StorageEngine` and return a failure/NACK indicator, containing the fault strictly within the connection/stream boundary.
     - `StorageEngine::put_envelope` is executed only upon successful subsystem validation for envelopes belonging to persistent retention classes (Classes 1–5).
     - Ephemeral Retention Class 0 envelopes (`KIND_VPN_DATA`, `KIND_VPN_HANDSHAKE`) bypass disk persistence entirely.

3. **Remote Socket Address Propagation (`SocketAddr`)**:
   - Capture the peer's physical network address (`conn.remote_address()`) within the QUIC stream handling loop in `NodeRuntime`.
   - Propagate `remote_addr: Option<SocketAddr>` through the wire demultiplexing seam:
     ```rust
     pub fn process_wire_frame_from(&self, wire_bytes: &[u8], remote_addr: Option<SocketAddr>) -> Result<DispatchOutcome>;
     pub fn dispatch_envelope_from(&self, header: &FastHeader, envelope: &ArkEnvelope, remote_addr: Option<SocketAddr>) -> Result<DispatchOutcome>;
     ```
   - Pass `remote_addr` to `VpnEngine::process_inbound_packet`, enabling dynamic peer endpoint roaming and NAT traversal updates upon receipt of valid, authenticated envelopes.

## Consequences

### Positive
- **Durable State Protection**: Invalid, corrupted, or Sybil spam envelopes are rejected at the edge, guaranteeing that neither Fjall LSM nor CRDT Merkle Search Trees are polluted with unverified state.
- **Deep Subsystem Seams**: Subsystem engines (`WotEngine`, `SovereignDnsEngine`, `VpnEngine`) encapsulate their own domain validation and admission invariants behind cohesive, high-leverage entry points.
- **Dynamic Peer Mobility**: Network address migration (Wi-Fi $\leftrightarrow$ cellular) is supported seamlessly through wire-level socket propagation without manual reconnection ceremonies.
- **Robust Peripheral Fault Isolation**: Stream-level malformed inputs or cryptographic failures emit isolated telemetry and NACKs without crashing the daemon or degrading neighboring subsystem operations.

### Negative / Trade-offs
- **CPU Verification Latency Before Disk I/O**: Performing signature verification and anti-Sybil checks prior to storage writes incurs CPU overhead before admitting envelopes to disk, though constant-time cryptographic primitives and asynchronous processing maintain high throughput.
- **Extended Ingress Signatures**: Wire processing and dispatch interfaces accept an optional socket address parameter, though default adapters maintain convenient parameterless signatures (`remote_addr = None`) for loopback tests and local channels.
