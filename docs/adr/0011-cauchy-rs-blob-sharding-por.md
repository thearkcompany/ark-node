# ADR-0011: Cauchy Reed-Solomon Blob Sharding & Merkle Proof-of-Retrievability (GCP-10)

## Context

Under the ARK 2026-LTS architectural mandate (GCP-10, ACP-0010), the ARK Sovereign P2P network requires a distributed, erasure-coded storage and retrieval engine (`ark-blob`) for bulk payloads exceeding the canonical $64\text{ KB}$ `ArkEnvelope` ceiling.

In decentralized and mobile peer-to-peer networks, traditional whole-file replication suffers from massive storage overhead, while naive striping is brittle under churn. Furthermore, mobile-first uploads present severe durability risks: if a mobile client disconnects or suffers hardware failure before its home server synchronizes the payload, data is permanently lost.

The `ark-node` requires an embedded bulk storage subsystem delivering mathematically guaranteed reconstruction under peer failures, bounded RAM footprint ($\le 65\text{ MB}$), two-tier Merkle cryptographic integrity, economic sustainability via Layer 2 sponsorship, and client-side data loss prevention through *Safe-Ghost Locking*.

## Decision

We establish the `ark-blob` subsystem implementing GCP-10 and ACP-0010 according to the following architectural decisions:

1. **Cauchy Reed-Solomon Erasure Coding in $GF(2^8)$:**
   Bulk payloads ($>64\text{ KB}$) are partitioned into standard $1\text{ MB}$ ($1,048,576\text{ bytes}$) shards using a canonical Cauchy dispersion matrix with ratio $10 + 4$:
   - $k = 10$ data shards.
   - $m = 4$ parity shards (total 14 shards).
   - Reconstitution is mathematically guaranteed from **any 10 distinct shards** among the 14 total.
   - Erasure coding operations leverage pure Rust SIMD acceleration (AVX2/NEON) wrapped in a deterministic `CauchyReedSolomon` primitive with zero unnecessary allocations.

2. **Two-Tier Merkle Tree & Canonical Blob CID:**
   Cryptographic identity and proof generation are structured in two tiers:
   - **File-Level Sub-Chunk Tree:** Pre-erasure payload is divided into $64\text{ KB}$ sub-chunks to compute a deterministic pre-coding integrity digest.
   - **Shard-Level Merkle Tree:** A Merkle tree of 14 leaves where each leaf is the SHA3-256 digest of a $1\text{ MB}$ shard. The Merkle root forms the canonical `BlobCID` carried in `TAG_CONTENT_CID` (`0x0002`). This allows remote nodes to generate and verify compact $O(\log 14)$ Merkle inclusion proofs for individual shards without accessing the full file.

3. **Hybrid Content-Addressed Storage (CAS FS + Fjall LSM):**
   To respect the node's strict $\le 65\text{ MB}$ RAM budget and prevent LSM write amplification:
   - Manifest metadata (`KIND_BLOB_MANIFEST`, `0x1000_0003`, Retention Class 1) and shard index records are indexed in `ark-storage` (Fjall LSM).
   - Heavy $1\text{ MB}$ shard payloads are stored directly in a dedicated content-addressed filesystem store (`.ark/blobs/<shard_hash>`) with atomic temporary writes and `fsync`.

4. **Staged Full Custody Lifecycle for Files $< 25\text{ MB}$:**
   To solve durability fragility in client-first mobile uploads:
   - **Phase 1 (Staged Full Custody):** When no local Homelab is immediately reachable, the public DePIN network persists all 14 shards ($10+4$, $140\%$ storage overhead) under a transient 72-hour TTL quorum.
   - **Phase 2 (Homelab Confirmation):** Once the owner's Homelab downloads the complete replica and broadcasts an authenticated `KIND_HOMELAB_ACK` (`0x0000_2011`), public nodes discard data shards $0..9$ and retain only parity shards $10..13$, stabilizing at $40\%$ permanent network overhead.
   - Unacknowledged staged files expire after 72 hours unless their L2 sponsorship escrow is explicitly renewed for full custody.

5. **Safe-Ghost Locking for Client Nodes:**
   Client daemons (`--role client` or `ark-app`) are physically prohibited from pruning or evicting local cached source chunks until receiving cryptographic confirmation:
   - Either a valid `KIND_HOMELAB_ACK` signed by the user's Homelab `ArkID`;
   - Or passing verification of at least 10 remote Proof-of-Retrievability (PoR) challenges against sponsored DePIN keeper nodes.

6. **Sampled Proof-of-Retrievability (PoR) (`KIND_DEPIN_CHALLENGE`):**
   Storage keepers are audited via challenge envelopes carrying `TAG_CHALLENGE_SEED` (`0x0016`). The keeper responds by computing $\text{KMAC256}(\text{seed}, \text{sub\_chunk})$ on a sampled $4\text{ KB}$ sub-block within the $1\text{ MB}$ shard along with its Merkle inclusion proof. Auditors verify possession in microseconds without transferring the full shard.

7. **Mandatory L2 Escrow Sponsorship:**
   Public network persistence requires an active sponsorship contract verified via `TAG_L2_CONTRACT` (`0x000F`). The `ark-blob` engine decouples billing via a pluggable `BlobEscrowVerifier` trait.

8. **Dedicated QUIC FastHeader Data Streaming:**
   Bulk shard transfer bypasses individual envelope overhead by using dedicated QUIC streams framed by 64-byte `FastHeader`s carrying `TAG_CONTENT_CID` and `TAG_SHARD_INDEX`, preventing redundant post-quantum signature verification per megabyte while preserving zero-copy throughput.

## Consequences

### Positive
- Resilience to up to 4 arbitrary keeper node failures per 14-node cluster with mathematically guaranteed reconstruction.
- Zero-risk mobile uploads through Staged Full Custody and Safe-Ghost locking.
- 40% long-term storage footprint for homelab-backed blobs, drastically reducing network storage costs.
- Microsecond verification of keeper custody via sampled Merkle PoR challenges.
- Avoids LSM buffer pool bloat by offloading bulk data to content-addressed filesystem storage.

### Negative / Trade-offs
- CPU overhead during Cauchy encoding/decoding matrices (mitigated by SIMD acceleration).
- Requires keeping file descriptors and directories synchronized between Fjall metadata and CAS disk storage.
- Transient 72-hour period incurs $140\%$ storage billing overhead until Homelab acknowledgement.
