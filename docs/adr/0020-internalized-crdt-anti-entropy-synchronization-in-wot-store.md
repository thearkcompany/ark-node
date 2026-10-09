# ADR-0020: Internalized CRDT Anti-Entropy Synchronization in WotStore

## Status
Accepted

## Context
Under ACP-04, Web-of-Trust (WoT) reputation state relies on dual representations:
1. **Local Persistent Storage**: Fjall LSM keyspaces (`wot_attestations`, `wot_revocations`) combined with an in-memory lock-free Personalized PageRank (PPR) trust graph and evaluation cache.
2. **Distributed Anti-Entropy Synchronization**: Merkle Search Tree (MST) CRDT partitions operating under namespace `ark/wot/v1` for peer-to-peer eventual consistency.

Previously, `WotEngine` leaked storage coordination seams by manually re-encoding `TrustAttestation` and `TrustRevocation` objects into `ArkEnvelope`s, computing raw 64-byte compound keys, and mutating `MstEngine` separately from `WotStore`. Furthermore, `WotStore` already constructed identical envelopes internally for `ark-storage`, resulting in duplicate serialization and envelope construction. Inbound CRDT synchronizations lacked a unified ingestion seam to absorb remote peer envelopes directly into the local trust graph and LSM state.

## Decision

1. **Encapsulate `MstEngine` within `WotStore`**:
   - `WotStore::open(local_root, storage)` initializes `MstEngine` internally using the shared `StorageEngine` instance and default `MstConfig`.
   - Provide `WotStore::with_mst_engine(local_root, storage, mst_engine)` for customized or mock CRDT injection in tests.

2. **Single-Pass Envelope Generation & Atomic Mutation**:
   - `WotStore::save_attestation` and `WotStore::save_revocation` generate the canonical `ArkEnvelope` exactly once.
   - The same envelope instance is stored in `StorageEngine` (retention classes) and indexed into `MstEngine` under namespace `ark/wot/v1` with the compound key `[issuer_id: 32B] || [subject_id: 32B]`.

3. **Unified Inbound Anti-Entropy Ingestion Seam**:
   - Introduce `WotStore::ingest_crdt_envelope(&self, envelope: &ArkEnvelope) -> Result<()>`.
   - The ingestion seam extracts `TAG_WOT_PUBKEY` from the envelope tags, cryptographically verifies the FN-DSA-512 signature and identity derivation (`issuer_id == SHA3-256(pubkey)`), updates LSM keyspaces, indexes into the MST, and immediately updates the in-memory trust graph (PPR) and evaluation cache.

4. **Deep `WotEngine` Facade**:
   - `WotEngine::record_attestation` and `WotEngine::revoke_attestation` delegate persistence and synchronization entirely to `WotStore`, eliminating manual key formatting and duplicate serialization.

## Consequences

### Positive
- **High Leverage & Locality**: Subsystem storage and synchronization concerns are unified inside `WotStore`. The facade `WotEngine` focuses purely on high-level reputation queries, scoring, and policy enforcement.
- **Zero Redundant Serialization**: Envelopes are constructed and serialized once per write.
- **Symmetric Convergence**: Inbound CRDT updates from network peers automatically update local PPR calculations and lock-free cache via `ingest_crdt_envelope`.
- **Zero-Trust Ingestion**: Remote CRDT envelopes are cryptographically validated before mutating local state.

### Negative / Trade-offs
- `WotStore` holds a direct dependency on `ark-crdt` (`MstEngine`), coupling CRDT synchronization with local storage engine management.
