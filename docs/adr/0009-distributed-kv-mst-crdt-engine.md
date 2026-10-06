# ADR-0009: Distributed Key-Value Consistency via Merkle Search Trees & Multi-Value Registers (GCP-09)

## Context

Following the implementation of `ark-storage` (ADR-0008, GCP-06), the ARK Sovereign P2P Node requires a distributed key-value consistency layer (`ark-crdt`) satisfying GCP-09.

Nodes across the sovereign peer network must synchronize mutable state (such as sovereign DNS `.ark` records, application KV namespaces, and worker metadata) asynchronously over QUIC streams without relying on centralized masters or consensus quorums. Sychronization must be resilient to arbitrary network partitions, guarantee deterministic state convergence, bound round-trips to $\mathcal{O}(\Delta \log n)$, and strictly adhere to the node's $\le 65\text{ MB}$ RAM budget.

## Decision

We adopt a Merkle Search Tree (MST) index integrated with `ark-storage` and backed by Last-Write-Wins (LWW) conflict resolution and Multi-Value Registers (MVR):

1. **Deterministic MST Topology:** 
   Keys are mapped into tree levels using trailing zero 4-bit nibbles of `SHA3-256(key)` ($\lfloor \text{ctz}(\text{SHA3-256}(key)) / 4 \rfloor$), yielding an average branching factor of $b = 16$. Because node levels depend solely on key hashes, identical key-value sets generate the identical 32-byte root digest regardless of insertion, update, or deletion order.
2. **In-Node Entry Layout:**
   Each node contains an ordered sequence of entries `(key, envelope_id, timestamp)` interleaved with child hashes `child_hash: [u8; 32]`. Storing `timestamp` and `envelope_id` directly in the tree node allows fast, zero-disk LWW conflict resolution during tree diffing.
3. **Partitioned Namespaces:**
   Distinct domains (e.g., `.ark` DNS tables, app databases) maintain isolated, independent MST roots and key spaces. This prevents unrelated state mutations from inflating synchronization overhead.
4. **Integration with `ark-storage` & Bounded Caching:**
   Serialized tree nodes are persisted in a dedicated keyspace (`mst_nodes`) within the Fjall LSM engine, supported by a bounded in-memory LRU cache ($\le 8\text{ MB}$).
5. **Headless Resolution Cascade:**
   For headless daemon nodes (`--role server`), concurrent edits resolve immediately via `MERGE_POLICY_LWW_BIVARIATE` ($\max(\text{timestamp}) \parallel \max(\text{id})$), preventing unbounded sibling accumulation while preserving determinism.
6. **Iterative 2-Phase Delta Reconciliation (`KIND_KV_MST_SYNC`):**
   Peer-to-peer reconciliation occurs over dedicated QUIC streams using structured Protobuf messages (`MstSyncRequest`, `MstSyncResponse`). Peers exchange root digests, descend into divergent subtrees, and transfer only divergent keys and missing `ArkEnvelope`s.
7. **Tombstone Semantics:**
   Key deletions are modeled as signed `ArkEnvelope`s carrying tombstone markers and fresh timestamps, guaranteeing that deletions reliably propagate and supersede older records across peers.
8. **Anti-DoS and Resource Bounding:**
   Requests enforce strict limits: maximum 64 tree nodes or 256 keys per sync response, maximum tree depth of 16, and immediate peer penalization / disconnection upon invalid node serialization hashes.

## Consequences

### Positive
- Order-independent deterministic root hashing enables rapid $O(1)$ root checks between peers to verify state synchronization.
- Delta synchronization scales with difference size $\mathcal{O}(\Delta \log n)$ rather than total dataset size.
- Low memory footprint ($\le 8\text{ MB}$ MST cache) fits safely inside the overall 65 MB node RAM limit.
- Compatible with offline and partitioned node operation.

### Negative / Trade-offs
- Node updates require updating and recalculating parent hashes up to the tree root ($\mathcal{O}(\log n)$ writes).
- Persisting tree nodes adds modest write amplification in the `mst_nodes` keyspace.
