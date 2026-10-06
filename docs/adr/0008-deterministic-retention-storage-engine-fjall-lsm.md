# ADR-0008: Deterministic Retention Storage Engine on Embedded Fjall LSM (GCP-06)

## Context

Phase 2 of the ARK Sovereign P2P Node requires a persistent storage engine (`ark-storage`) executing with a strict frugal memory ceiling ($\le 65\text{ MB}$ RAM) on commodity hardware and single-board nodes. 

The node must handle diverse event lifecycles dictated by GCP-06: ephemeral control signals, immutable event streams, replaceable identity profiles, parameterized key-value entries, bounded-lifetime cache entries, and strictly immutable equivocation proofs.

## Decision

We adopt pure-Rust embedded LSM engine `fjall` configured with partitioned `Keyspace`s and a shared global block cache / write buffer bounded to $64\text{ MB}$.

1. **Partitioned Keyspaces:** Dedicated keyspaces isolate distinct retention classes (`class1_append`, `class2_replaceable`, `class3_param_d`, `class4_ttl`, `class5_worm`), enabling custom compaction policies and targeted bloom filters.
2. **Canonical Envelope Identity:** All stored envelopes are canonically addressed by their SHA3-256 digest (32 bytes) computed over wire/envelope serialization.
3. **Deterministic Retention Classifier:** A canonical function classifies envelopes into retention classes based on `kind` range rules, prioritized by `TAG_EXPIRATION` (TTL binding) and `TAG_PARAM_D` (parameterized grouping).
4. **Bivariate LWW for Replaceable Classes (Class 2 & Class 3):** Concurrent or competing updates for the same logical key are deterministically resolved via bivariate Last-Write-Wins: $\max(\text{timestamp}) \parallel \max(\text{id})$. Ties in timestamp are broken by lexicographical comparison of the 32-byte envelope digest.
5. **Class 4 Bounded TTL:** Implemented via lazy expiration upon read (`timestamp > expiration`) combined with an active secondary index (`[exp_timestamp: 8B BE] || [id: 32B]`) swept periodically by a background task.
6. **Class 5 Strict WORM:** Enforces tamper-proof immutability where repeated writes of identical bytes are idempotent no-ops, but mutations or deletion attempts immediately yield `ArkStorageError::WormViolation`.
7. **Class 0 Ephemeral:** Bypasses disk write pipelines entirely, residing strictly in bounded in-memory channels/ring buffers.
8. **Frugal Memory Budgeting:** A configurable `StorageConfig` defaults to $32\text{ MB}$ block cache and $16\text{ MB}$ write buffer/memtable, strictly preserving total engine RAM usage below the $65\text{ MB}$ ceiling.
9. **Unified Envelope Storage API & Explicit Outcomes:** Interacting modules consume high-level strongly typed APIs returning explicit `RetentionOutcome` variants (`Stored`, `Replaced`, `SupersededLww`, `EphemeralPassed`, `IdempotentDuplicate`) preventing bypass of retention invariants.
10. **Tiered Fsync Durability Policy:** Class 5 (Strict WORM) forces immediate synchronous `fsync` to guarantee crash-resilient persistence of equivocation proofs; Classes 1–4 utilize periodic/asynchronous WAL flushing to optimize disk write endurance and sustain sub-millisecond write latencies.


## Consequences

### Positive
- Strict memory bound ($\le 65\text{ MB}$) across all database partitions via centralized Fjall partition managers.
- Zero ghost reads for expired records and deterministic garbage collection without table locks.
- Immutable auditability for equivocation proofs and receipts without risk of accidental truncation or overwrite.
- Fast index lookups and point queries aligned with zero-copy buffer layouts.

### Negative / Trade-offs
- Secondary index maintenance for TTL incurs an additional disk write per TTL-bounded envelope.
- Keyspace management requires explicit lifecycle coordination on node startup and graceful shutdown.
