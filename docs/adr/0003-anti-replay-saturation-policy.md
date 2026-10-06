# ADR-0003: Memory-Bounded Anti-Replay Defense via Strict Filter Saturation Policy

## Context

The ARK protocol implements an anti-replay mechanism based on a Dual Cuckoo Filter in memory, allocated with a strict ceiling ($\le 24\text{ MB}$). Under adverse conditions, such as high-volume replay attacks or distributed packet spam, the active generation filter could reach its operational capacity before the scheduled epoch rotation.

## Decision

When the active Cuckoo Filter reaches saturation and cannot insert a new sequence nonce:
1. The packet is rejected immediately with an explicit error (`ArkError::ReplayFilterFull`).
2. The packet is dropped without executing further cryptographic decoding.
3. The node does NOT trigger premature generation rotation and does NOT dynamically allocate unbounded overflow buffers.

## Consequences

### Positive
- Formal preservation of replay prevention guarantees: no replayed packet can bypass verification under memory pressure.
- Unbreakable guarantee on node memory consumption ($\le 24\text{ MB}$), preventing out-of-memory (OOM) kernel panics.

### Negative / Trade-offs
- Legitimate packets may be dropped during extreme flood attacks until the filter rotation interval elapses or client rate-limiting mitigates the spike.
