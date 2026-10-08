# ADR-0016: Canonical PmtClock Abstraction and Adapters

## Status
Accepted

## Context
Across the ARK protocol subsystem crates, temporal consensus (Peer-Median-Time, PMT) had multiple ad-hoc definitions and divergent interfaces:
- `ark-paas` defined duplicate traits `PmtClock` in `src/cron.rs` and `PmtClockBackend` in `src/traits.rs`, alongside a local `MockPmtClock`.
- `ark-dns` maintained its own independent `TimeProvider` / `MockTimeProvider` in `src/lifecycle.rs`.
- `ark-wot` exposed `evaluate_trust` requiring callers to manually supply `current_pmt: u64` rather than self-contained evaluation against consensus time.

This fragmentation led to repetitive mock implementations across test suites, code duplication, and inconsistent temporal abstractions across engines.

## Decision

1. **Canonical Capability Trait in `ark-time`**:
   - Define a single canonical capability trait in `crates/ark-time/src/clock.rs`:
     ```rust
     pub trait PmtClock: Send + Sync {
         fn now_pmt(&self) -> u64;
     }
     ```
   - Re-export `PmtClock` at `ark_time::PmtClock`.

2. **Standard Adapters Out of the Box**:
   - `SystemPmtClock`: Wraps `Arc<PeerMedianTime>` and local system clock (`SystemTime::now()`) to return `peer_median.network_time_secs(local_secs)`.
   - `MockPmtClock`: Backed by `AtomicU64`, providing deterministic zero-sleep methods `new(initial)`, `set_time(secs)`, and `advance(delta_secs)`. Available for testing and downstream crates via `test-utils` or direct dependency.

3. **Subsystem Engine Consolidation**:
   - **`ark-wot`**: `WotEngine::new` and `WotEngine::open` receive `Arc<dyn PmtClock>`. `WotEngine::evaluate_trust` queries `clock.now_pmt()` directly, deepening the interface. Pure mathematical decay functions (`compute_decayed_weight`) remain pure functions taking timestamp scalars.
   - **`ark-paas`**: Cleanly delete duplicate traits `PmtClock` from `src/cron.rs` and `PmtClockBackend` from `src/traits.rs`. Update `ArkCron` and `PaasEngine` to use `ark_time::PmtClock`.
   - **`ark-dns`**: Replace `TimeProvider` in `src/lifecycle.rs` with `ark_time::PmtClock`. `LeaseLifecycleEngine` and `SovereignDnsEngine` accept `Arc<dyn PmtClock>`.

## Consequences

### Positive
- Single, authoritative capability trait for Peer-Median-Time consensus across all ARK crates.
- Test suites across all crates can share `ark_time::MockPmtClock` for deterministic, zero-sleep time progression tests.
- Deeper engine interfaces where callers do not need to query or supply timestamps for internal lifecycle or reputation decisions.

### Negative / Trade-offs
- Workspace crates depend on `ark-time` for temporal capability traits. Since `ark-time` is a low-level protocol crate with minimal dependencies, this dependency overhead is negligible.
