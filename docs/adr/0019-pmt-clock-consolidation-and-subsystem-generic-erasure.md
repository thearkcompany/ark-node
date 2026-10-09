# ADR-0019: PmtClock Consolidation and Subsystem Generic Parameter Erasure

## Status
Accepted

## Context
Following the design principles in `codebase-design` and our domain conventions:
1. `ark-dns` introduced a shallow wrapper trait `TimeProvider: PmtClock` with a single default method `fn now_secs(&self) -> u64 { self.now_pmt() }`. This introduced cognitive overhead and terminology drift against `ark-time::PmtClock` and ADR-0010.
2. `SovereignDnsEngine<T: TimeProvider, V: L2ContractVerifier>`, `LeaseLifecycleEngine<T>`, and `StubResolver<T, V>` leaked type parameters throughout downstream crates (such as `ark-runtime` and test suites), requiring callers to either specify concrete types or carry default type parameters. DNS queries and escrow verifications are not tight inner-loop compute bottlenecks where dynamic dispatch introduces measurable overhead.
3. `ark-paas` defined `InMemoryPmtClock` backed by `Arc<Mutex<u64>>`, needlessly duplicating the lock-free, atomic `ark_time::MockPmtClock` (`AtomicU64`).

## Decision

1. **Elimination of `TimeProvider` in favor of `ark_time::PmtClock`**:
   - Remove `TimeProvider` from `crates/ark-dns/src/lifecycle.rs`.
   - Update `LeaseLifecycleEngine` and related DNS modules to consume `ark_time::PmtClock` directly via `now_pmt()`.

2. **Generic Parameter Erasure via Trait Objects (`Arc<dyn ...>`)**:
   - Erase generic type parameters from `SovereignDnsEngine`, `LeaseLifecycleEngine`, and `StubResolver`.
   - Store dependencies as trait objects:
     - `clock: Arc<dyn PmtClock>`
     - `l2_verifier: Arc<dyn L2ContractVerifier>`
   - Deepen `SovereignDnsEngineBuilder`:
     - Provide a default `clock` instance initialized to `Arc::new(SystemPmtClock::default())`.
     - Keep `l2_verifier` as a required builder input, returning `DnsError::InvalidRecord` if omitted.

3. **Consolidation of In-Memory Mock Clocks**:
   - Deprecate/replace `ark_paas::traits::InMemoryPmtClock` with `ark_time::MockPmtClock`.
   - Provide a type alias `pub type InMemoryPmtClock = ark_time::MockPmtClock;` in `ark-paas::traits` to maintain non-breaking source compatibility while eliminating redundant mutex-based clock code.

## Consequences

### Positive
- **Deep Seams**: Subsystems consuming DNS (`ark-runtime`, `NodeRuntimeBuilder`, `EnvelopeDispatcher`) no longer require generic parameters or generic bounds for DNS capabilities.
- **Canonical Consensus Time**: A single trait (`PmtClock`) represents network consensus time across all subsystems (`ark-time`, `ark-dns`, `ark-wot`, `ark-paas`).
- **Zero Lock Overhead**: Test doubles uniformly utilize atomic operations (`MockPmtClock`) rather than mutex locks.

### Negative / Trade-offs
- Dynamic dispatch (`vtable` dereference) on `PmtClock::now_pmt` and `L2ContractVerifier::verify_escrow_contract`. This overhead is negligible in IO-bound network protocol handling.
