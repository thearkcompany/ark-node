# ADR-0012: Sovereign Sandboxed Compute & Execution Engine (AEP-01)

## Context

Under the ARK Ecosystem Governance model, the core protocol wire and persistence norms are strictly frozen under Track 1 (**ACP-01 to ACP-10**, 2026-LTS biennial freeze). To provide decentralized applications, autonomous microservices, and network automations with programmable compute without destabilizing the frozen Layer 1 protocol, application manifests, worker execution standards, and schedulers reside in Track 2 (**AEP — Ark Ecosystem Proposals**).

The `ark-node` requires an embedded, sovereign execution engine (`ark-paas`) inaugurating Track 2 as **AEP-01 (or AEP-0001)**. This engine must execute untrusted or decentralized user functions with:
1. Strict, uncompromised isolation from the host operating system (zero direct OS sockets, zero arbitrary filesystem access).
2. Deterministic execution limits preventing infinite loops, memory bloat, and resource exhaustion.
3. Hermetic capability-based integration with Core primitives: `ark-storage` (ACP-06 / Fjall LSM), `ark-crdt` (ACP-09 / MST & MVRs), and `ark-blob` (ACP-10 / content-addressed shards).
4. High-performance asynchronous job queueing with causal ordering and crash resilience.
5. Deterministic periodic invocation via an event-driven distributed cron synchronized with peer consensus time.

## Decision

We establish the `ark-paas` subsystem implementing **AEP-01** according to the following architectural decisions:

1. **Sandboxed Wasmtime Runtime for `wasm32-unknown-unknown`:**
   Guest workers run as WebAssembly modules compiled to the canonical target `wasm32-unknown-unknown`. Execution is managed via `wasmtime` with memory capped using `StoreLimitsBuilder` (default $64\text{ MB}$ allocation limit per instance) and preemptive epoch deadline timers (`epoch_deadline_callback`) to guarantee termination.

2. **Dual-Pool Fuel Metering (Independent CPU & I/O Fuel):**
   Resource consumption is governed by two orthogonal, strictly metered pools:
   - **CPU Fuel**: Metred instruction-by-instruction by Wasmtime's internal fuel counters (default $10^7$ fuel units). Exceeding this budget halts execution immediately with `PaasError::CpuFuelExhausted`.
   - **I/O Fuel**: Enforced in host memory buffers across every host interaction (default $1\text{ MB}$ combined I/O budget for key-value, blob reads, and envelope writes). Exceeding this budget halts execution with `PaasError::IoFuelExhausted`.

3. **Hermetic Capability-Based Ark Host-ABI (`ark_host_*`):**
   Guests are physically prohibited from opening OS sockets or accessing host paths. Guest-host communication operates over linear memory via exported guest allocators `ark_alloc(size: u32) -> *mut u8` and `ark_dealloc(ptr: *mut u8, size: u32)`. The host exposes six canonical capability syscalls:
   - `ark_host_kv_get(key_ptr, key_len, out_ptr, out_max_len) -> i32`
   - `ark_host_kv_set(key_ptr, key_len, val_ptr, val_len) -> i32`
   - `ark_host_blob_read(cid_ptr, cid_len, offset, out_ptr, out_max_len) -> i32`
   - `ark_host_envelope_emit(env_ptr, env_len) -> i32`
   - `ark_host_log(level, msg_ptr, msg_len)`
   - `ark_host_now_pmt() -> u64`

4. **Ark Queue with In-Memory ACK Elision & LSM Durability:**
   Job dispatching adheres to at-least-once causal ordering:
   - Inbound tasks are durably logged to a dedicated `ark-storage` partition (`Keyspace` / Class 1 retention).
   - Execution dispatches associate jobs with an in-memory `JobLease` tracked in an atomic concurrent ring buffer.
   - **ACK Elision in RAM**: When a job completes successfully within its lease window, the acknowledgment is resolved purely in memory without synchronous disk writes. The disk tombstones are flushed lazily during periodic LSM compactions.
   - If a crash occurs or lease expires, unacknowledged jobs are re-enqueued on restart (up to 3 retries before dead-letter queue routing).

5. **Ark Cron with Peer-Median-Time (PMT) & Skip-Missed Policy:**
   Periodic worker execution schedules derive timing deterministically from decentralized consensus time (`ark-time` / PMT) rather than local OS clocks. If a node goes offline, upon rejoining it applies a strict **Skip Missed Intervals** policy: only the most recent scheduled execution is dispatched, suppressing historical catch-up cascades.

6. **Unified Trigger Abstraction:**
   The `PaasEngine` exposes a unified event trigger dispatcher (`TriggerSource`):
   - `Trigger::Cron`: Fired on PMT cron ticks.
   - `Trigger::EnvelopeReceived`: Reactive execution triggered by inbound envelopes matching registered `CoreTagMask` or `kind`.
   - `Trigger::ManualInvocation`: Direct synchronous invocation via CLI or local node management API.

## Consequences

### Positive
- Fully decoupled governance: Core protocol wire formats (ACP-01 to ACP-10) remain strictly frozen, while AEP-01 evolves semiannually.
- Provable host security: Complete absence of OS network/filesystem attack vectors inside sandboxed workers.
- Deterministic denial-of-service immunity through isolated dual-pool CPU and I/O fuel traps.
- Zero disk write overhead for normally completing jobs via in-memory ACK elision.
- Eliminates clock drift exploits in scheduled jobs by synchronizing with Peer-Median-Time.

### Negative
- Wasmtime compilation and memory initialization introduce microsecond-level overhead relative to native code execution.
- Capability-based ABI requires explicit guest serialization/deserialization across linear memory boundaries.
