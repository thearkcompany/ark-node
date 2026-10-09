# CODING_STANDARDS.md

Architectural conventions and judgment criteria for engineers and AI review agents (`/code-review`) working on `ark-node`.

These standards focus exclusively on architectural judgment calls that cannot be automated via compiler warnings, formatting tools, or `clippy`.

---

## 1. Deep Modules and Facades

- **Thin Facades, Deep Engines**: Subsystem facades (`WotEngine`, `VpnEngine`, `DnsEngine`, `BlobEngine`, `PaasEngine`) must remain thin coordinators that delegate state, validation, and storage to internalized engines and stores (`WotStore`, `MstStore`, `StorageEngine`, `DnsOverlay`).
- **Encapsulate Storage**: Internal storage engines (such as LSM trees or Merkle Search Trees) must be owned and managed by their subsystem store rather than passed through as unencapsulated caller dependencies.
- **Seam Discipline**: When designing or refactoring subsystem boundaries, place the seam where multiple adapters or swappable behaviors actually exist (e.g. `PmtClock`, `TunAdapter`, `TransportSink`). Avoid creating speculative seams or pass-through traits where only a single implementation ever exists.
- **Interface Minimality**: Expose the smallest feasible surface area on public engine types. Complex internal details (such as epoch intervals, lock choreography, and serialization buffers) must remain private to the module implementation.

---

## 2. Zero-Trust Envelope Verification & Retention

- **Adversarial Ingestion Invariant**: Never trust incoming wire envelopes. Every subsystem ingesting envelopes (`ArkEnvelope`) must strictly verify:
  1. Cryptographic signatures (`FN-DSA`) against the declared sender identity.
  2. Retention class compatibility (e.g. VPN traffic MUST be Class 0 ephemeral; CRDT delta records MUST match Class 1 or Class 2; time beacons must match Class 0).
  3. Anti-replay protection (cuckoo filter membership and monotonic sequence counter progression).
  4. Timestamp drift tolerance (rejecting timestamps beyond the consensus drift window, e.g. ±30s).
- **RAM-Only Isolation for Class 0**: Ephemeral traffic (VPN tunnels, real-time telemetry, routing packets) classified as Retention Class 0 must strictly bypass disk storage engines and never write to LSM keyspaces.
- **Single-Pass Ingestion**: When receiving envelopes containing signed CRDT updates or attestations, perform verification and state application in a single pass to prevent race conditions and duplicate disk I/O.

---

## 3. Error Handling and Encapsulation

- **Subsystem-Scoped Error Enums**: Each crate must define its own domain-specific error enum (e.g., `VpnError`, `WotError`, `PaasError`, `DnsError`) using `thiserror`.
- **No Error Leakage**: Internal lower-level errors (such as `fjall::Error`, `bincode::Error`, or `quinn::ConnectionError`) must be mapped into domain errors at the crate boundary rather than exposed in public method signatures.
- **Deterministic Failure Telemetry**: For compute and background task systems (`ark-paas`), execution errors must produce deterministic execution telemetry rather than dropping tasks silently.

---

## 4. Test Isolation and Determinism

- **Hermetic Unit & Integration Tests**: Tests must avoid relying on fixed network ports or persistent disk state outside temporary test fixtures (`tempfile`).
- **Deterministic Clocks in Tests**: Prefer simulated or controllable clock implementations (`MockPmtClock`) for testing temporal expiration, half-life decay, and lease expirations rather than sleeping real wall-clock time.
- **Property-Based Verification**: For cryptographic protocols, CRDT anti-entropy reconciliations, and erasure coding (Cauchy RS), complement deterministic regression tests with generative or exhaustive combinations where feasible.
