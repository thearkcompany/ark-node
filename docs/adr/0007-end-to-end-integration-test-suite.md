# ADR-0007: End-to-End Integration Test Suite for Protocol Compliance

## Context

The ARK protocol v0.1 encompasses six interdependent crates implementing ACP-02 (Crypto), ACP-03 (Core), ACP-04 (Transport), ACP-05 (Protocol), ACP-07 (Time), and CLI runtime. Isolated unit tests verify individual structs but do not guarantee that a full client daemon can connect to a server daemon, negotiate ALPN `ark-pqc/v1`, transmit a signed `ArkEnvelope`, and pass replay and drift validation.

## Decision

We establish an automated end-to-end integration test harness in `tests/e2e_node.rs`. The test harness starts an in-process `ark-node` server listening on localhost UDP/QUIC, generates client identities, issues encrypted envelopes, verifies FastHeader extraction, enforces clock drift bounds, validates anti-replay insertion, and asserts round-trip acknowledgment.

## Consequences

### Positive
- Immediate regression detection across the entire protocol stack before pull requests land.
- Serves as the primary runnable acceptance criteria for `/to-spec` and `/implement`.

### Negative / Trade-offs
- Integration tests bind ephemeral local ports and require asynchronous tokio test runtimes.
