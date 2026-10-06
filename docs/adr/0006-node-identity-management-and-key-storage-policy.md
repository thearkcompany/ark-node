# ADR-0006: Node Identity Management and Key Storage Policy

## Context

Running an `ark-node` daemon requires post-quantum asymmetric key pairs (FN-DSA-512 and ML-KEM-768) to sign envelopes and participate in key exchange. Development workflows, CI runs, and automated testing must execute without polluting developer home directories with persistent key files, while production deployments require deterministic key paths with strict permissions.

## Decision

In v0.1:
1. `ark-node` supports an explicit `--identity <path>` CLI flag and `ARK_IDENTITY_KEY` environment variable.
2. If neither flag nor environment variable is supplied, the node checks `~/.ark/identity.key`.
3. If no file exists, the node generates an ephemeral in-memory identity for the lifecycle of the session.
4. The `ark-node keygen` command writes to stdout and, when provided `--out <path>`, writes with strict file permissions (`0600`).
5. All private key buffers in RAM are locked against swap using `mlock` via `LockedBuffer<T>` and zeroized on drop.

## Consequences

### Positive
- Zero friction for testing and ephemeral Docker/CI instances.
- Secure fallback defaults preventing accidental plain-text leakages.

### Negative / Trade-offs
- Operators running production nodes must remember to supply `--identity` or run `keygen` explicitly so identities persist across daemon restarts.
