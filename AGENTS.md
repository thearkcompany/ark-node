# AGENTS.md

Instructions, context, and conventions for AI coding agents working on `ark-node`.

## Agent skills

### Issue tracker

Issues and specs live in GitHub Issues (accessed via the `gh` CLI). See `docs/agents/issue-tracker.md`.

### Triage labels

Canonical 5-role triage vocabulary (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`). See `docs/agents/triage-labels.md`.

### Domain docs

Single-context layout (`GLOSSARY.md` and `docs/adr/` at repo root). See `docs/agents/domain.md`.

## Workspace navigation

- **Subsystem crates** (`crates/`):
  - `ark-core`: Core wire types and zero-copy `FastHeader`.
  - `ark-protocol`: Envelope encoding, retention classes, hashing, and wire framing.
  - `ark-crypto`: Post-quantum cryptography (`FN-DSA`, `ML-KEM-768`) and persistent identities.
  - `ark-storage`: LSM-tree retention engine (`Fjall`) for classes 1-5.
  - `ark-transport`: QUIC endpoint and connection management (`quinn`).
  - `ark-time`: Physical Monotonic Time (`PmtClock`) consensus and anti-replay cuckoo filters.
  - `ark-crdt`: Distributed KV MST Merkle search tree and replication engine.
  - `ark-dns`: Sovereign DNS radix trie, crypto name resolution, and anti-Sybil overlay.
  - `ark-blob`: Cauchy RS-erasure blob sharding and Proof-of-Retrievability (PoR).
  - `ark-paas`: Sandboxed WASM compute engine (`wasmtime`), job leases, and deterministic cron.
  - `ark-vpn`: Sovereign P2P mesh VPN pipeline, TUN adapter, PQMT framing, and blind relays.
  - `ark-wot`: Web of Trust Sybil resistance, Personalized PageRank, and CRDT store.
  - `ark-runtime`: Unified node daemon, subsystem ingress dispatch, and lifecycle supervision.
  - `ark-cli`: Node administration CLI and identity management.
- **Architectural decisions** (`docs/adr/`): System-wide architectural decision records (ADR 0001–0020). Consult relevant ADRs before modifying subsystem contracts.

## Phase boundaries

Respect phase boundaries: never edit production code (`crates/`, `src/`, `tests/`) during exploratory, research, grilling, or wayfinding phases. Reserve code changes exclusively for implementation tasks triggered by implementation skills (`/implement-spec`, `/tdd`).
