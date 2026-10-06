# ADR-0002: Hermetic Protobuf Schema Generation via protobuf-src

## Context

The ARK envelope format canonical definitions reside in `proto/ark_envelope.proto` and must be compiled into strongly-typed Rust structs using `prost` and `prost-build`. Relying on a system-installed `protoc` binary introduces environmental fragility, as developer machines and CI runners may lack `protoc` or have incompatible versions.

## Decision

We adopt `protobuf-src` as a build dependency within `ark-protocol/Cargo.toml`. The `build.rs` script sets the `PROTOC` environment variable pointing to the hermetically-compiled binary provided by `protobuf-src`.

## Consequences

### Positive
- Fully self-contained workspace: running `cargo build` succeeds cleanly out-of-the-box without requiring OS package manager commands (`brew install protobuf` or `apt-get install protobuf-compiler`).
- Guaranteed version consistency of schema compilation across all environments.

### Negative / Trade-offs
- Slight increase in initial clean build compilation time as `protobuf-src` builds from source.
