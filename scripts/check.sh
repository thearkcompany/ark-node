#!/usr/bin/env bash
set -euo pipefail

echo "==> Running format check (cargo fmt --check)..."
cargo fmt --check

echo "==> Running clippy linter (cargo clippy --all-targets -- -D warnings)..."
cargo clippy --all-targets -- -D warnings

echo "==> Running workspace tests (cargo test --workspace)..."
cargo test --workspace

echo "==> All CI checks passed successfully!"
