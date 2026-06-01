#!/usr/bin/env bash
# Generate a flamegraph for the handshake benchmark.
# Requires: cargo install cargo-flamegraph
#
# Output: flamegraph.svg (in the current directory)
set -euo pipefail

if ! command -v cargo-flamegraph &>/dev/null && ! cargo flamegraph --version &>/dev/null 2>&1; then
    echo "cargo-flamegraph is not installed." >&2
    echo "Install with: cargo install flamegraph" >&2
    exit 1
fi

echo "Generating flamegraph for handshake benchmark..."
cargo flamegraph --bench handshake -- --bench
echo "Flamegraph saved to flamegraph.svg"
