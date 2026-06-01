#!/usr/bin/env bash
# bench-json.sh — Run all oxitls benchmarks and save output in JSON format.
# Requires: cargo, jq (for downstream scripts)
# Usage: ./scripts/bench-json.sh [output-dir]
# Output: target/criterion/<bench>/<group>/new/estimates.json (Criterion's native output)
set -euo pipefail
OUTPUT_DIR="${1:-target/criterion}"
echo "Running benchmarks... output will appear in: $OUTPUT_DIR"
# Criterion stores JSON at target/criterion/<bench-name>/<group-name>/new/estimates.json
cargo bench --workspace --no-fail-fast 2>&1
echo "Benchmark JSON files available under: $OUTPUT_DIR"
echo "Run: find $OUTPUT_DIR -name 'estimates.json' | head -20"
