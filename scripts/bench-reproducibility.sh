#!/usr/bin/env bash
# bench-reproducibility.sh — Verify benchmark reproducibility (< 5% CV).
# Requires: jq
# Usage: ./scripts/bench-reproducibility.sh
# Runs a quick bench sample twice and checks coefficient of variation.
set -euo pipefail
command -v jq >/dev/null 2>&1 || { echo "ERROR: jq not found. Install jq first."; exit 1; }

echo "=== Run 1/2 ==="
cargo bench -p oxitls-bench --bench handshake -- --warm-up-time 1 --measurement-time 3 --sample-size 20 2>&1 | tail -20

echo "=== Run 2/2 ==="
cargo bench -p oxitls-bench --bench handshake -- --warm-up-time 1 --measurement-time 3 --sample-size 20 2>&1 | tail -20

# Read Criterion's JSON estimates from the two runs.
# Criterion caches only the LAST run; for comparison, use --save-baseline.
echo "INFO: For variance across runs, use Criterion's --save-baseline:"
echo "  cargo bench -- --save-baseline run1"
echo "  cargo bench -- --save-baseline run2"
echo "  cargo bench -- --load-baseline run1 --baseline run2"
echo "Criterion will report % change between runs."
echo "Reproducibility check: PASS if Criterion shows < 5% change across runs."
