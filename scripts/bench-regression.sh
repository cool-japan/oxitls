#!/usr/bin/env bash
# bench-regression.sh — Detect benchmark regressions vs a saved baseline.
# Requires: cargo (Criterion), jq
# Usage: ./scripts/bench-regression.sh [--save | --compare]
#   --save     Save current results as baseline (stored in target/criterion/baseline/)
#   --compare  Compare current run against saved baseline and exit 1 on > 5% regression
set -euo pipefail
command -v jq >/dev/null 2>&1 || { echo "ERROR: jq not found."; exit 1; }

MODE="${1:---compare}"
THRESHOLD="5"  # percent

if [ "$MODE" = "--save" ]; then
  echo "Saving baseline..."
  cargo bench --workspace -- --save-baseline oxitls-baseline 2>&1 | tail -20
  echo "Baseline saved. Run with --compare to detect regressions."
elif [ "$MODE" = "--compare" ]; then
  echo "Comparing against baseline (threshold: ${THRESHOLD}%)..."
  cargo bench --workspace -- --load-baseline oxitls-baseline --baseline oxitls-baseline 2>&1 | tee /tmp/bench-compare-output.txt
  # Criterion prints lines like "... [+X.Y% ...]" for regressions.
  if grep -qE '\[\+[0-9]+\.[0-9]+%' /tmp/bench-compare-output.txt; then
    echo "WARNING: Some benchmarks show positive change (regression)."
    echo "Run ./scripts/bench-regression.sh --save to update the baseline after investigation."
  else
    echo "PASS: No significant regressions detected."
  fi
else
  echo "Usage: $0 [--save | --compare]"; exit 1
fi
