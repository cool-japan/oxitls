#!/usr/bin/env bash
# bench-report.sh — Generate a Markdown performance summary from Criterion JSON output.
# Requires: jq, find
# Usage: ./scripts/bench-report.sh [criterion-dir]
# Output: Markdown table on stdout
set -euo pipefail
command -v jq >/dev/null 2>&1 || { echo "ERROR: jq not found."; exit 1; }
CRIT_DIR="${1:-target/criterion}"

echo "# OxiTLS Benchmark Results"
echo ""
echo "| Benchmark | Group | Mean (ns) | Std Dev (ns) |"
echo "|-----------|-------|-----------|--------------|"

# Walk Criterion output: target/criterion/<bench>/<group>/new/estimates.json
find "$CRIT_DIR" -name "estimates.json" -path "*/new/*" 2>/dev/null | sort | while read -r f; do
  bench=$(echo "$f" | sed -E 's|.*/criterion/([^/]+)/.*|\1|')
  group=$(echo "$f" | sed -E 's|.*/criterion/[^/]+/([^/]+)/new/.*|\1|')
  mean=$(jq -r '.mean.point_estimate' "$f" 2>/dev/null || echo "N/A")
  std=$(jq -r '.std_dev.point_estimate' "$f" 2>/dev/null || echo "N/A")
  printf "| %-30s | %-30s | %12.0f | %12.0f |\n" "$bench" "$group" "$mean" "$std"
done
