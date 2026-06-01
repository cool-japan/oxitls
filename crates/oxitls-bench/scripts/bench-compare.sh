#!/usr/bin/env bash
# Compare criterion benchmark results between two baselines.
# Usage: bench-compare.sh <baseline1> <baseline2>
# Requires: jq
#
# Criterion stores baseline estimates under:
#   target/criterion/<bench_name>/base/estimates.json   (saved baseline)
#   target/criterion/<bench_name>/changes/estimates.json (regression run)
#
# To save a baseline before a change:
#   cargo bench -p oxitls-bench -- --save-baseline pre-wave5
# Then after the change:
#   cargo bench -p oxitls-bench -- --baseline pre-wave5
set -euo pipefail

B1="${1:-pre-wave5}"
B2="${2:-current}"

CRIT_DIR="$(cargo metadata --no-deps --format-version 1 | jq -r '.target_directory')/criterion"

if [[ ! -d "$CRIT_DIR" ]]; then
    echo "No criterion output directory found at: $CRIT_DIR" >&2
    echo "Run 'cargo bench -p oxitls-bench' first." >&2
    exit 1
fi

if ! command -v jq &>/dev/null; then
    echo "jq is required. Install with: brew install jq  (macOS)" >&2
    exit 1
fi

echo "Comparing baselines: $B1 -> $B2"
echo "Criterion dir: $CRIT_DIR"
echo "---"

found=0
for bench_dir in "$CRIT_DIR"/*/; do
    bench_name="$(basename "$bench_dir")"
    f1="$bench_dir/base/estimates.json"
    f2="$bench_dir/changes/estimates.json"
    if [[ -f "$f1" && -f "$f2" ]]; then
        mean1=$(jq '.mean.point_estimate' "$f1")
        mean2=$(jq '.mean.point_estimate' "$f2")
        # Calculate delta percentage.
        delta=$(jq -n --argjson m1 "$mean1" --argjson m2 "$mean2" \
            'if $m1 == 0 then 0 else (($m2 - $m1) / $m1 * 100) end')
        printf "%-50s  %12.0f ns  ->  %12.0f ns  (%+.1f%%)\n" \
            "$bench_name" "$mean1" "$mean2" "$delta"
        found=1
    fi
done

if [[ "$found" -eq 0 ]]; then
    echo "No comparison data found."
    echo "Save a baseline first: cargo bench -p oxitls-bench -- --save-baseline $B1"
    echo "Then run with:         cargo bench -p oxitls-bench -- --baseline $B1"
fi
