#!/usr/bin/env bash
# bench-quic-compare.sh — Compare TLS handshake (oxitls) vs QUIC handshake (oxiquic) latency.
# Requires: cargo
# Usage: ./scripts/bench-quic-compare.sh
# The scripts runs the TLS handshake bench from oxitls-bench and the QUIC h3 bench
# from oxiquic, then prints a side-by-side summary.
set -euo pipefail

OXITLS_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OXIQUIC_DIR="$(dirname "$OXITLS_DIR")/oxiquic"

echo "=== OxiTLS: TLS 1.3 handshake latency ==="
( cd "$OXITLS_DIR" && cargo bench -p oxitls-bench --bench handshake -- --warm-up-time 1 --measurement-time 3 2>&1 | grep -E 'time:|thrpt:' | head -10 )

if [ -d "$OXIQUIC_DIR" ]; then
  echo ""
  echo "=== OxiQUIC: QUIC+TLS handshake latency ==="
  ( cd "$OXIQUIC_DIR" && cargo bench 2>&1 | grep -E 'time:|thrpt:' | head -10 ) || echo "(oxiquic benches not available)"
else
  echo ""
  echo "INFO: oxiquic not found at $OXIQUIC_DIR"
  echo "Manually run: ( cd <oxiquic-dir> && cargo bench ) to compare QUIC handshake latency."
fi
echo ""
echo "For a full comparison, see:"
echo "  oxitls-bench/benches/handshake.rs (TLS 1.3 over TCP)"
echo "  oxiquic/crates/oxiquic-h3/benches/ (QUIC + H3 over UDP)"
