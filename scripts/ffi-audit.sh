#!/usr/bin/env bash
set -euo pipefail
RESULT=$(cargo tree --target x86_64-unknown-linux-gnu --edges normal 2>/dev/null | grep -E '(ring v|aws-lc-sys v|aws-lc-rs v|openssl-sys v|native-tls v)' || true)
if [ -n "$RESULT" ]; then
  echo "FFI AUDIT FAILED: forbidden crates in tree:"
  echo "$RESULT"
  exit 1
fi
echo "FFI audit PASSED"
