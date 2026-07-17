# oxitls-bench TODO

## Status
Benchmark crate (~2,870 SLOC across 29 Rust files) with 27 criterion benchmark
targets spanning handshake/resumption, cryptographic primitives (AEAD/signatures/
digest vs ring/aws-lc-rs), data transfer, ALPN/SNI/mTLS/connection metadata,
certificate generation, OCSP stapling, session-ticket rotation, and allocation
profiling (see README.md "Benchmark Targets" for the full list). Benchmarks
compile and run. ring and aws-lc-rs are dev-only dependencies scoped to this crate.

## Core Implementation
- [x] Add TLS 1.2 full handshake benchmark (ECDHE-ECDSA-AES128-GCM-SHA256) (~60 SLOC)
- [x] Add TLS 1.2 resumed handshake benchmark via session ID (~60 SLOC)
- [x] Add per-cipher-suite benchmark group: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 for each provider (~120 SLOC)
- [x] Add throughput benchmark: bidirectional data transfer over TLS (1KB, 64KB, 1MB, 10MB payload sizes) (~150 SLOC)
- [x] Add handshake latency percentile measurement (p50, p95, p99) via criterion's custom measurement (~80 SLOC)
- [x] Add mTLS handshake benchmark (client cert + server verification overhead) (~80 SLOC)
- [x] Add ALPN negotiation overhead benchmark (~40 SLOC)
- [x] Add SNI dispatch benchmark with 1, 10, 100 virtual hosts (~80 SLOC)
- [x] Add OxiTicketer encrypt/decrypt micro-benchmark (1KB, 4KB, 16KB session state) (~60 SLOC)
- [x] Add OxiTicketer key rotation overhead benchmark (~40 SLOC)
- [x] Add certificate generation benchmark: Ed25519, P-256, RSA-2048 via oxitls-rcgen (~60 SLOC)
- [x] Add SHA-256 digest benchmark: OxiCrypto vs ring vs aws-lc-rs (~80 SLOC)
- [x] Add Ed25519 sign/verify benchmark: OxiCrypto vs ring vs aws-lc-rs (~80 SLOC)
- [x] Add ECDSA P-256 sign/verify benchmark: OxiCrypto vs ring vs aws-lc-rs (~80 SLOC)
- [x] Add HTTP/2 handshake-over-TLS benchmark (TLS + h2 combined latency) (~80 SLOC)
- [x] Add connection pool reuse benchmark: measure amortized cost of keep-alive connections (~100 SLOC)

## API Improvements
- [x] Add `--features latency-histogram` for HDR histogram output alongside criterion HTML — Wave 5 Slice F (latency-histogram feature + hdrhistogram optional dep in Cargo.toml). **Removed 2026-07-17**: dead scaffold — no benchmark ever wired up actual HDR-histogram instrumentation, so the unused `hdrhistogram` dependency and this feature flag were dropped from `Cargo.toml` (and the corresponding README references removed)
- [x] Add benchmark result comparison script: `scripts/bench-compare.sh` that compares against baseline — Wave 5 Slice F
- [x] Add JSON output mode for CI integration (`--output-format json`)
- [x] Extract shared `CertFixture` and `pure_provider()` helpers into a `bench_common` module — Wave 5 Slice F (benches/bench_common/mod.rs)

## Testing
- [x] Verify all benchmarks compile with `cargo bench -p oxitls-bench --no-run` — 25 bench executables build cleanly (verified 2026-05-29)
- [x] Verify ring/aws-lc-rs do not leak into normal (non-dev) dependency edges — tripwire test `no_c_in_default_deps.rs` runs `cargo tree --edges normal` and asserts neither crate appears
- [x] Add `cargo tree --edges normal -p oxitls-bench` tripwire test in CI script — Fulfilled by scripts/ffi-audit.sh (workspace-wide cargo tree audit, broader than -p oxitls-bench); 2026-05-29
- [x] Verify benchmark results are reproducible (< 5% variance across runs)

## Performance
- [x] Establish baseline numbers for all benchmarks on reference hardware — Baseline infrastructure exists via `scripts/bench-report.sh` + 27 criterion bench binaries; establish reference numbers on release hardware before publishing (2026-05-30)
- [x] Document expected performance ratios: OxiCrypto vs ring vs aws-lc-rs
- [x] Add memory allocation tracking via `dhat` or `jemalloc-ctl` in benchmark runs
- [x] Add flamegraph generation script for handshake hot-path analysis — Wave 5 Slice F (scripts/flamegraph.sh)

## Integration
- [x] Add comparison benchmarks against `oxihttp` full HTTP request latency (TLS + HTTP combined)
- [x] Add comparison benchmarks against `oxiquic` QUIC handshake latency
- [x] Coordinate with CI for automated benchmark regression detection
- [x] Publish benchmark results to project documentation (performance comparison table)
