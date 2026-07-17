# oxitls-bench — OxiTLS benchmark suite

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

`oxitls-bench` is the benchmark crate for the OxiTLS ecosystem. It measures handshake latency and throughput, AEAD / signature / digest primitive performance, certificate generation, OCSP stapling overhead, session-ticket rotation, HTTP/2-over-TLS data transfer, and full HTTPS request latency — exercising the Pure-Rust stack end to end (`oxitls` + `oxitls-adapter-rustls-rustcrypto` + `oxitls-rcgen` + `oxitls-webpki-roots` + `oxitls-h2`).

Where a meaningful comparison exists, the primitive benchmarks (AEAD, signatures, SHA-256) place the Pure-Rust **OxiCrypto / RustCrypto** implementations side by side with **`ring`** and **`aws-lc-rs`** as reference baselines. Those two comparison crates are **`dev-dependencies` only** — they never appear on the `oxitls` library edge, keeping the production closure 100% Pure Rust. This crate is **not published** (`publish = false`).

## Installation

`oxitls-bench` is an internal workspace member, not a library you depend on. Run it from a checkout of the `oxitls` workspace.

## Quick Start

```bash
# Run the whole benchmark suite.
cargo bench -p oxitls-bench

# Run a single benchmark target.
cargo bench -p oxitls-bench --bench handshake

# Compile-only gate (fast CI check, no measurement).
cargo bench -p oxitls-bench --no-run

# Heap-allocation profiling (writes dhat-heap.json).
cargo bench -p oxitls-bench --features dhat-heap --bench allocations
```

All targets use [`criterion`] (`harness = false`).

## Benchmark Targets

### Handshake & resumption

| Target | Measures |
|--------|----------|
| `handshake` | TLS 1.3 full + resumed (OxiTicketer) handshake throughput, plus AES-256-GCM 1 KiB encrypt across OxiCrypto / ring / aws-lc-rs |
| `tls12_handshake` | TLS 1.2 full handshake vs TLS 1.3, quantifying protocol-version overhead |
| `tls12_handshake_resumed` | TLS 1.2 session-ID resumed handshake (cheap path vs full) |
| `zero_rtt_handshake` | 0-RTT resumed (OxiTicketer) handshake latency vs a fresh TLS 1.3 full handshake |
| `connector_cold_start` | `connector_with_webpki_roots()` cold-start vs cached (`Arc::clone`) cost |
| `builder_construction` | `ClientBuilder` / `ServerBuilder` `build()` cost (provider + root-store setup) |
| `connection_pool` | Pool "hit" (`Arc::clone` of a config) vs "cold build" of a fresh `ClientConfig` |
| `early_data` | `ClientBuilder::with_early_data()` and `ServerBuilder::with_max_early_data_size()` construction overhead vs baseline `build()` |

### Cryptographic primitives (vs ring / aws-lc-rs)

| Target | Measures |
|--------|----------|
| `aead` | AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 for a 1 KiB payload, across three providers |
| `aead_per_suite` | The same three AEADs across three payload sizes (1 KiB / 16 KiB / 256 KiB) and three providers |
| `sig` | Sign + verify for Ed25519, ECDSA-P256, ECDSA-P384, RSA-2048 (PKCS#1 v1.5 / SHA-256), pure Rust |
| `digest` | SHA-256 across providers (sha2 / OxiCrypto, ring, aws-lc-rs) at 1 KiB / 64 KiB / 1 MiB |

### Data transfer

| Target | Measures |
|--------|----------|
| `throughput` | Bidirectional TLS 1.3 data transfer for 1 KB / 64 KB / 1 MB / 10 MB payloads (in-memory) |
| `h2_over_tls` | TLS 1.3 handshake completion with ALPN = `h2` (TLS layer isolated from H2 framing) |
| `h2_tls_throughput` | End-to-end single-stream HTTP/2 data throughput over a TLS 1.3 loopback |
| `http_latency` | Full HTTPS request latency (TCP connect + TLS + HTTP) using `oxihttp`, payloads 1 B / 1 KB / 64 KB |

### Negotiation, mTLS & metadata

| Target | Measures |
|--------|----------|
| `alpn_sni` | ALPN negotiation latency (h2 + http/1.1) and SNI dispatch with 1 / 10 / 100 vhost certs |
| `mtls` | Client-certificate presentation + `WebPkiClientVerifier` overhead |
| `connection_info_extract` | Cost of `tls_connection_info()` extraction from an established TLS 1.3 stream |
| `keying_material_export` | Cost of `OxiTlsStream::export_keying_material` on an established connection |

### Certificate generation

| Target | Measures |
|--------|----------|
| `cert_gen` | Ed25519 / P-256 / RSA-2048 / RSA-4096 self-signed cert generation (via `oxitls-rcgen`) |

### OCSP stapling

| Target | Measures |
|--------|----------|
| `ocsp_resolver_dispatch` | `StaticOcspResolver::resolve` dispatch + server `build()` cost with an OCSP resolver installed |
| `ocsp_stapling_overhead` | TLS 1.3 handshake overhead: no staple vs empty staple vs non-empty static staple |

### Session tickets (OxiTicketer)

| Target | Measures |
|--------|----------|
| `oxiticketer_encrypt` | OxiTicketer encrypt micro-benchmarks |
| `oxiticketer_rotation` | OxiTicketer creation + full encrypt/decrypt round-trip |
| `ticketer_rotation_contention` | Encrypt throughput under concurrent access (4 tasks), with an explicit mid-flight `rotate()` variant |

### Allocation profiling

| Target | Measures |
|--------|----------|
| `allocations` | Heap bytes allocated while constructing the primary builder / ticketer types (gate on `--features dhat-heap`) |

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `dhat-heap` | off | Installs `dhat` as the `#[global_allocator]` for heap profiling (writes `dhat-heap.json`) |

## Cross-references

- **`oxitls`** — the façade under benchmark (built with `pure`, `rcgen`, `webpki-roots`).
- **`oxitls-adapter-rustls-rustcrypto`** — the Pure-Rust provider exercised by the handshake/throughput benches.
- **`oxitls-rcgen`** — certificate generation used by `cert_gen` and the handshake setup.
- **`oxitls-webpki-roots`** — root store used by the connector benches.
- **`oxitls-h2`** — HTTP/2 layer exercised by `h2_over_tls` / `h2_tls_throughput`.
- **`oxitls-core`** — supplies the `OsRng` adapter used by the RSA signature bench.

## License

Apache-2.0 — COOLJAPAN OU (Team Kitasan)
