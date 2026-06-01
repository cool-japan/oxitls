# Changelog

All notable changes to OxiTLS will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-06-01

### Added

#### Core (`oxitls-core`)
- `TlsVersion`, `CipherSuite`, and `ConnectionInfo` types for connection metadata
- `OxiTlsStream<S>` wrapper bundling stream + connection info
- `TlsConnectionExt` trait for extracting version/suite/ALPN/peer certs
- `OsRng` adapter (getrandom-backed) for rand_core 0.6 compatibility with RSA/Ed25519/X25519
- Key logging support via `SSLKEYLOGFILE` environment variable
- Alert formatting via `alert.rs` module
- Generic transport GAT traits behind `generic-transport` feature flag

#### TLS Facade (`oxitls`)
- `ClientBuilder` with ALPN, SNI, session resumption, 0-RTT early data, client cert auth
- `ServerBuilder` with ALPN, SNI dispatch, mTLS, OCSP stapling, CRL checking
- Certificate pinning in both client and server paths
- `DangerZone` methods for testing: `accept_invalid_certs()`, `accept_invalid_hostnames()`
- Post-quantum key exchange (X25519MLKEM768) behind `post-quantum` feature flag
- TLS session keying material export
- `quic-preview` feature flag for QUIC TLS hooks

#### Pure Rust Adapter (`oxitls-adapter-rustls-rustcrypto`)
- Pure-Rust `CryptoProvider` backed by RustCrypto primitives (no ring, no aws-lc-rs)
- `pure_provider()` and `pure_provider_with_pq()` constructors
- `OcspClientVerifier` with SoftFail and HardRequire policies (RFC 6960)
- `SctClientVerifier` for Certificate Transparency log verification
- `CrlChecker` for Certificate Revocation List checking
- `CertPinner` for certificate pinning
- RSA PKCS#1 v1.5 (SHA-256) and ECDSA (P-256, P-384) OCSP signature verification
- Post-quantum X25519+ML-KEM-768 hybrid KX group (`post-quantum` feature)

#### FFI Adapters (opt-in, default-closed)
- `oxitls-adapter-aws-lc`: bounded FFI adapter for aws-lc-rs CryptoProvider (`aws-lc` feature)
- `oxitls-adapter-pkcs11`: HSM/TPM adapter via cryptoki PKCS#11 (`pkcs11` feature)
  - SoftHSM integration tests (marked `#[ignore]` by default)

#### Certificate Generation (`oxitls-rcgen`)
- Self-signed certificate generation for Ed25519, ECDSA-P256, ECDSA-P384, RSA-2048, RSA-4096
- CA certificate and intermediate CA generation
- CSR generation and signing
- Certificate chain building (`CertChainBuilder`)
- PKCS#12 (PFX) export
- `CertificateParamsBuilder` fluent API with SAN, EKU, name constraints, validity period
- `CertifiedKey::to_rustls_certified_key()` conversion
- Key usage and extended key usage helpers
- `OxiRsa2048Key::from_pkcs8_der` / `OxiRsa4096Key::from_pkcs8_der` for test fixtures
- `self_signed_from_rsa2048_key` / `self_signed_from_rsa4096_key` helpers

#### Root Store (`oxitls-webpki-roots`)
- `RootStoreBuilder` with filter, merge, and exclude operations
- Intermediate certificate cache (LRU-based, configurable capacity)
- Expiring roots support with configurable validity window
- Platform native certificate store support (`native-roots` feature, bounded FFI)
- WebPKI bundled root certificates via `webpki-roots`

#### HTTP/2 (`oxitls-h2`)
- Generic stream support (not hardcoded to `TcpStream`)
- `H2SettingsBuilder` for window size, frame size, and concurrent streams
- Concurrent streams stress tests (100 streams)
- Server push support
- HTTP/2 + TLS combined latency benchmarks

#### Benchmarks (`oxitls-bench`)
- TLS 1.2 / 1.3 handshake benchmarks
- Per-cipher-suite AEAD benchmarks (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305)
- Throughput benchmarks (1KB to 10MB payload sizes)
- mTLS handshake overhead benchmark
- SNI dispatch benchmark with many virtual hosts
- Certificate generation benchmarks (Ed25519, P-256, RSA-2048, RSA-4096)
- Ed25519 and P-256 sign/verify benchmarks vs ring and aws-lc-rs
- HTTP/2 over TLS combined latency benchmark
- Connection pool reuse amortization benchmark

### Milestones Completed
- M0: Workspace skeleton
- M1: TLS 1.3 client (rustls-rustcrypto, webpki-roots, no ring)
- M2: TLS 1.3 server + mTLS + ALPN + SNI
- M3: TLS 1.2 fallback + HTTP/2 binding + client session resumption
- M4: oxitls-rcgen (Pure cert-gen) + OxiTicketer + oxitls-bench
- M5: oxitls-adapter-aws-lc + oxitls-adapter-pkcs11 (bounded FFI, off default)
- Wave 6: Post-quantum X25519MLKEM768 hybrid KX group
- Wave 7: CRL distribution points, AIA/OCSP URL, extended EKU, name constraints
- Wave 8: Anti-replay for 0-RTT early data, key usage extensions
- Wave 9: OCSP stapling integration tests

### Test Coverage
- 324 tests across all crates
- Loopback handshake tests for all key types (Ed25519, P-256, P-384, RSA-2048, RSA-4096)
- 3-level CA chain validation tests
- CSR generation and signing round-trip tests
- PKCS#12 export/import round-trip tests
- OCSP stapling, SCT verification, CRL revocation tests
- 0-RTT anti-replay protection tests
- Certificate pinning match/mismatch tests
- Post-quantum key exchange smoke tests

### Notes
- Pure Rust by default; no ring, no aws-lc-rs, no OpenSSL on the default feature path
- RSA tests use pre-generated key fixtures to avoid slow keygen in pure Rust
- PKCS#11 tests require SoftHSM2 and are marked `#[ignore]` by default
- `oxitls-bench` has `publish = false` (internal benchmarking tool)

[0.1.0]: https://github.com/cool-japan/oxitls/releases/tag/v0.1.0
