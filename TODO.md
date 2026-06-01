# OxiTLS TODO

## Status — v0.1.0 (released 2026-06-01)

Pure-Rust TLS transport stack at ~4300 SLOC across 9 subcrates. All M0–M5
milestones and Waves 6–9 complete. 324 tests passing.

Release-check performed 2026-06-01:
- cargo check: PASS
- cargo clippy -- -D warnings: PASS (0 warnings)
- cargo nextest run: 324 passed, 2 skipped (PKCS#11 SoftHSM, `#[ignore]`)
- CHANGELOG.md: created
- README.md: updated to reflect v0.1.0 status
- Workspace Cargo.toml: all internal deps now have version = "0.1.0"
- RSA test fixtures: pre-generated keys added to avoid slow pure-Rust keygen
- nextest config: .config/nextest.toml with per-test timeouts

## Core Implementation
- [x] 0-RTT early data support in ClientBuilder and ServerBuilder (~200 SLOC)
- [x] OCSP stapling: server-side response injection and client-side verification (~160 SLOC)
- [x] Certificate Transparency (SCT) verification on client side (~100 SLOC)
- [x] SSLKEYLOGFILE / key logging for Wireshark debugging (~60 SLOC)
- [x] Client certificate authentication via ClientBuilder (~40 SLOC)
- [x] CRL (Certificate Revocation List) checking in adapter and facade (~150 SLOC)
- [x] Certificate pinning in adapter and facade (~230 SLOC)
- [x] RSA-2048 and RSA-4096 key support in oxitls-rcgen (~250 SLOC)
- [x] ECDSA P-384 key support in oxitls-rcgen (~120 SLOC)
- [x] CA certificate and intermediate CA generation in oxitls-rcgen (~180 SLOC)
- [x] CSR generation and signing in oxitls-rcgen (~180 SLOC)
- [x] Certificate chain building in oxitls-rcgen (~120 SLOC)
- [x] PKCS#12 export in oxitls-rcgen (~100 SLOC)
- [ ] Encrypted Client Hello (ECH) support behind feature flag (blocked on rustls ECH API stabilisation)
- [x] Post-quantum key exchange (X25519MLKEM768) behind feature flag (Wave 6 — 2026-05-29)
- [x] Connection info extraction trait for version/suite/ALPN/peer certs (~80 SLOC)
- [x] TLS session export / keying material export (~40 SLOC)
- [x] oxitls-adapter-aws-lc: bounded-FFI adapter for aws-lc-rs CryptoProvider (~300 SLOC)
- [x] oxitls-adapter-pkcs11: HSM/TPM adapter via cryptoki PKCS#11 (~400 SLOC)
- [x] Generic stream type support in oxitls-h2 (not hardcoded to TcpStream) (~60 SLOC)
- [x] H2 settings builder for window size, frame size, concurrent streams (~100 SLOC)
- [x] Root store builder with filtering, merging, and native roots (~200 SLOC)
- [x] Intermediate certificate caching in webpki-roots (~300 SLOC)
- [x] `OxiRsa2048Key::from_pkcs8_der` / `OxiRsa4096Key::from_pkcs8_der` for test fixtures (2026-06-01)
- [x] `self_signed_from_rsa2048_key` / `self_signed_from_rsa4096_key` API helpers (2026-06-01)

## API Improvements
- [x] `TlsVersion`, `CipherSuite`, and `ConnectionInfo` types in oxitls-core
- [x] Builder validation with descriptive error messages on missing fields
- [x] Danger methods for testing: `accept_invalid_certs()`, `accept_invalid_hostnames()`
- [x] `OxiTlsStream<S>` wrapper bundling stream + connection info
- [x] `CertifiedKey::to_rustls_certified_key()` conversion in oxitls-rcgen
- [x] `CertificateParamsBuilder` fluent API in oxitls-rcgen
- [x] `RootStoreBuilder` in oxitls-webpki-roots with filter/merge/exclude

## Testing
- [x] 0-RTT early data send and replay protection tests — Wave 8 (wave8_anti_replay.rs)
- [x] OCSP stapling integration test — Wave 9 (wave9_ocsp.rs)
- [x] SSLKEYLOGFILE output format validation
- [x] CRL-revoked cert rejection test
- [x] Certificate pinning match/mismatch tests
- [x] RSA-2048 and P-384 loopback handshake tests (using key fixtures for speed)
- [x] RSA-4096 loopback handshake test (using key fixture — was timing out in pure Rust)
- [x] CA chain validation tests (root -> intermediate -> leaf)
- [x] CSR generation and signing round-trip test
- [x] H2 concurrent streams stress test (100 streams)
- [x] H2 server push test
- [x] Root store filtering and merging tests
- [x] aws-lc adapter handshake test (cross-provider client/server)
- [x] PKCS#11 SoftHSM integration test (ignored by default)
- [x] OCSP RSA-2048 signer verification tests (using key fixture)
- [x] Total: 324 tests, 2 skipped (PKCS#11 SoftHSM)

## Performance
- [x] TLS 1.2 handshake benchmarks in oxitls-bench
- [x] Per-cipher-suite AEAD benchmarks (AES-128-GCM, ChaCha20-Poly1305)
- [x] Throughput benchmarks (1KB to 10MB payload sizes)
- [x] mTLS handshake overhead benchmark
- [x] SNI dispatch benchmark with many virtual hosts
- [x] Certificate generation benchmarks (Ed25519, P-256, RSA-2048, RSA-4096)
- [x] Ed25519 and P-256 sign/verify benchmarks vs ring and aws-lc-rs
- [x] HTTP/2 over TLS combined latency benchmark
- [x] Connection pool reuse amortization benchmark
- [x] Flamegraph generation for handshake hot path

## Integration
- [x] Wire TLS into oxihttp-client for HTTPS connections
- [x] Wire TLS into oxihttp-server for HTTPS listener
- [x] Wire QUIC TLS hooks into oxiquic-tls via `quic-preview` feature flag
- [x] Provide oxihttp with `ServerBuilder` defaults for HTTP/2 (ALPN h2)
- [x] Coordinate key logging with oxihttp for Wireshark HTTP debugging
- [x] Replace rcgen dev-dep in oxihttp/oxiquic tests with oxitls-rcgen

## Milestones
- [x] M0: Workspace skeleton
- [x] M1: TLS 1.3 client (rustls-rustcrypto, webpki-roots, no ring)
- [x] M2: TLS 1.3 server + mTLS + ALPN + SNI
- [x] M3: TLS 1.2 fallback + HTTP/2 binding + client session resumption
- [x] M4: oxitls-rcgen (Pure cert-gen) + OxiTicketer + oxitls-bench
- [x] M5: oxitls-adapter-aws-lc + oxitls-adapter-pkcs11 (bounded FFI, off default)
- [x] Wave 6: Post-quantum X25519MLKEM768 hybrid KX group
- [x] Wave 7: CRL distribution points, AIA/OCSP URL, extended EKU, name constraints
- [x] Wave 8: Anti-replay for 0-RTT early data, key usage extensions
- [x] Wave 9: OCSP stapling integration tests
- [x] v0.1.0 release-check (2026-06-01): all tests green, CHANGELOG, README, LICENSE, doc fixes, publish dry-run
