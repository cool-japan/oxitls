# OxiTLS TODO

## Status — v0.1.3 (work in progress)

Pure-Rust TLS transport stack at ~26 000 SLOC across 9 subcrates. All M0–M5
milestones and Waves 6–9 complete, plus ECH/HPKE (RFC 9180) and RFC 8879 cert compression added in v0.1.1.
**424 tests passing** (10 skipped — PKCS#11 SoftHSM + ignored ignores).

Release-check performed 2026-06-01 (v0.1.0):
- cargo check: PASS
- cargo clippy -- -D warnings: PASS (0 warnings)
- cargo nextest run: 324 passed, 2 skipped (PKCS#11 SoftHSM, `#[ignore]`)
- CHANGELOG.md: created
- README.md: updated to reflect v0.1.0 status
- Workspace Cargo.toml: all internal deps now have version = "0.1.0"
- RSA test fixtures: pre-generated keys added to avoid slow pure-Rust keygen
- nextest config: .config/nextest.toml with per-test timeouts

Release-check performed 2026-06-04 (v0.1.1):
- cargo nextest run --workspace --all-features: 423 passed, 10 skipped
- New features: ECH (RFC 9180 HPKE base-mode, ech feature), cert-compression (RFC 8879)
- Added RFC 9180 KAT vectors (Appendix A) in hpke/vectors.rs
- Added hybrid PKCS#11+aws-lc integration tests (wave10_hybrid_pkcs11.rs)
- Version bumped: Cargo.toml, CHANGELOG.md, pub_oxitls.sh, all subcrate READMEs

Release-check performed 2026-06-10 (v0.1.2):
- cargo fmt: PASS (no changes needed)
- cargo clippy --all-features --all-targets -- -D warnings: PASS (0 warnings)
- RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps: PASS (0 warnings)
- cargo nextest run --all-features: 424 passed, 10 skipped
- Activated wave8 coexist integration tests (oxitls + oxicrypto aws-lc-rs in one binary)
- oxiarc-deflate bumped to 0.3.3; oxicrypto-{adapter-aws-lc,core} added as dev-deps
- CHANGELOG.md, README.md, TODO.md version references updated to 0.1.2
- pub_oxitls.sh VERSION already at 0.1.2
- cargo publish --dry-run: expected-fail (0.1.2 deps not yet on crates.io)

Release-check performed 2026-06-19 (v0.1.3):
- cargo fmt --all: PASS (no changes needed)
- cargo clippy --all-features --all-targets -- -D warnings: PASS (0 warnings)
- RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps: PASS (0 warnings)
- cargo nextest run --all-features: 424 passed, 10 skipped
- cargo test --all-features --doc: PASS (all doc tests pass)
- oxihttp dev-dep bumped 0.1.0→0.1.2; oxihttp-server dev-dep bumped 0.1.1→0.1.2
- Doctest in oxitls-adapter-aws-lc fixed: fn-wrapper form for rustdoc typed-fn requirement
- CHANGELOG.md updated with 0.1.3 entry (dated 2026-06-19)
- pub_oxitls.sh VERSION=0.1.3, license header: Apache-2.0
- cargo publish --dry-run oxitls-core: PASS (cascade failures for dependents expected pre-publish)

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
- [x] Encrypted Client Hello (ECH) support behind feature flag (completed 2026-06-03)
  - **Goal:** `oxitls-adapter-rustls-rustcrypto` gains an `ech` feature exposing `pub fn pure_hpke_suites() -> &'static [&'static dyn rustls::crypto::hpke::Hpke]` backed by a hand-rolled RFC 9180 base-mode HPKE over RustCrypto primitives, covering 4 ECH suites (X25519/P-256 × AES-128-GCM/ChaCha20Poly1305), proven against RFC 9180 Appendix A KATs.
  - **Design:** New module `src/hpke/` split across `mod.rs` (rustls trait impls + suite statics), `kem.rs` (DHKEM Encap/Decap), `kdf.rs` (LabeledExtract/LabeledExpand, key schedule), `aead.rs` (Context seal/open, seq→nonce management), `vectors.rs` (KAT constants). KEM: X25519 via x25519-dalek StaticSecret, P-256 via p256 ECDH + rejection-sample keygen. KDF: hkdf 0.13 + sha2 0.11, raw LabeledExtract/Expand. AEAD: aes-gcm/chacha20poly1305 with caller-supplied 12-byte nonce. Entropy from getrandom::fill directly (no rand_core binding). New workspace dep: hkdf="0.13".
  - **Files:** `crates/oxitls-adapter-rustls-rustcrypto/src/hpke/{mod,kem,kdf,aead,vectors}.rs`, `src/lib.rs` (gated pub mod + re-export), `Cargo.toml` (ech feature), root `Cargo.toml` (workspace hkdf dep).
  - **Tests:** RFC 9180 A.1/A.2/A.3/A.5 KATs (byte-exact enc/key/base_nonce/ciphertext); round-trip seal/open; seq-overflow MUST-abort; X25519 non-contributory DH rejection; p256 off-curve/identity rejection.
  - **Risk:** hand-rolled crypto composition layer — mitigated by byte-exact KATs. Landmines: seq overflow MUST abort; nonce = base_nonce XOR I2OSP(seq,12); was_contributory() for X25519; suite_id/label byte-exactness; p256 0.14 API renames (to_uncompressed_point, from_sec1_bytes).
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
- [x] Activated wave8 coexist test (oxitls + oxicrypto aws-lc-rs in one binary, zero symbol conflicts) now that oxicrypto published 0.1.1; ported both real tests from oxicrypto and removed the `oxicrypto-coexist` marker feature. (done 2026-06-05)
- [x] PKCS#11 SoftHSM integration test (ignored by default)
- [x] OCSP RSA-2048 signer verification tests (using key fixture)
- [x] Total: 339 tests, 8 skipped (PKCS#11 SoftHSM + #[ignore] guards)

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
- [x] v0.1.1 release-check (2026-06-03): 339 tests, ECH/HPKE KATs, cert-compression, hybrid PKCS11+aws-lc, version bump
- [x] v0.1.2 release-check (2026-06-10): 424 passed, 10 skipped; wave8 coexist test activated; CHANGELOG/README/TODO finalized; dry-run expected-fail (deps not yet published)
