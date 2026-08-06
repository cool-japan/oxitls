# Changelog

All notable changes to OxiTLS will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.1] - Unreleased

## [0.3.0] - 2026-08-06

### Fixed
- **OCSP staple false-rejection on leaf-only chains**: `OcspClientVerifier` no longer
  synthesises the end-entity certificate as its own issuer when the peer sends no
  intermediates. Previously, a CA-signed leaf presented with an empty intermediates list
  resolved the OCSP signer key to the leaf's own SPKI, turning a legitimate stapled
  response into an unconditional `BadSignature` handshake failure that even `SoftFail`
  could not escape. The end-entity is now only treated as its own issuer when it is
  structurally self-signed (`subject == issuer`); otherwise a missing issuer is reported
  as an unverifiable (`Unparseable`) staple, which policy correctly governs. See
  `end_entity_is_self_signed` in `oxitls-adapter-rustls-rustcrypto/src/verifier/ocsp_client.rs`.
- `labeled_expand` (RFC 9180 HPKE LabeledExpand, `oxitls-adapter-rustls-rustcrypto/src/hpke/kdf.rs`)
  no longer panics on a too-short PRK or an oversized output length — it now returns
  `Result` (delegating to the existing checked implementation) and every internal caller
  (`key_schedule_base`, `kem::extract_and_expand`, and all four `DhKem::encap`/`decap`
  implementations) propagates the error instead of aborting the process.

### Changed
- Cross-workspace `Cargo.lock` scope notes for `RUSTSEC-2026-0104`/-0099/-0098/-0049 (all
  four resolve to the same `rustls-webpki` 0.102.8 edge, reached only via the bench-only
  `oxihttp = "0.2.0"` dev-dependency pulling the published `oxitls` 0.2.0) and for
  `RUSTSEC-2023-0071` (Marvin/rsa timing side-channel, unreachable here — `rsa` is used
  only for signing/verification, never PKCS#1v1.5 decryption) are now documented and
  scoped in `deny.toml` `[advisories] ignore`, each with a written justification, so
  `cargo deny check advisories` passes.
- `deny.toml` `[bans] deny` entries for `ring` / `aws-lc-rs` / `aws-lc-sys` /
  `security-framework` now carry `wrappers` scoping their one intentional dev-only,
  bench-only, or quarantine-crate edge (`rcgen`, `oxitls-bench`, `oxicrypto-adapter-aws-lc`,
  `oxitls-adapter-aws-lc`, `oxitls-native-certs`) — any *new* normal-edge dependency on
  these crates still fails the gate, but the existing intentional edges no longer do, so
  `cargo deny check bans` passes.
- `oxitls-native-certs`'s `security-framework` and `schannel` dependencies are now gated
  under `[target.'cfg(target_os = "...")'.dependencies]` instead of being unconditional —
  a Linux (or any non-macOS/non-Windows) consumer of this opt-in quarantine crate no
  longer compiles both platforms' FFI shims for nothing.
- `sha2` (the 0.11 line) is now a single `workspace.dependencies` entry consumed via
  `sha2 = { workspace = true }` by all six call sites that previously pinned
  `sha2 = { version = "0.11", ... }` individually with slightly different feature sets
  (`oxitls`, `oxitls-adapter-rustls-rustcrypto` ×2, `oxitls-rcgen`, `oxitls-webpki-roots`,
  `oxitls-bench`). The deliberately-separate `sha2 = "0.10.7"` pin in the vendored
  `oxitls-rustcrypto-provider` fork is unchanged. `rand_core` (the 0.6 line, the
  getrandom-backed `OsRng` adapter's trait requirement) is likewise now a single
  `workspace.dependencies` entry consumed by `oxitls-core` via `rand_core = { workspace = true }`;
  the deliberately-separate, differently-featured `rand_core = "0.6.4"` pin in
  `oxitls-rustcrypto-provider` is unchanged.
- `post-quantum` feature doc comments (`crates/oxitls/Cargo.toml`,
  `crates/oxitls-adapter-rustls-rustcrypto/Cargo.toml`) corrected from "namespace
  reservation, full wiring deferred to Wave 6" to reflect that Wave 6 is complete and
  X25519MLKEM768 is fully wired (real encapsulate/decapsulate in `src/kx.rs`, selected by
  both `tls13::client::ClientBuilder` and `tls13::server::ServerBuilder`).
- `crates/oxitls-adapter-rustls-rustcrypto/TODO.md`: removed stale `[compile-blocked]`
  annotations on the three RFC 7250 raw-public-key integration tests
  (`tests/raw_public_keys.rs`) — they compile and pass cleanly under `--all-features`
  (verified: 3/3 tests green).
- `oxiarc-deflate`: 0.3.6 → 0.4.1.
- `oxicrypto-core` / `oxicrypto-adapter-aws-lc` (dev-dependency only — `oxitls-adapter-aws-lc`'s
  wave8 coexistence test and the `oxitls-bench` AEAD/handshake comparison benches): 0.2.1 →
  0.3.0. No production code path is affected (`Cargo.lock` is not committed in this workspace,
  per `.gitignore`; the bump is a `Cargo.toml` requirement change only).
- `p256` / `p384` (workspace-level, used by `oxitls-rcgen`): 0.14.0-rc.15 → 0.14.0 (stable
  release, dropping the release-candidate pin now that upstream has cut 0.14.0).

### Added
- Workspace-root `rustfmt.toml` and `clippy.toml` (msrv `"1.89"`, matching
  `rust-version` in the workspace `Cargo.toml`).
- Three new fuzz targets alongside the existing `client_config_parser`, covering oxitls's
  own hand-rolled, attacker-facing parsers rather than only the upstream `rustls-pemfile`
  surface: `sct_list_parser` (RFC 6962 §3.3 SCT list wire format), `precert_hash_parser`
  (RFC 6962 §3.2 precert_entry TBSCertificate reconstruction), and `ocsp_staple_parser`
  (end-to-end OCSP staple verification via the public `OcspClientVerifier` trait entry
  point, against a fixed valid cert pair with fuzzed staple bytes).
- Regression tests for the `labeled_expand` panic-to-`Result` conversion
  (`labeled_expand_short_prk_returns_err_not_panic`,
  `labeled_expand_oversized_l_returns_err_not_panic`) and for the leaf-only-chain OCSP fix
  (`self_signed_cert_detected_as_self_issuer`, `ca_signed_leaf_not_detected_as_self_issuer`,
  `garbage_cert_not_self_signed`, `no_issuer_no_delegated_signer_is_unparseable_not_badsignature`,
  `softfail_leaf_only_chain_does_not_hard_fail`,
  `hardrequire_leaf_only_chain_fails_as_unparseable_not_badsignature`).

---

## [0.2.1] - 2026-07-17

### Security
- **RUSTSEC-2026-0104** (rustls-webpki 0.102.x CRL-parsing panic) is eliminated from every
  normal (non-dev) oxitls dependency path. The `rustls-rustcrypto` workspace dependency now
  resolves to a new in-workspace crate, `oxitls-rustcrypto-provider` — an in-oxitls fork of
  `rustls-rustcrypto` 0.0.2-alpha with the `webpki` / `rustls-webpki` 0.102.x dependency
  removed entirely; certificate and signature algorithm identifiers are routed through
  `rustls-pki-types::alg_id` instead. (Scope note: `rustls` itself still uses the current,
  unaffected `rustls-webpki` 0.103.x for path validation — a different, non-CVE'd version.
  The vulnerable 0.102.x can still appear in *this workspace's* own `Cargo.lock` through the
  bench-only `oxihttp` dev-dependency, which transitively pulls the published `oxitls` 0.2.0;
  that dev/bench edge is not part of any downstream consumer's dependency graph and will clear
  once `oxihttp` publishes a release built against `oxitls` ^0.3.) The swap is transparent to callers: the workspace
  `Cargo.toml` renames the dependency
  (`rustls-rustcrypto = { package = "oxitls-rustcrypto-provider", ... }`), so
  `oxitls-adapter-rustls-rustcrypto` keeps compiling against the unchanged
  `rustls_rustcrypto::` extern name with no source or feature-flag changes required.
- **OCSP revocation-check hardening**
  (`oxitls-adapter-rustls-rustcrypto::verifier::ocsp_client`): `check_ocsp_staple` no longer
  accepts a `Good`/`Unknown` `SingleResponse` unless its `CertID` — `issuerNameHash`,
  `issuerKeyHash` (recomputed by the new `ocsp_digest`, covering id-sha1 / sha256 / sha384 /
  sha512 per RFC 6960 §4.1.1), and `serialNumber` — is matched against the certificate
  actually being verified and its issuer (new `cert_id_matches` / `evaluate_responses`).
  Previously every `SingleResponse` in a staple was scanned unconditionally, so a response
  containing no entry for the target certificate — or only entries for an unrelated
  certificate from the same issuer — still fell through to `OcspCheckResult::Good`. Freshness
  is now enforced as well: a matching `Good`/`Unknown` outside its `thisUpdate..=nextUpdate`
  window (new `single_response_is_current`) is rejected as stale, closing a replayed-response
  bypass; a matching `Revoked` stays authoritative regardless of freshness (fail-safe).
  Covered by 7 new unit tests, including a dedicated id-sha1 CertID regression pair.

### Added
- New crate **`oxitls-rustcrypto-provider`**: a complete Pure-Rust
  `rustls::crypto::CryptoProvider` (`oxitls_rustcrypto_provider::provider()`) carrying the
  RUSTSEC-2026-0104 fix described above. Supplies TLS 1.3 cipher suites (AES-128-GCM,
  AES-256-GCM, ChaCha20-Poly1305), optional TLS 1.2 ECDHE-ECDSA / ECDHE-RSA suites (`tls12`
  feature, on by default), X25519 / secp256r1 / secp384r1 key exchange, ECDSA / Ed25519 / RSA
  (PKCS#1v1.5 + PSS) signing and verification, and an RFC 9001 §5.4 QUIC header-protection
  module (`quic::HeaderProtectionKey`). Its RustCrypto dependency versions are intentionally
  pinned rather than workspace-shared to track the proven upstream fork exactly (e.g. it pins
  `p256`/`p384` 0.13.x while the rest of the workspace uses 0.14.0-rc.x for `oxitls-rcgen`).

### Changed
- `oxihttp` dev-dependency: 0.1.4 → 0.2.0.
- `oxiarc-deflate`: 0.3.3 → 0.3.6.
- `h2`: 0.4.14 → 0.4.15.
- `p256` / `p384` (workspace-level, used by `oxitls-rcgen`): 0.14.0-rc.9 → 0.14.0-rc.15.
- `getrandom`: 0.4.2 → 0.4.3.
- `aws-lc-rs` (bench/dev-only edge): 1.17.0 → 1.17.1.
- `oxicrypto-core` / `oxicrypto-adapter-aws-lc` (dev-dependency only — `oxitls-adapter-aws-lc`'s
  wave8 coexistence test and the `oxitls-bench` AEAD/handshake comparison benches): 0.2.0 →
  0.2.1. `Cargo.lock` re-resolved to match; no production code path is affected.
- `aes-gcm`: 0.10.3 → 0.11.0; `chacha20poly1305`: 0.10 → 0.11. Internal call sites in
  `oxitls::ticketer`, `oxitls-adapter-rustls-rustcrypto::hpke::aead`, and the `oxitls-bench`
  AEAD/handshake benchmarks were migrated from the deprecated `AeadInPlace` API to the new
  `AeadInOut` / `encrypt_inout_detached` API; no behavior change.
- New `sha1` workspace dependency (0.10, `oid` feature) added to
  `oxitls-adapter-rustls-rustcrypto`, used by the OCSP `CertID` hash recomputation above.
- All workspace-internal crate versions bumped to 0.2.1 in root `Cargo.toml`.

### Fixed
- `extract_sct_extension` (`oxitls-adapter-rustls-rustcrypto::verifier::sct`) now strips the
  nested DER `OCTET STRING` tag/length that RFC 6962 §3.3 wraps around the TLS-encoded
  `SignedCertificateTimestampList` before handing the bytes to `parse_sct_list` (new
  `strip_sct_octet_string`, handling both short- and long-form DER lengths). Previously the
  wrapper's leading `0x04 <len>` bytes were fed straight into the TLS-format parser as if
  they were its `u16` list-length prefix, so a certificate carrying a real, X.509-embedded
  SCT list extension always failed to parse — Certificate Transparency verification never saw
  a valid SCT via this path. Covered by 4 new unit tests.

---

## [0.2.0] - 2026-06-22

### Security
- Eliminates `security-framework-sys`, `core-foundation-sys`, and `windows-sys` from the
  transitive dependency closure under `--all-features`.  The FFI surface was leaking through
  the unconditional `native-roots` feature on `oxitls-webpki-roots` and through the `aws-lc`
  / `pkcs11` optional features on the `oxitls` facade, violating Pure Rust Policy v2 L1.
  This fix clears the violation for all downstream crates that depend on `oxitls` —
  including `oxihttp`, `oxiquic`, and `oxisql`.

### Added
- New `oxitls-native-certs` quarantine crate: provides OS-native certificate-store access
  via `Security.framework` (macOS) and `SChannel` (Windows).  Intentionally kept separate
  so the FFI boundary is explicit and opt-in.  Apps that need to load system trust anchors
  add `oxitls-native-certs` as a direct dependency; the rest of the `oxitls` workspace
  stays 100% Pure Rust.

### Removed
- `aws-lc` and `pkcs11` optional features removed from the `oxitls` facade `Cargo.toml`,
  along with the corresponding `dep:oxitls-adapter-aws-lc` / `dep:oxitls-adapter-pkcs11`
  optional dependencies and the `oxitls::aws_lc` re-export module.  Apps that need the
  aws-lc-rs or PKCS#11 providers must now depend on `oxitls-adapter-aws-lc` /
  `oxitls-adapter-pkcs11` directly.
- `native-roots` feature removed from `oxitls-webpki-roots` `Cargo.toml`.  The feature was
  a no-op gate: `security-framework` and `schannel` were always linked regardless of whether
  the feature was enabled.  The implementation (`native_roots.rs`, ~203 lines) and its
  `load_native_roots` re-export have been moved to `oxitls-native-certs`.
- Unconditional `tokio`, `security-framework`, and `schannel` dependencies removed from
  `oxitls-webpki-roots`; `tokio` dev-dependency also removed.

### Changed
- `oxitls-webpki-roots` is now Mozilla-roots-only: it provides `webpki-roots`-backed root
  stores, expiring-roots helpers, and the intermediate-cert cache — all without any
  platform-native or FFI dependency.
- Apps needing native CA trust anchors: add `oxitls-native-certs` and call
  `oxitls_native_certs::load_native_roots(...)` directly instead of
  `oxitls_webpki_roots::load_native_roots(...)`.
- Apps needing aws-lc-rs or PKCS#11 crypto: depend on `oxitls-adapter-aws-lc` or
  `oxitls-adapter-pkcs11` directly rather than enabling the (now-removed) facade features.

---

## [0.1.3] - 2026-06-19

### Changed
- All workspace-internal crate versions bumped to 0.1.3 in root `Cargo.toml`
  (`oxitls-core`, `oxitls-adapter-rustls-rustcrypto`, `oxitls-adapter-aws-lc`,
  `oxitls-adapter-pkcs11`, `oxitls-webpki-roots`, `oxitls`, `oxitls-h2`, `oxitls-rcgen`).
- `oxihttp` dev-dependency updated from 0.1.0 → 0.1.2 in workspace `Cargo.toml`.
- `oxihttp-server` dev-dependency in `oxitls-adapter-aws-lc` updated from 0.1.1 → 0.1.2
  (HTTPS integration test wave9 picks up latest oxihttp-server release).

### Fixed
- Doctest in `oxitls-adapter-aws-lc` corrected: bare `# {` / `# Ok::<(), String>(())`
  pattern replaced with `# fn example() -> Result<(), String>` / `# Ok(())` to satisfy
  rustdoc's typed-fn requirement and eliminate the rustdoc warning.

---

## [0.1.2] - 2026-06-10

### Added
- **Coexistence integration tests** (`oxitls-adapter-aws-lc`): activated the wave8 coexist
  test that proves `oxitls-adapter-aws-lc` and `oxicrypto-adapter-aws-lc` link and initialize
  cleanly in the same binary with zero symbol conflicts, now that `oxicrypto` 0.1.1 is
  published to crates.io. Two real tests replace the former placeholder:
  `both_aws_lc_crates_link_and_initialize_cleanly` and
  `sequential_use_of_both_crates_no_interference`.
- oxicrypto-adapter-aws-lc and oxicrypto-core added as dev-dependencies (registry, stripped
  on publish) to enable the real coexist tests.

### Changed
- Bumped `oxiarc-deflate` to 0.3.3 in workspace dependencies (Pure Rust policy, latest release).
- All workspace internal deps updated to 0.1.2 in `Cargo.toml`.
- `oxihttp-server` dev-dep in `oxitls-adapter-aws-lc` re-enabled at 0.1.1 (post-publish
  diamond dep resolved).

### Fixed
- Removed the `oxicrypto-coexist` placeholder feature and the `coexist_placeholder` no-op
  test that were blocking real coexist coverage.

## [0.1.1] - 2026-06-04

### Added

#### Encrypted Client Hello / HPKE (`oxitls-adapter-rustls-rustcrypto`, `oxitls`)
- Full RFC 9180 HPKE implementation (base mode) behind the `ech` feature flag, with two
  KEM variants (`KemX25519`, `KemP256`) and two AEAD suites (`AeadAes128Gcm`, `AeadChacha20`)
  — validated against known-answer test vectors.
- `generate_ech_config_list(suite, config_id, public_name, max_name_length)` — mints a
  spec-correct `ECHConfigList` (draft-ietf-tls-esni-18 / `0xfe0d`) with self-validation;
  re-exported from the `oxitls` facade as `oxitls::generate_ech_config_list`.
- `GeneratedEchConfig` struct exposing `config_list`, `private_key`, `public_key`, and
  `config_id` fields for deploy-ready ECH key management.
- `ClientBuilder::with_ech_config_list(bytes)` — enable real ECH with a raw `ECHConfigList`
  from a DNS HTTPS record (`ech` feature, implies `pure`).
- `ClientBuilder::with_ech_grease()` — enable RFC 8701 GREASE mode to prevent ECH extension
  ossification without a real server config.
- `OxiTlsStream::ech_status()` — inspect the ECH negotiation outcome on a client stream
  (`ech` feature).
- `EchConfig`, `EchGreaseConfig`, `EchMode`, `EchStatus` re-exported from `oxitls` under
  the `ech` feature for consumers who do not depend on `rustls` directly.

#### RFC 8879 Certificate Compression (`oxitls-adapter-rustls-rustcrypto`, `oxitls`)
- `OxiArcZlibCompressor` / `OxiArcZlibDecompressor` — zero-sized `rustls::CertCompressor` /
  `CertDecompressor` implementations backed by `oxiarc-deflate` (pure-Rust RFC 1950 zlib);
  map `Interactive` → level 1 and `Amortized` → level 9.
- `OXIARC_ZLIB_COMPRESSOR` / `OXIARC_ZLIB_DECOMPRESSOR` static references for direct use.
- `install_cert_compression_client(config)` / `install_cert_compression_server(config)` —
  convenience helpers that wire the OxiARC compressors into a `rustls` config in one call.
- `ClientBuilder::with_cert_compression()` / `ServerBuilder::with_cert_compression()` —
  high-level builder methods that activate RFC 8879 compression on the produced config
  (`cert-compression` feature, TLS 1.3 only).
- New `cert-compression` feature flag in both `oxitls-adapter-rustls-rustcrypto` and `oxitls`.
- New `ech` feature flag in `oxitls-adapter-rustls-rustcrypto` and `oxitls`.

#### PKCS#11 Hybrid Integration (`oxitls-adapter-aws-lc`)
- Real-HSM integration test `real_pkcs11_key_with_aws_lc_provider_succeeds` — exercises a
  full TLS 1.3 loopback handshake where the server's private key never leaves SoftHSM2 while
  `aws_lc_provider()` handles bulk crypto (marked `#[ignore]`; requires env vars).

#### PKCS#11 Benchmarks (`oxitls-adapter-pkcs11`)
- `bench_semaphore_acquire` and `bench_pool_sign_throughput` — hardware-free session-pool
  micro-benchmarks measuring `tokio::sync::Semaphore` acquire/release latency and concurrent
  P-256 sign throughput at pool capacities 1, 4, and 16.
- `bench_hsm_pool_acquire` — real HSM pool acquire bench (compiled under `pkcs11` feature;
  skipped gracefully when `SOFTHSM2_MODULE` is absent).
- `bench_sign_latency` and `bench_pool_contention` — software ECDSA-P256 baseline always
  measured; HSM variants active only with the `pkcs11` feature and `SOFTHSM2_MODULE` set.

#### Server Ticketer Rotation (`oxitls`)
- `ServerBuilder::with_ticketer_rotation_interval(duration)` — installs an `OxiTicketer`
  that spawns a background tokio task to rotate session-ticket keys on the given interval.

### Changed
- `p256` dependency: `ecdh` feature added (required by DHKEM P-256 in HPKE).
- `aes-gcm` dependency: `alloc` feature added (required by HPKE AEAD seal/open).
- `oxiarc-deflate 0.2` and `hkdf 0.13` added as optional workspace dependencies (used by
  `cert-compression` and `ech` features respectively).
- `oxitls-adapter-rustls-rustcrypto` and `oxitls-adapter-aws-lc` dev-dependencies restored
  post-publish: `oxitls-rcgen`, `oxihttp-server`, `oxitls-adapter-pkcs11` paths re-enabled.

### Fixed
- `clone_private_key_der` in `oxitls` client path now returns `Result<PrivateKeyDer, TlsError>`
  instead of panicking on unrecognised `PrivateKeyDer` variants (no-unwrap policy); all four
  `ClientBuilder::build()` call sites updated accordingly.

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
- 423 tests across all crates (--all-features)
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

[0.2.1]: https://github.com/cool-japan/oxitls/releases/tag/v0.2.1
[0.1.3]: https://github.com/cool-japan/oxitls/releases/tag/v0.1.3
[0.1.2]: https://github.com/cool-japan/oxitls/releases/tag/v0.1.2
[0.1.1]: https://github.com/cool-japan/oxitls/releases/tag/v0.1.1
[0.1.0]: https://github.com/cool-japan/oxitls/releases/tag/v0.1.0
