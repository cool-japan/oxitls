# oxitls-adapter-aws-lc TODO

## Status
Feature-gated (`aws-lc` feature, default off) BOUNDED_FFI adapter providing an `aws-lc-rs` backed `rustls::crypto::CryptoProvider` via a single `aws_lc_provider()` function returning `Arc<CryptoProvider>`. The provider delegates to `rustls::crypto::aws_lc_rs::default_provider()`. Minimal implementation (~30 SLOC across lib.rs and provider.rs). Integration tests cover a TLS 1.3 handshake (loopback with rcgen self-signed cert) and a purity test verifying default features pull no C code.

## Core Implementation
- [x] Add `aws_lc_client_config(roots: RootCertStore) -> Result<ClientConfig, TlsError>` convenience builder that constructs a `ClientConfig` with the aws-lc-rs provider, safe default protocol versions, and the supplied root store (~30 SLOC)
- [x] Add `aws_lc_server_config(cert_chain: Vec<CertificateDer>, key: PrivateKeyDer) -> Result<ServerConfig, TlsError>` convenience builder pre-wired with the aws-lc-rs provider (~35 SLOC)
- [x] Add FIPS mode validation: `is_fips_mode() -> bool` checking `aws_lc_rs::fips::indicator()` or equivalent to confirm the aws-lc-rs build is running in FIPS-approved mode (~15 SLOC)
- [x] Add custom `CryptoProvider` construction: `aws_lc_provider_with_cipher_suites(suites: &[SupportedCipherSuite]) -> Arc<CryptoProvider>` for restricting TLS cipher suites to a FIPS-approved subset (~40 SLOC)
- [x] Add TLS 1.2-only provider variant: `aws_lc_provider_tls12_only()` that restricts protocol versions to TLS 1.2 for legacy compatibility requirements (~25 SLOC)
- [x] Add mTLS helper: `aws_lc_mtls_client_config(client_cert, client_key, roots) -> Result<ClientConfig, TlsError>` for mutual TLS authentication scenarios (~40 SLOC)
- [x] Add session ticket key rotation: `AwsLcTicketRotator` implementing `rustls::server::ProducesTickets` with periodic key rotation using aws-lc-rs HKDF (~80 SLOC)

## API Improvements
- [x] Add `TlsError` conversion from `rustls::Error` to `oxitls_core::TlsError` for all builder functions, avoiding the `.unwrap()` in the current doc example (~20 SLOC) — `rustls_error_to_tls_error()` free function in `error.rs`; doc example updated to use `map_err`
- [x] Add `AwsLcTlsProvider` struct wrapping the `Arc<CryptoProvider>` with methods for client/server config construction, acting as a one-stop TLS setup object (~50 SLOC) — `src/provider_type.rs`
- [x] Add feature detection: `supported_cipher_suites() -> Vec<String>` and `supported_kx_groups() -> Vec<String>` for runtime introspection of available algorithms (~25 SLOC) — free functions in `lib.rs`
- [x] Add `Debug` impl for the provider wrapper that lists enabled cipher suites and protocol versions (~20 SLOC) — `impl Debug for AwsLcTlsProvider` in `src/provider_type.rs`

## Testing
- [x] Add TLS 1.2 handshake test: verify client-server handshake completes with TLS 1.2 protocol version (~50 SLOC, similar to existing TLS 1.3 handshake test)
- [x] Add mTLS handshake test: client authenticates with a client certificate, server verifies it (~70 SLOC with rcgen client+server certs)
- [x] Add cipher suite restriction test: construct provider with only AES-256-GCM suites, verify handshake uses only that suite (~40 SLOC)
- [x] Add provider parity test: compare `aws_lc_provider()` cipher suite list against `oxitls-adapter-rustls-rustcrypto` provider to document differences (~30 SLOC)
- [x] Add certificate chain validation test: multi-level CA chain (root -> intermediate -> leaf) handshake (~60 SLOC)
- [x] Add ALPN negotiation test: server offers h2+http/1.1, client prefers h2, verify negotiated protocol (~35 SLOC)
- [x] Add error path tests: expired certificate, wrong hostname, self-signed without trust anchor (~45 SLOC)
- [x] Add FIPS indicator test: when `aws-lc` feature is enabled, verify `is_fips_mode()` returns expected value (~15 SLOC)

## Performance
- [x] Add criterion benchmarks: TLS 1.3 handshake latency (full handshake + resumed) vs Pure Rust rustcrypto provider (~80 SLOC)
- [x] Add criterion benchmarks: bulk data transfer throughput (1MB/10MB) through an aws-lc-rs TLS connection (~60 SLOC)
- [x] Add criterion benchmarks: CryptoProvider construction cost (one-shot vs cached Arc) (~25 SLOC)

## Integration
- [x] Wire into `oxitls` facade: re-export `aws_lc_provider` under `oxitls::fips::provider()` or `oxitls::aws_lc::provider()` behind `aws-lc` feature (~15 SLOC) — Wave 8 (`oxitls::aws_lc::provider()` + `AwsLcTlsProvider` added); 2026-05-29
- [x] Add integration with `oxicrypto-adapter-aws-lc`: verify shared `aws-lc-rs` dependency links cleanly when both crates are enabled in the same binary (~20 SLOC link test) — Empirically verified 2026-05-29 (no symbol conflicts, aws-lc-rs 1.17.0 deduped); permanent dev-dep blocked until oxicrypto publishes to a registry (currently unpublished v0.0.0 workspace). Test scaffold with full activation instructions created at `tests/wave8_coexist.rs`. **Activated 2026-06-04**: `oxicrypto-adapter-aws-lc = "0.1.1"` dev-dep added; `tests/wave8_coexist.rs` exercises both crates in one binary — 2 tests pass, zero symbol conflicts confirmed.
- [x] Add integration test with `oxihttp` (if it exists): establish HTTPS connection using aws-lc-rs provider, fetch a resource, verify TLS version in response (~50 SLOC) — Wave 9: `tests/wave9_https.rs`; oxihttp server backed by `TlsConfig::new(aws_lc_server_config(...))`, raw hyper+tokio-rustls client backed by `aws_lc_client_config`; asserts TLS 1.3 + 200 OK; 2026-05-29
- [x] Add integration with PKCS#11 HSM-backed TLS server key (private key on HSM, aws-lc-rs for bulk encryption) (done 2026-06-02)
  - **Goal:** A real `Pkcs11SigningKey` (SoftHSM2-backed) drives the server's `CertificateVerify` while `aws_lc_provider()` does bulk crypto, replacing the stand-in P-256 signer in `tests/wave10_hybrid_pkcs11.rs`.
  - **Design:** Extend `tests/wave10_hybrid_pkcs11.rs` — keep the always-on stand-in test; add an `#[ignore]` integration test gated on `SOFTHSM2_MODULE`/`SOFTHSM2_SLOT`/`SOFTHSM2_PIN`/`SOFTHSM2_KEY_LABEL`/`SOFTHSM2_CERT_LABEL` env vars (graceful early-return when unset). Builds `Pkcs11TlsProvider::new(module,slot,pin)` → `signing_key(label)` → `ServerConfig::builder_with_provider(aws_lc_provider()).with_cert_resolver(...)`, runs a loopback TLS 1.3 handshake, asserts success. Adds `oxitls-adapter-pkcs11` as a dev-dependency of this crate (dev-only, pkcs11 doesn't dep aws-lc, no publish-cycle concern).
  - **Files:** `crates/oxitls-adapter-aws-lc/tests/wave10_hybrid_pkcs11.rs`, `crates/oxitls-adapter-aws-lc/Cargo.toml` (add oxitls-adapter-pkcs11 as dev-dep with features=[pkcs11,aws-lc-bridge]).
  - **Tests:** The `#[ignore]` HSM hybrid test; CI/no-HSM path stays green via graceful skip.
  - **Risk:** Cross-crate dev-dep — ensure it doesn't perturb the default feature build. Whole test file already gated `#[cfg(feature="aws-lc")]`.

## Proposed follow-ups

- [x] **oxicrypto-adapter-aws-lc coexist link-test** (done 2026-06-04): Both aws-lc-rs adapters
  (oxitls + oxicrypto) are now **actively tested** in one binary via `tests/wave8_coexist.rs`
  (gated behind the `aws-lc` feature). The link-cleanliness check — aws-lc-rs 1.17.0 deduped,
  zero symbol conflicts — was previously only empirically verified (2026-05-29) and deferred as a
  stub because oxicrypto was unpublished. Now that oxicrypto publishes `0.1.1` to crates.io, the
  registry dev-dependencies `oxicrypto-adapter-aws-lc = { version = "0.1.1", features = ["aws-lc"] }`
  and `oxicrypto-core = { version = "0.1.1" }` are added (dev-deps are stripped on publish, so this
  is safe for the already-released crate, with no cross-workspace path/git dep). The earlier
  `oxicrypto-coexist` marker feature is removed.
