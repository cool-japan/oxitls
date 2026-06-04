# oxitls-adapter-pkcs11 TODO

## Status

Core signing scaffold is implemented (~290 SLOC across `src/`). The `pkcs11`
feature gate pulls in the `cryptoki` crate (PKCS#11 v2.40 Rust bindings).

**Already implemented:**
- `Pkcs11SigningKey` implementing `rustls::sign::SigningKey` (signer.rs)
- `Pkcs11Signer` implementing `rustls::sign::Signer` for ECDSA-P256/P384 and
  RSA-PKCS1 / RSA-PSS-SHA{256,384,512} (signer.rs)
- ECDSA raw r||s → DER/ASN.1 conversion helper (signer.rs)
- `session.rs`: `open_user_session`, `find_private_key_by_label`, `probe_key_type`
- `error.rs`: `PkcsSignError` with Display/Error impls
- `tests/softhsm.rs`: headless error-type test + `#[ignore]` SoftHSM2 round-trip test

**Not yet implemented:**
- `Pkcs11ServerCertResolver` (reads CKO_CERTIFICATE objects and pairs with signing key)
- `Pkcs11TlsProvider` convenience builder (`new(lib_path, slot, pin)` → `ServerConfig`)
- Session pool for concurrent TLS handshakes
- `oxitls` facade re-export behind `pkcs11` feature flag

## Design Questions (resolve before implementation)

- PKCS#11 v2.40 vs v3.0: `cryptoki` 0.12 covers v2.40; v3.0 adds protected auth paths
  and Profiles. Decision: target v2.40 for broadest HSM compatibility; v3.0 features
  gated separately.
- Session pool: synchronous PKCS#11 calls on multiple threads require separate sessions.
  Use an `Arc<Mutex<Vec<Session>>>` pool or per-thread sessions via `thread_local!`.
- Login policy: `USER_PIN` vs `CKU_CONTEXT_SPECIFIC` for protected-authentication-path
  HSMs. Expose as `LoginMode::Pin(SecretString)` vs `LoginMode::ProtectedPath`.
- RSA-PSS: currently falls back to `Sha{256,384,512}RsaPkcs` — needs
  `RsaPkcsPss` mechanism with explicit salt-length params for true PSS signing.
- Test strategy: SoftHSM2 (C library, separate process) vs a Pure-Rust PKCS#11 mock.
  SoftHSM2 requires system-level installation; prefer a mock for CI portability.

## Core Implementation

- [x] `oxitls-adapter-pkcs11` — promote from skeleton to production: fix RSA-PSS mechanism mismatch in existing signer, add `Pkcs11ServerCertResolver`, `Pkcs11SessionPool`, `Pkcs11TlsProvider` one-stop builder, `SecretString` PIN wrapping, integration tests against SoftHSM2 (`#[ignore]`-gated for CI), `pkcs11_bench.rs`, and `#[cfg(feature = "pkcs11")] pub mod pkcs11` re-export in the `oxitls` facade (planned 2026-05-27)
  - **Goal:** the PKCS#11 adapter delivers a complete HSM-backed TLS server stack — caller passes module path + slot + PIN → `Pkcs11TlsProvider::server_config(chain_label, key_label)` returns a `rustls::ServerConfig` whose private-key operations transparently route to the HSM via a bounded session pool. RSA-PSS works correctly (current `signer.rs` mismatches mechanism vs. hash); RSA-PKCS1v1.5 and ECDSA-P256/P384 are also covered.
  - **Design:**
    1. **RSA-PSS fix** in `src/signer.rs`: dispatch to `Mechanism::RsaPkcsPss(PkcsPssParams{hash_alg, mgf, s_len})` for `RSA_PSS_SHA256/384/512`; split `sign()` into `sign_rsa_pkcs1v15`, `sign_rsa_pss`, `sign_ecdsa` private methods.
    2. **`Pkcs11ServerCertResolver`** (new `src/resolver.rs` ~150 SLOC): impl `rustls::server::ResolvesServerCert`; holds `Arc<CertifiedKey>` built at construction from PKCS#11-loaded cert chain + `Pkcs11SigningKey`. Single-cert resolver (SNI dispatch is Wave 5).
    3. **`Pkcs11SessionPool`** (new `src/pool.rs` ~200 SLOC): bounded `VecDeque<Session>` behind `parking_lot::Mutex` + `tokio::sync::Semaphore`; `PooledSession` RAII wrapper.
    4. **`Pkcs11TlsProvider`** (new `src/provider.rs` ~120 SLOC): `new(module_path, slot_index, pin: SecretString)` → `server_config(chain_label, key_label) -> Result<ServerConfig, Pkcs11Error>`.
    5. **`SecretString` PIN**: replace `String` in public API with `secrecy::SecretString`; expose only at `Session::login` call.
    6. **Facade re-export**: `#[cfg(feature = "pkcs11")] pub mod pkcs11 { pub use oxitls_adapter_pkcs11::*; }` in `crates/oxitls/src/lib.rs`; optional dep + feature entry in `crates/oxitls/Cargo.toml`.
  - **Files:** `src/signer.rs` (modify), new `src/{resolver,pool,provider}.rs`, `src/lib.rs` (register mods), `Cargo.toml` (secrecy + parking_lot workspace deps), `crates/oxitls/src/lib.rs` + `crates/oxitls/Cargo.toml` (facade re-export); new `tests/pkcs11_integration.rs` + `benches/pkcs11_bench.rs`.
  - **Prerequisites:** cryptoki 0.12 (already workspace dep); add secrecy = "0.10", parking_lot = "0.12" to workspace Cargo.toml.
  - **Tests:** 5 integration tests (#[ignore]-gated on SOFTHSM2_MODULE env var): session_pool_roundtrip, signer_rsa_pss_sha256, signer_rsa_pkcs1v15, signer_ecdsa_p256, tls_provider_loopback_handshake; 1 bench: pkcs11_signer_throughput.
  - **Risk:** SoftHSM2 not in CI — guard via `#[ignore]` + env check. cryptoki 0.12 PkcsPssParams field names to verify. Session pool deadlock check: permit acquired before pop.

- [x] Fix RSA-PSS signing: replace `Sha{256,384,512}RsaPkcs` fallback with
  `Mechanism::RsaPkcsPss` + correct `PkcsRsaPssParams` (salt length = hash length).
  (~30 SLOC in `signer.rs`)
- [x] Add `Pkcs11ServerCertResolver` implementing `rustls::server::ResolvesServerCert`
  that reads the certificate chain from PKCS#11 token objects (`CKO_CERTIFICATE`) and
  pairs them with a `Pkcs11SigningKey`. (~150 SLOC, new `src/resolver.rs`)
- [x] Add `Arc<Mutex<SessionPool>>` for concurrent TLS handshakes — each handshake
  needs a separate PKCS#11 session for thread safety. (~100 SLOC, new `src/pool.rs`)
- [x] Add `Pkcs11TlsProvider` convenience struct: `new(lib_path, slot, pin)` exposes
  `server_config(cert_label, key_label, alpn) -> Result<rustls::ServerConfig, TlsError>`.
  (~100 SLOC, new `src/provider.rs`)

## API Improvements

- [x] Add `Pkcs11TlsProvider::list_keys(label_filter: Option<&str>) -> Vec<Pkcs11KeyInfo>`
  for key enumeration (~50 SLOC)
- [x] Add `Pkcs11TlsProvider::import_cert(der: &[u8], label: &str)` for injecting certs
  onto the token — useful for bootstrap (~80 SLOC)
- [x] Add `From<cryptoki::error::Error> for Pkcs11Error` mapping — three new variants
  (`HsmError`, `Unsupported`, `LoadFailed`) plus catch-all `Other` (~60 SLOC in `error.rs`)
- [x] Replace raw `String` PIN storage in `Pkcs11SigningKey` / `Pkcs11Signer` with
  `secrecy::SecretString` to avoid PIN leakage in Debug output

## Testing

- [x] Test: `Pkcs11SigningKey::sign()` ECDSA round-trip with a Pure-Rust PKCS#11 mock
  (evaluate `pkcs11-mock` crate or hand-roll a minimal in-process mock) (~80 SLOC)
- [x] Test: `Pkcs11ServerCertResolver::resolve()` SNI dispatch correctness verified
  via `sni_dispatch_correct_variant` in `tests/pkcs11_hardening.rs`
- [x] Test: session pool handles N=4 concurrent signing requests without deadlock
  (N=4 tokio tasks each calling `sign()`) (~80 SLOC)
- [x] Test: full TLS 1.3 server handshake with `Pkcs11TlsProvider` (loopback, SoftHSM2)
  — `#[ignore]`-gated in `tests/pkcs11_hardening.rs::full_tls13_handshake_with_pkcs11_server`
- [x] Test: `Pkcs11Session::login_logout` cycle does not leak PKCS#11 sessions (~30 SLOC)

## Performance

- [x] Benchmark harness: `benches/pkcs11_perf.rs` registered in Cargo.toml; skips
  gracefully without SoftHSM2
- [x] Benchmark PKCS#11 sign latency vs software key sign (HSM adds RTT over PKCS#11 IPC; measure baseline with SoftHSM2 on loopback) (planned 2026-06-02)
  - **Goal:** Real criterion bench in `benches/pkcs11_perf.rs` (group 1) replacing the no-op stub. Always-measured software ECDSA-P256 baseline; HSM path when `SOFTHSM2_MODULE` is set (graceful skip otherwise).
  - **Design:** Software baseline: p256 dev-dep (`SigningKey::sign_prehash`), same pattern as wave10 `TestP256Signer`. HSM path: `Pkcs11SessionPool::new` → `Pkcs11SigningKey::new` → `choose_scheme` → `sign`. Optionally also a `MockSigningBackend` micro-bench for PKCS#11 dispatch overhead without hardware. Log what is skipped (no silent caps).
  - **Files:** `crates/oxitls-adapter-pkcs11/benches/pkcs11_perf.rs`.
  - **Tests:** `cargo bench -p oxitls-adapter-pkcs11 --no-run` compiles; bench runs to completion without HSM.
  - **Risk:** p256 dev-dep version coupling (0.14-rc.9 workspace); verify `SigningKey` API at that version.
- [x] Benchmark session-pool contention: 1 vs 4 vs 16 concurrent signers, measure throughput (planned 2026-06-02)
  - **Goal:** Real criterion bench (group 2 in `pkcs11_perf.rs`) + rewrite of `benches/pkcs11_bench.rs` stub. Produces hardware-free contention curves via `MockSigningBackend`; richer numbers when `SOFTHSM2_MODULE` is set.
  - **Design:** `Pkcs11SessionPool::new(module, slot, pin, NonZeroUsize)` directly at capacities 1/4/16 (avoids Pkcs11TlsProvider's hardcoded-4 capacity). Fan out concurrent tasks via `criterion.async_tokio` multi-thread. `MockSigningBackend` (`signer.rs:491`) for hardware-free contention curves. `pkcs11_bench.rs` converted to a real session acquire/release micro-bench (no more empty stub). Log any hardware-skipped paths explicitly.
  - **Files:** `crates/oxitls-adapter-pkcs11/benches/pkcs11_perf.rs`, `crates/oxitls-adapter-pkcs11/benches/pkcs11_bench.rs`.
  - **Tests:** `cargo bench -p oxitls-adapter-pkcs11 --no-run` compiles both binaries; both run without HSM.
  - **Risk:** `MockSigningBackend::new` / `sign_raw` API (signer.rs:491,507) — verify signature.

## Integration

- [x] Wire `Pkcs11TlsProvider` into `oxitls` facade behind `pkcs11` feature flag:
  `oxitls::pkcs11::provider(lib_path, slot, pin)` re-export (~15 SLOC)
- [x] Add integration guide in crate docs: SoftHSM2 setup section added to
  `src/lib.rs` module-level doc comment (Wave 5, 2026-05-27)
- [x] SNI dispatcher: `with_sni_map` constructor implemented; strict-SNI (no fallback)
  mode and wildcard matching are implemented (Wave 8, 2026-05-29)
- [x] Coordinate with `oxitls-adapter-aws-lc` for hybrid HSM+FIPS deployments:
  PKCS#11 key + aws-lc-rs bulk TLS crypto (Wave 10, 2026-05-30; wave10_hybrid_pkcs11.rs proves seam)
