# oxitls-adapter-rustls-rustcrypto TODO

## Status
Working adapter wrapping rustls 0.23 + rustls-rustcrypto CryptoProvider (as of
0.2.1, backed by the in-workspace `oxitls-rustcrypto-provider` fork — see
Cargo.toml). Provides `pure_provider()`, `client_config()`, `server_config()`,
`RustcryptoConnector`, and `RustcryptoAcceptor` (~108 SLOC). Per-config provider
injection -- never calls `install_default()`. Functional for basic TLS 1.3 and
TLS 1.2 handshakes. 60 tests passing (default features) / 97 passing
(all-features), zero failures/warnings (0.2.1).

## Core Implementation
- [x] Add CRL (Certificate Revocation List) checking via `rustls::server::WebPkiClientVerifier` CRL injection (~120 SLOC)
- [x] Add OCSP stapling support: RFC 6960 signer crypto verification in `OcspClientVerifier` with `SoftFail`/`HardRequire`/`Disabled` policies
- [x] Add certificate pinning: `CertPinVerifier` implementing `rustls::client::danger::ServerCertVerifier` with SHA-256 pin matching
- [x] Add custom `ServerCertVerifier` wrapper for user-supplied verification callbacks
- [x] RFC 7250 raw public key support: `RawPublicKeyServerVerifier` + `RawPublicKeyClientVerifier` + resolver helpers (`server_raw_public_key_resolver`, `client_raw_public_key_resolver`) — written; full integration test blocked pending workspace dep-version reconciliation (der 0.7→0.8 / signature 2→3 conflict from PQ slice breaks ocsp_*.rs)
- [x] Add SSLKEYLOGFILE support via `KeyLogBridge` on both client and server configs
- [x] Add `RustcryptoClientConfigBuilder` with fluent API (Wave 2)
- [x] Add `RustcryptoServerConfigBuilder` at adapter level (Wave 2)
- [x] Add CT log verification via `SctVerifier` with embedded log keys and crypto verification (Wave 5)
- [x] Add certificate chain validation with intermediate cert caching (Wave 2/3)
- [x] Expose cipher suite enumeration: `supported_cipher_suites() -> Vec<SupportedCipherSuite>` (~30 SLOC)
- [x] Expose protocol version enumeration: `supported_versions() -> Vec<ProtocolVersion>` (~20 SLOC)
- [x] Add `ConnectionInfo` population from `rustls::CommonState` post-handshake (~60 SLOC)

## API Improvements
- [x] Add `RustcryptoConnector::connect_with_alpn()` that overrides ALPN per-connection
- [x] Add `RustcryptoAcceptor::accept_with_timeout()` combining TLS accept with a deadline
- [x] Return `ConnectionInfo` from `connect()` / `accept()` alongside the TLS stream (via `RustcryptoClientStream`)
- [x] Add `RustcryptoConnector::from_config_with_sni()` for per-connection SNI override
- [x] Make `client_config()` and `server_config()` return `Result<Arc<ClientConfig>, TlsError>` consistently (server already does; client does too -- verify generic variants)

## Testing
- [x] Integration test: CRL-revoked client cert rejected in mTLS handshake (wave2_tests.rs)
- [x] Integration test: OCSP signer crypto verification — RSA/ECDSA/EKU paths (ocsp_crypto_paths.rs — Wave 5)
- [x] Integration test: SCT/CT signature verification — Ed25519/ECDSA/parser paths (sct_crypto_paths.rs — Wave 5)
- [x] Integration test: certificate pin match succeeds; pin mismatch fails handshake (wave2_tests.rs)
- [x] Integration test: SSLKEYLOGFILE writes key material to temp file, NSS key log format validated (wave2_tests.rs)
- [x] Unit test: `supported_cipher_suites()` returns non-empty list with expected TLS 1.3 suites
- [x] Unit test: `supported_versions()` includes TLS 1.3, conditionally TLS 1.2
- [x] Integration test: RPK server pinned match succeeds (raw_public_keys.rs — Wave 6 RPK) [compile-blocked — see workspace dep conflict note]
- [x] Integration test: RPK wrong pin fails (raw_public_keys.rs — Wave 6 RPK) [compile-blocked]
- [x] Integration test: RPK mutual auth both succeed (raw_public_keys.rs — Wave 6 RPK) [compile-blocked]
- [x] Fuzz test: malformed certificate DER input to `client_config()` does not panic

## Performance
- [x] Benchmark `pure_provider()` construction time (should be near-zero, just struct assembly)
- [x] Benchmark TLS 1.3 vs TLS 1.2 handshake latency through this adapter (compare with oxitls-bench)
- [x] Profile certificate chain validation overhead with deep chains (3, 5, 10 intermediates) — `benches/deep_chain_validation.rs` fully implemented
- [x] Measure memory footprint of `ClientConfig` and `ServerConfig` instances

## Integration
- [x] Wire `ConnectionInfo` population into `oxitls-core::ConnectionInfo` struct — `connection_info_from_state()` at src/lib.rs:130
- [x] Coordinate with `oxitls` facade `ClientBuilder`/`ServerBuilder` for CRL, OCSP, and pinning builder methods — `with_crl`, `with_cert_pinning`, `with_ocsp_response`/`with_ocsp_response_resolver` all wired in facade
- [x] Ensure `oxitls-bench` benchmarks cover adapter-level config construction — `benches/builder_construction.rs` in oxitls-bench + `benches/builder.rs` in this crate
- [x] Coordinate with `oxihttp-client` for per-request TLS config overrides — `RequestTlsConfig` + `HttpsClient::with_request_tls_config()` implemented in oxihttp-client; 3 integration tests pass
- [x] Provide `From<rustls::Error> for oxitls_core::TlsError` mapping for all new error variants

## Wave 14

- [x] RFC 9180 §5.3 HPKE Context.Export + typed public HPKE API (planned 2026-06-03)
  - **Goal:** The Wave-13 hand-rolled HPKE gains a public, KAT-verified `export()` on both sender and receiver contexts, plus an ergonomic oxitls-native typed API (`setup_sender`/`setup_receiver` returning concrete `HpkeSealerCtx<A>`/`HpkeOpenerCtx<A>` and four `pub const` typed suite values). `exporter_secret` — currently computed and discarded — is threaded through and surfaced.
  - **Design:**
    - `kdf.rs`: add `exporter_secret: [u8; 32]` to `HpkeKeyMaterial`; un-discard `_exporter_secret` (already correctly derived: `LabeledExpand(secret,"exp",ks_context,32)`). Add `labeled_expand_checked(suite_id, prk, label, info, l) -> Result<Vec<u8>, rustls::Error>` guarding `l <= 255*32` (public Export path must not panic on attacker-influenced L).
    - `mod.rs`: store `exporter_secret: [u8; 32]` and `suite_id: [u8; 10]` in `HpkeSealerCtx<A>` and `HpkeOpenerCtx<A>` (suite_id needed for Export's full-HPKE-domain LabeledExpand; ctx is generic only over A). Make both ctx types `pub`. Add inherent `pub fn export(&self, exporter_context: &[u8], len: usize) -> Result<Vec<u8>, rustls::Error>` = `labeled_expand_checked(&self.suite_id, &self.exporter_secret, b"sec", exporter_context, len)` (RFC 9180 §5.3 label = `"sec"`, NOT `"exp"`). Add typed `setup_sender`/`setup_receiver` on `HpkeSuiteImpl<K,A>` that return concrete ctx types (rustls `setup_sealer`/`setup_opener` delegate to these). Expose four `pub const` suite values and `pub use kem::{KemX25519,KemP256}`, `pub use aead::{AeadAes128Gcm,AeadChacha20}`.
    - `vectors.rs`: add `exporter_secret: [u8; 32]` to `Kat` struct; add RFC 9180 Appendix A exporter KAT values for A.1/A.2/A.3/A.5 (three standard queries each: empty ctx, `"00"`, `"TestContext"`, L=32 each).
    - `lib.rs`: re-export `HpkeSealerCtx`, `HpkeOpenerCtx`, the four suite consts, `KemX25519`, `KemP256`, `AeadAes128Gcm`, `AeadChacha20`.
  - **Files:** `crates/oxitls-adapter-rustls-rustcrypto/src/hpke/{kdf.rs,mod.rs,vectors.rs}`, `…/src/lib.rs`. No Cargo.toml change.
  - **Prerequisites:** none.
  - **Tests:** RFC 9180 Appendix A KAT — assert derived `exporter_secret` == KAT; assert each `export()` == `exported_value` byte-for-byte; `setup_sender`/`setup_receiver` round-trip asserting both sides export same value for same `(context, L)`; `export` with len > 255*32 returns `Err` (not panic).
  - **Risk:** label `"sec"` for Export vs `"exp"` for exporter_secret derivation must not be confused. suite_id must be full 10-byte HPKE id. Both pinned by KATs.

- [x] RFC 8879 certificate compression (TLS 1.3) backed by OxiARC zlib — pure Rust (done 2026-06-03)
  - **Goal:** oxitls clients/servers can negotiate certificate compression (RFC 8879, algorithm 1 = zlib) backed entirely by `oxiarc-deflate` (COOLJAPAN pure-Rust RFC 1950 zlib), behind a new `cert-compression` feature. Zero C/forbidden codecs; rustls's own `zlib`/`brotli` features stay off.
  - **Design:**
    - New `src/cert_compression.rs`: zero-sized `OxiArcZlibCompressor` and `OxiArcZlibDecompressor` implementing `rustls::compress::{CertCompressor,CertDecompressor}`. `compress` maps `Interactive→level 1`, `Amortized→level 9`; calls `oxiarc_deflate::zlib_compress`. `decompress` calls `zlib_decompress`, enforces strict `d.len() == output.len()` contract before `copy_from_slice`. Expose `pub const OXIARC_ZLIB_COMPRESSOR: &dyn CertCompressor` and `pub const OXIARC_ZLIB_DECOMPRESSOR: &dyn CertDecompressor`. Add `pub fn install_cert_compression(c: &mut ClientConfig)` / `(&mut ServerConfig)` setting the public `cert_compressors`/`cert_decompressors` Vec fields on each config.
    - `Cargo.toml`: feature `cert-compression = ["dep:oxiarc-deflate"]`; `oxiarc-deflate = { workspace = true, optional = true }`. Root workspace.dependencies gains `oxiarc-deflate = { version = "0.3", default-features = false }` (published on crates.io 0.3.2, pure Rust, no C).
    - `lib.rs`: `#[cfg(feature="cert-compression")] pub mod cert_compression; pub use cert_compression::{OXIARC_ZLIB_COMPRESSOR, OXIARC_ZLIB_DECOMPRESSOR, install_cert_compression};`
  - **Files:** NEW `…/src/cert_compression.rs`; `…/src/lib.rs`; `…/Cargo.toml`; root `Cargo.toml`.
  - **Prerequisites:** `oxiarc-deflate` 0.3.2 verified published on crates.io; pure Rust, no build.rs/sys.
  - **Tests:** unit round-trip compress→decompress on a sample cert-chain blob (both levels); length-mismatch input rejected as `DecompressionFailed`; integration TLS 1.3 loopback with both peers using `with_cert_compression()` asserting handshake success.
  - **Risk:** `oxiarc-deflate` fetch from crates.io; mitigated — feature is opt-in so default build is unaffected. Brotli (alg 2) via `oxiarc-brotli` is a follow-up.

## v0.2.1 — OCSP/SCT hardening

- [x] OCSP `CertID` binding + freshness enforcement in `check_ocsp_staple` (`src/verifier/ocsp_client.rs`): new `ocsp_digest` / `cert_id_matches` / `evaluate_responses` / `single_response_is_current` helpers recompute `issuerNameHash`/`issuerKeyHash` (id-sha1/sha256/sha384/sha512 per RFC 6960 §4.1.1) and match `serialNumber` against the certificate actually being verified and its issuer, and reject a matching `Good`/`Unknown` outside its `thisUpdate..=nextUpdate` window. Closes a bypass where a staple containing no matching entry (or only an unrelated entry) previously fell through to `Good`. A matching `Revoked` stays authoritative regardless of freshness (fail-safe). 7 new unit tests.
- [x] SCT embedded-extension parsing fix in `extract_sct_extension` (`src/verifier/sct.rs`): new `strip_sct_octet_string` strips the RFC 6962 §3.3 DER `OCTET STRING` tag/length wrapper (both short- and long-form DER lengths) before handing the bytes to `parse_sct_list`. Previously the wrapper's leading `0x04 <len>` bytes were fed straight into the TLS-format parser as the `u16` list-length prefix, so a certificate carrying a real, X.509-embedded SCT list extension always failed to parse. 4 new unit tests.

See `CHANGELOG.md` `[0.2.1]` for full detail.

## Proposed follow-ups

- RFC 8879 brotli (algorithm 2) via `oxiarc-brotli` — natural extension of cert-compression once `oxiarc-brotli` compress/decompress API is byte-verified.
