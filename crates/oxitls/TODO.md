# oxitls (facade) TODO

## Status
Facade crate (~66 SLOC in lib.rs, plus ~160 SLOC client.rs, ~262 SLOC server.rs,
~227 SLOC ticketer.rs) providing the unified `oxitls` API. Feature-gated re-exports
from all subcrates. Includes `ClientBuilder` (TLS 1.3 default, TLS 1.2 fallback,
session resumption, webpki roots), `ServerBuilder` (single cert, mTLS, ALPN, SNI,
protocol versions, session ticketer), `OxiTicketer` (AES-256-GCM session ticket
encryptor with key rotation), `connector_with_webpki_roots()` convenience function,
and re-exports for `h2` and `rcgen_bridge`. Comprehensive integration tests for TLS
1.3 server, mTLS, ALPN, SNI, TLS 1.2 fallback, session resumption, and ticket
resumption. 90 tests passing (default features) / 105 passing (all-features),
zero failures/warnings (0.2.1). No direct API changes in 0.2.1; the facade
transitively picks up the adapter's OCSP/SCT verifier hardening and the
RUSTSEC-2026-0104 fix (see `CHANGELOG.md` `[0.2.1]`).

## Core Implementation
- [x] Add 0-RTT (early data) support: `ClientBuilder::with_early_data()` and `OxiTlsStream::early_data()` accessor — Wave 5 Slice C (wave5_early_data_transit.rs, 3 tests)
- [x] Add OCSP stapling: `ServerBuilder::with_ocsp_response(Vec<u8>)` passing OCSP response to rustls `ServerConfig` (~60 SLOC)
- [x] Add SCT (Signed Certificate Timestamp) / Certificate Transparency support via `ClientBuilder::with_ct_logs()` — Wave 5 Slice D (wave5_facade_glue.rs)
- [x] Add SSLKEYLOGFILE support: `ClientBuilder::with_key_log_file(path)` and `ServerBuilder::with_key_log_file(path)` wiring rustls `KeyLogFile` (~60 SLOC)
- [x] Add `ClientBuilder::with_client_cert(certs, key)` for client certificate authentication (~40 SLOC)
- [x] Add `ClientBuilder::with_cert_pinning(pins: &[CertPin])` for certificate pinning (~30 SLOC, delegates to adapter)
- [x] Add `ClientBuilder::with_crl(crl_der: Vec<u8>)` for CRL checking (~30 SLOC, delegates to adapter)
- [x] Add `ServerBuilder::with_ocsp_response_resolver(Arc<dyn OcspResponseResolver>)` for dynamic OCSP stapling (~80 SLOC)
- [x] Add `ServerBuilder::with_ticketer_rotation_interval(Duration)` that spawns a background task rotating OxiTicketer keys (~60 SLOC)
- [x] Add ECH (Encrypted Client Hello) support behind `ech` feature flag (done 2026-06-03)
  - **Goal:** `oxitls` facade `ClientBuilder` can enable ECH (real config or GREASE mode) and the resulting `OxiTlsStream` exposes `ech_status()`. Depends on Slice A (`pure_hpke_suites()` from `oxitls-adapter-rustls-rustcrypto`).
  - **Design:** New `ech = ["pure", "dep:oxitls-adapter-rustls-rustcrypto", "oxitls-adapter-rustls-rustcrypto/ech"]` feature (mirrors post-quantum, implies pure). `ClientBuilder` gains `#[cfg(feature="ech")] ech_mode: Option<rustls::client::EchMode>` field; two builder methods: `with_ech_config_list(bytes) -> Result<Self, TlsError>` (parses ECHConfigList via `EchConfig::new(bytes, pure_hpke_suites())`, stores `EchMode::Enable`) and `with_ech_grease(self) -> Self` (stores `EchMode::Grease`). `build()` branches at line ~542: when ech_mode is Some, calls `.with_ech(mode)?` instead of `.with_protocol_versions(versions)` (both yield `ConfigBuilder<ClientConfig, WantsVerifier>`; with_ech forces TLS 1.3). `OxiTlsStream::ech_status()` via `Inner::Client(s) => Some(s.get_ref().1.ech_status()), Server => None` (mirrors early_data/export_keying_material). Re-export `rustls::client::{EchMode,EchConfig,EchGreaseConfig,EchStatus}` cfg-gated.
  - **Files:** `crates/oxitls/src/tls13/client.rs`, `crates/oxitls/src/stream.rs`, `crates/oxitls/src/lib.rs` (re-exports), `crates/oxitls/Cargo.toml` (ech feature).
  - **Tests:** GREASE-mode loopback handshake asserting `ech_status() == EchStatus::Grease`; Enable-path test building ClientConfig from a self-crafted single-suite ECHConfigList; error test for malformed list. Full Accepted path untestable (no rustls ECH server) — noted in test comments.
  - **Risk:** WantsVersions consume-order — handled by build() branch. Note rustls `with_ech` forces TLS1.3 internally; protocol_versions field ignored when ech path taken.
- [x] Add `post-quantum` feature flag: facade PQ provider wiring active — Wave 6 Slice FAC (client.rs + server.rs auto-select `pure_provider_with_pq()` when `post-quantum` feature is enabled; full handshake test `pq_handshake_via_facade` in wave6_pq_rpk_facade.rs; pending parallel Slice PQ landing); 2026-05-29
- [x] Add raw public keys (RFC 7250) support — Wave 6 Slice FAC (ClientBuilder::with_server_raw_public_keys, ServerBuilder::with_server_raw_public_key + with_client_raw_public_keys wired; tests in wave6_pq_rpk_facade.rs gated on Slice RPK landing; RPK-only config validation guard fixed); 2026-05-29
- [x] Add `quic-preview` feature flag reserving the namespace for oxiquic TLS integration (~10 SLOC, feature flag only)
- [x] Add connection info extraction: `TlsConnectionExt` trait providing `negotiated_version()`, `negotiated_cipher_suite()`, `alpn_protocol()`, `peer_certificates()` (~80 SLOC)
- [x] Add TLS session export: `export_keying_material(label, context, length)` wrapping rustls API (~40 SLOC)
- [x] Add `ServerBuilder::with_max_fragment_size(u16)` for TLS record size control (~20 SLOC)

## API Improvements
- [x] Add `ConnectFuture` type alias for the return type of connector operations — Wave 7 (lib.rs `pub type ConnectFuture<IO> = tokio_rustls::client::Connect<IO>`; compile-time test `connect_future_type_alias_usable` in wave7_facade_tests.rs); 2026-05-29
- [x] Add `AcceptFuture` type alias for the return type of acceptor operations — Wave 7 (lib.rs `pub type AcceptFuture<IO> = tokio_rustls::server::Accept<IO>`; compile-time test `accept_future_type_alias_usable` in wave7_facade_tests.rs); 2026-05-29
- [x] Add `OxiTlsStream<S>` wrapper type that bundles the stream with `ConnectionInfo` — Wave 5 Slice C (stream.rs, exported from crate root)
- [x] Add `ClientBuilder::with_danger_accept_invalid_certs()` for testing/development (clearly documented as unsafe)
- [x] Add `ClientBuilder::with_danger_accept_invalid_hostnames()` for testing/development
- [x] Add `ServerBuilder::with_pem_cert_chain_and_key(chain_pem, key_pem)` supporting PEM-encoded full chains
- [x] Add builder validation: `build()` returns descriptive errors when required fields are missing
- [x] Add `Clone` derive on `ClientBuilder` and `ServerBuilder` for config templating — Wave 7 (`ClientBuilder` already derived Clone; `ServerBuilder` manual `impl Clone` added to server.rs with `clone_private_key_der` helper; tested `server_builder_clone_produces_independent_configs` in wave7_facade_tests.rs); 2026-05-29
- [x] Re-export `rustls::ProtocolVersion` and `rustls::SupportedProtocolVersion` for ergonomics — Wave 7 (lib.rs `pub use rustls::ProtocolVersion` + `pub use rustls::SupportedProtocolVersion`; tested `protocol_version_re_exports_usable` in wave7_facade_tests.rs); 2026-05-29

## Testing
- [x] Test: `OxiTlsStream::early_data()` is None on server stream — Wave 5 Slice C
- [x] Test: `OxiTlsStream::early_data()` is None on first-connection client (no ticket) — Wave 5 Slice C
- [x] Test: `with_early_data()` flag is explicit opt-in (defaults to false) — Wave 5 Slice C
- [x] Test: OCSP stapling: server provides OCSP response; client verifies — Wave 8 smoke (`ocsp_resolver_smoke_build` in wave8_facade.rs) + Wave 9 full integration (`ocsp_staple_delivered_to_client_verifier`, `no_ocsp_configured_means_empty_bytes`, `static_ocsp_resolver_*` in wave9_ocsp.rs); 2026-05-29
- [x] Test: SSLKEYLOGFILE: key material written to temp file in NSS format — Wave 7 (`sslkeylogfile_writes_to_temp_dir` in wave7_facade_tests.rs); 2026-05-29
- [x] Test: client certificate auth via `ClientBuilder::with_client_cert()` — Wave 5 Slice F (wave5_coverage.rs test 4; mTLS + peer_certificates)
- [x] Test: certificate pinning: correct pin succeeds; wrong pin fails — Wave 7 (`cert_pin_match_succeeds` + `cert_pin_mismatch_rejected` in wave7_facade_tests.rs); 2026-05-29
- [x] Test: CRL checking: revoked cert rejected; valid cert accepted — Wave 5 Slice F (wave5_coverage.rs tests 1+2)
- [x] Test: ticketer rotation interval: keys rotate on schedule; old tickets still decrypt — Wave 8 (`ticketer_rotation_decrypt_with_previous_key` + `ticketer_rotation_second_rotation_drops_original_key` in wave8_facade.rs); 2026-05-29
- [x] Test: connection info extraction returns correct version, suite, ALPN
- [x] Test: `export_keying_material()` produces deterministic output for same session
- [x] Test: `with_danger_accept_invalid_certs()` accepts self-signed without trusted root — Wave 5 Slice F (wave5_coverage.rs test 3)
- [x] Test: max_fragment_size respected in TLS records

## Performance
- [x] Benchmark 0-RTT handshake latency vs full handshake
- [x] Benchmark OCSP stapling overhead on handshake — Wave 5 Slice F (oxitls-bench/benches/ocsp_stapling_overhead.rs; compile/run gate pending Slices A/B/I)
- [x] Benchmark connection info extraction overhead — Wave 5 Slice F (oxitls-bench/benches/connection_info_extract.rs; compile/run gate pending Slices A/B/I)
- [x] Profile OxiTicketer rotation under high-concurrency server load — Wave 5 Slice F (oxitls-bench/benches/ticketer_rotation_contention.rs; compile/run gate pending Slices A/B/I)
- [x] Benchmark `connector_with_webpki_roots()` cold-start time — Wave 5 Slice F (oxitls-bench/benches/connector_cold_start.rs; compile/run gate pending Slices A/B/I)

## Integration
- [x] Wire 0-RTT support into `oxihttp-client` for HTTP fast-open — `ClientBuilder::with_early_data()` in oxihttp-client; `early_data: bool` field + `with_early_data()` builder method; `build_tls_connector` passes flag to `oxitls::ClientBuilder::with_early_data()`; loopback tests in oxihttp/tests/early_data_test.rs
- [x] Wire SSLKEYLOGFILE into `oxihttp` for Wireshark debugging of HTTP traffic — `TlsConfig::from_pem_with_key_log` (server), `ClientBuilder::with_key_log_file` (client), `ServerBuilder::with_key_log_file` added to oxitls ServerBuilder; loopback integration tests in oxihttp/tests/key_log_test.rs
- [x] Wire client cert auth into `oxihttp-server` for mTLS-protected HTTP endpoints — `TlsConfig::with_client_auth` in oxihttp-server; full loopback tests in oxihttp/tests/mtls_test.rs (4 tests)
- [x] Coordinate `quic-preview` feature flag with `oxiquic-tls` crate
- [x] Wire `TlsConnectionExt` into `oxihttp-core` for HTTP-level TLS introspection — `PeerCertInfo` extended with typed `version`/`cipher_suite`/`sni`; both accept loops use `tls_stream.tls_connection_info()`; `req.tls_connection_info()` added to `Request`; test `test_request_handler_can_read_tls_connection_info` in oxihttp/tests/mtls_test.rs
- [x] Provide `oxihttp-server` with `ServerBuilder` defaults optimized for HTTP/2 (ALPN, settings) — `TlsConfig::http2_defaults()` and `http2_defaults_from_der()` added; `ServerBuilder::with_alpn()` already wires ALPN; `ServerHttp2Settings` covers H2 tuning

## Wave 14

- [x] ECHConfigList generation — mint a publishable ECH config from a fresh HPKE keypair (done 2026-06-03)
  - **Goal:** oxitls can mint a spec-correct `ECHConfigList` (draft-ietf-tls-esni-18, version `0xfe0d`) from a freshly generated HPKE keypair, returning both the publishable config bytes and the operator's long-term HPKE private key. Makes ECH deployable (not just GREASE) and upgrades test coverage from GREASE-only to the real Enable path. rustls parses ECHConfig but ships no generator — per IMPLEMENT POLICY we build it.
  - **Design:**
    - New submodule `crates/oxitls-adapter-rustls-rustcrypto/src/hpke/ech_config.rs`:
      `pub struct GeneratedEchConfig { pub config_list: Vec<u8>, pub private_key: Vec<u8>, pub public_key: Vec<u8>, pub config_id: u8 }`
      `pub fn generate_ech_config_list(suite: &'static dyn Hpke, config_id: u8, public_name: &str, maximum_name_length: u8) -> Result<GeneratedEchConfig, rustls::Error>`
    - Internals: `suite.generate_key_pair()?` → `(pk, sk)`. Read `suite.suite()` for `kem_id/kdf_id/aead_id`. Hand-roll TLS-presentation-language bytes (forced by unnameable `PayloadU16<NonEmpty>` field): outer `u16`-len ECHConfigList → `ECHConfig{ u16 version=0xfe0d, u16 len, contents }` → `ECHConfigContents{ HpkeKeyConfig{ u8 config_id, u16 kem_id, u16-len pk.0, u16-len cipher_suites[{u16 kdf_id, u16 aead_id}] }, u8 maximum_name_length, u8-len public_name, u16-len extensions=∅ }`.
    - Self-validate: parse emitted bytes back via `rustls::client::EchConfig::new(EchConfigListBytes::from(bytes.clone()), pure_hpke_suites())` and via `Vec::<EchConfigPayload>::read` before returning — a malformed emit fails fast.
    - `…/hpke/mod.rs`: add `pub mod ech_config;`.
    - `…/rustls-rustcrypto/src/lib.rs`: `#[cfg(feature="ech")] pub use hpke::ech_config::{GeneratedEchConfig, generate_ech_config_list};`
    - `crates/oxitls/src/lib.rs`: `#[cfg(feature="ech")] pub use oxitls_adapter_rustls_rustcrypto::{GeneratedEchConfig, generate_ech_config_list};`
  - **Files:** NEW `crates/oxitls-adapter-rustls-rustcrypto/src/hpke/ech_config.rs`; `…/hpke/mod.rs` (+1 line); `…/rustls-rustcrypto/src/lib.rs`; `crates/oxitls/src/lib.rs`; NEW `crates/oxitls/tests/wave14_ech_config_tests.rs`. No new deps.
  - **Prerequisites:** Slice A (for shared mod.rs file-ordering; functionally independent).
  - **Tests:** `ech_generated_config_accepted_by_builder` — mint → `ClientBuilder::new().with_ech_config_list(cfg.config_list)` returns `Ok` and mode is `Enable`; `ech_generated_config_roundtrips` — parse emitted bytes back and assert `config_id/kem_id/public_key/public_name/cipher_suites` field-for-field; `ech_generated_config_x25519_and_p256` — both KEM families mint+parse. Note in test header: `EchStatus::Accepted` end-to-end requires rustls ECH server (not available in 0.23.40).
  - **Risk:** wire-format byte errors mitigated by parsing every emitted config back through rustls before returning. Public-key length is KEM-dependent (X25519=32, P-256=65), read from `pk.0.len()` not hardcoded.
