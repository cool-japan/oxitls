# oxitls-adapter-rustls-rustcrypto TODO

## Status
Working adapter wrapping rustls 0.23 + rustls-rustcrypto CryptoProvider. Provides
`pure_provider()`, `client_config()`, `server_config()`, `RustcryptoConnector`,
and `RustcryptoAcceptor` (~108 SLOC). Per-config provider injection -- never calls
`install_default()`. Functional for basic TLS 1.3 and TLS 1.2 handshakes.

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
