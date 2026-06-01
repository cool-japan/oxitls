# oxitls-core TODO

## Status
Foundation crate providing `TlsError`, `TlsStream` trait alias, marker traits
`TlsConnector`/`TlsAcceptor`, plus `TlsVersion`, `CipherSuite`, and `ConnectionInfo`
types. (~300 SLOC).

## Core Implementation
- [x] Add `TlsVersion` enum (`Tls12`, `Tls13`) for version introspection (~20 SLOC)
- [x] Add `CipherSuite` enum covering TLS 1.3 mandatory suites and TLS 1.2 AEAD suites (~60 SLOC)
- [x] Add `ConnectionInfo` struct (negotiated version, cipher suite, ALPN protocol, SNI, peer certificates) (~80 SLOC)
- [x] Extend `TlsStreamTrait` with `fn connection_info(&self) -> Option<&ConnectionInfo>` via new `TlsStreamInfo` trait with default impl (~30 SLOC)
- [x] Add `TlsError::CertRevoked` variant for CRL/OCSP revocation failures (~10 SLOC)
- [x] Add `TlsError::AlertReceived(AlertDescription)` variant for TLS alert mapping (~30 SLOC)
- [x] Add `AlertDescription` enum covering TLS 1.3 alert codes (RFC 8446 Section 6) (~80 SLOC)
- [x] Add `TlsConfig` trait with methods `protocol_versions()`, `alpn_protocols()`, `sni_name()` for generic config introspection (~50 SLOC)
- [x] Add `KeyLogPolicy` enum (`Disabled`, `File(PathBuf)`, `Custom(Arc<dyn KeyLog>)`) for SSLKEYLOGFILE support (~40 SLOC)
- [x] Implement `From<TlsError> for std::io::Error` conversion (~15 SLOC)

## API Improvements
- [x] Derive `Clone + PartialEq` on `TlsError` — `Io` already holds `io::ErrorKind` (Copy+Clone+PartialEq), so simple derive sufficed; no Arc needed
- [x] Implement `PartialEq` on `TlsError` for testing ergonomics (via derive)
- [x] Add `TlsError::is_handshake()`, `is_io()`, `is_cert()` convenience predicates
- [x] Add `TlsConnector::connect()` and `TlsAcceptor::accept()` as required async trait methods — boxed-future signatures, object-safe (`&dyn TlsConnector`/`&dyn TlsAcceptor` both compile)
- [x] Add builder pattern for `ConnectionInfo` to allow adapter crates to construct it incrementally
- [x] Make `TlsStream` generic over the underlying transport rather than boxed-trait (optional behind feature flag)

## Testing
- [x] Unit tests for all `TlsError` Display formatting variants
- [x] Unit tests for `From<io::Error> for TlsError` conversion
- [x] Unit tests for `AlertDescription` enum exhaustiveness
- [x] Unit tests for `ConnectionInfo` builder and accessor methods
- [x] Property-based tests for `TlsVersion` and `CipherSuite` round-trip (Display -> FromStr)

## Performance
- [x] Benchmark `TlsError` construction overhead: `bench_tls_error_io_from`, `bench_tls_error_other_alloc`, `bench_tls_error_alert_no_alloc` added to `benches/core_ops.rs`
- [x] Consider `#[non_exhaustive]` on `TlsError` variants for forward compatibility (already implied by enum)
- [x] Evaluate using `compact_str` for string-carrying error variants to reduce allocations — documented decision: not adopting; error-path String overhead negligible; avoids a dep

## Integration
- [x] Ensure all adapter crates (rustls-rustcrypto, future aws-lc, future pkcs11) can populate `ConnectionInfo`
- [x] Coordinate `CipherSuite` enum values with `oxitls-adapter-rustls-rustcrypto` mapping
- [x] Provide conversion traits from/to `rustls::Error` for adapter crates
- [x] Coordinate with `oxihttp-core::OxiHttpError` for TLS-over-HTTP error propagation
- [x] Coordinate with `oxiquic-core::OxiQuicError` for QUIC-TLS error propagation
