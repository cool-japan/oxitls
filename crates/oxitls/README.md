# oxitls — The COOLJAPAN Pure-Rust TLS facade

[![Crates.io](https://img.shields.io/crates/v/oxitls.svg)](https://crates.io/crates/oxitls)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

`oxitls` is the top-level facade for the OxiTLS stack. With its default features it wires rustls to the Pure-Rust [`oxitls-adapter-rustls-rustcrypto`](https://crates.io/crates/oxitls-adapter-rustls-rustcrypto) provider, giving you a complete TLS 1.3 / TLS 1.2 client and server with **zero FFI** — no `ring`, no `aws-lc-rs`, no OpenSSL. It bundles ergonomic `ClientBuilder` / `ServerBuilder` types, a unified `OxiTlsStream`, a Pure-Rust AES-256-GCM session ticketer, RFC 8446 §8 anti-replay for 0-RTT, and the Mozilla CA bundle.

The facade also performs **provider selection** through feature flags. The default closure is 100% Pure Rust and never calls `CryptoProvider::install_default()` — providers are injected per-config. Two non-default, non-Pure-Rust providers can be opted in: the C-backed aws-lc-rs provider (`aws-lc`) and the PKCS#11 HSM/TPM signer (`pkcs11`). Enabling them does not change the default Pure-Rust path; it only adds extra modules and re-exports.

## Installation

```toml
[dependencies]
# Default: Pure-Rust TLS + Mozilla webpki roots
oxitls = "0.1.0"

# HTTP/2 over TLS and Pure-Rust cert generation
oxitls = { version = "0.1.0", features = ["h2", "rcgen"] }

# Opt in to the aws-lc-rs provider (NOT Pure Rust — C/FFI):
oxitls = { version = "0.1.0", features = ["aws-lc"] }

# Opt in to the PKCS#11 HSM/TPM signer (NOT Pure Rust — loads a C module):
oxitls = { version = "0.1.0", features = ["pkcs11"] }
```

## Quick Start

### Server

```rust,no_run
use oxitls::tls13::{ServerBuilder, tokio_acceptor};

#[tokio::main]
async fn main() -> Result<(), oxitls::TlsError> {
    let config = ServerBuilder::new()
        .with_pem_cert_and_key(
            include_bytes!("../tests/fixtures/cert.pem"),
            include_bytes!("../tests/fixtures/key.pem"),
        )?
        .with_alpn_protocols(vec![b"h2".to_vec(), b"http/1.1".to_vec()])?
        .build()?;

    let acceptor = tokio_acceptor(config);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8443").await
        .map_err(|e| oxitls::TlsError::Other(e.to_string()))?;
    let (tcp, _) = listener.accept().await
        .map_err(|e| oxitls::TlsError::Other(e.to_string()))?;
    let _tls = acceptor.accept(tcp).await
        .map_err(|e| oxitls::TlsError::Handshake(e.to_string()))?;
    Ok(())
}
```

### Client

```rust,no_run
use oxitls::tls13::ClientBuilder;

# fn example() -> Result<(), oxitls::TlsError> {
let config = ClientBuilder::new()      // TLS 1.3 only by default
    .with_webpki_roots()               // trust the Mozilla CA bundle
    .with_alpn_protocols(vec![b"h2".to_vec()])?
    .build()?;
# Ok(())
# }
```

Or trust the Mozilla bundle in one call:

```rust,no_run
# fn example() -> Result<(), oxitls::TlsError> {
let connector = oxitls::connector_with_webpki_roots()?;
# Ok(())
# }
```

## Provider selection

| Provider | Feature | Pure Rust | Crate behind it |
|----------|---------|-----------|-----------------|
| RustCrypto (rustls + RustCrypto) | `pure` *(default)* | ✅ | [`oxitls-adapter-rustls-rustcrypto`](https://crates.io/crates/oxitls-adapter-rustls-rustcrypto) |
| aws-lc-rs | `aws-lc` | ❌ (C/FFI) | [`oxitls-adapter-aws-lc`](https://crates.io/crates/oxitls-adapter-aws-lc) |
| PKCS#11 HSM/TPM signer | `pkcs11` | ❌ (loads a C module) | [`oxitls-adapter-pkcs11`](https://crates.io/crates/oxitls-adapter-pkcs11) |

The default `pure` provider is available as `oxitls::pure_provider()`. The opt-in providers live under feature-gated modules (`oxitls::aws_lc`) and adapter re-exports; enabling them never affects the default Pure-Rust closure.

## API Overview

### `tls13::ClientBuilder`

Fluent `ClientConfig` builder (TLS 1.3 only by default; 256-entry resumption cache).

| Method | Description |
|--------|-------------|
| `new()` | New builder (TLS 1.3 only) |
| `with_tls12_fallback()` | Also allow TLS 1.2 |
| `with_protocol_versions(&[..])` | Restrict to explicit protocol versions |
| `with_trusted_cert_der(Vec<u8>) -> Result<Self, _>` | Add a DER trust anchor |
| `with_webpki_roots()` *(feature `webpki-roots`)* | Trust the Mozilla CA bundle |
| `with_root_store_builder(..)` *(feature `webpki-roots`)* | Merge an extra `RootCertStore` |
| `with_resumption_capacity(usize)` | Session-resumption cache size (0 = disabled) |
| `with_alpn_protocols(..)` | Set ALPN protocols |
| `with_client_cert(..)` | Client certificate for mutual TLS |
| `with_cert_pinning(Vec<[u8; 32]>)` | Pin acceptable leaf certs by SHA-256 |
| `with_crl(Vec<CertificateRevocationListDer>)` | CRL-based revocation checking |
| `with_ct_logs(..)` *(feature `pure`)* | Certificate Transparency SCT verification |
| `with_intermediate_cache(..)` *(feature `webpki-roots`)* | Cache intermediate certs across handshakes |
| `with_key_log_file(PathBuf)` / `with_key_log_custom(Arc<dyn KeyLog>)` | Key logging (SSLKEYLOGFILE-style) |
| `with_early_data()` | Enable 0-RTT early data on TLS 1.3 |
| `with_server_raw_public_keys(..)` *(feature `pure`)* | RFC 7250 raw-public-key pinning |
| `with_provider(Arc<CryptoProvider>)` | Inject a custom crypto provider |
| `with_danger_accept_invalid_certs()` / `with_danger_accept_invalid_hostnames()` | **Testing only** — weaken verification |
| `build() -> Result<ClientConfig, TlsError>` | Produce the config |

### `tls13::ServerBuilder`

Fluent `ServerConfig` builder.

| Method | Description |
|--------|-------------|
| `new()` | New builder |
| `with_pem_cert_and_key(certs, key) -> Result<Self, _>` | Load a PEM certificate + key |
| `with_der_cert_and_key(..) -> Result<Self, _>` | Load a DER certificate + key |
| `with_pem_cert_chain_and_key(..) -> Result<Self, _>` | Load a full PEM chain + key |
| `with_client_cert_verifier(RootCertStore)` | Require client certificates (mutual TLS) |
| `with_alpn_protocols(..)` | Set ALPN protocols |
| `with_protocol_versions(&[..])` | Restrict protocol versions |
| `with_sni_cert(server_name, CertifiedKey)` | Add an SNI-specific certificate |
| `with_ticketer(Arc<dyn ProducesTickets>)` | Use a custom session ticketer |
| `with_anti_replay() -> Result<Self, _>` | Wrap the ticketer with RFC 8446 §8 single-use replay protection |
| `with_ocsp_response(Vec<u8>)` / `with_ocsp_response_resolver(Arc<dyn OcspResponseResolver>)` | OCSP stapling (static or dynamic) |
| `with_max_fragment_size(Option<usize>)` | Set the max TLS record fragment size |
| `with_max_early_data_size(u32)` | 0-RTT early-data budget |
| `with_server_raw_public_key(..)` / `with_client_raw_public_keys(..)` | RFC 7250 raw public keys |
| `with_provider(Arc<CryptoProvider>)` | Inject a custom crypto provider |
| `with_key_log_file(PathBuf)` / `with_key_log_custom(..)` | Key logging |
| `build() -> Result<ServerConfig, TlsError>` | Produce the config |

| Item | Description |
|------|-------------|
| `tokio_acceptor(ServerConfig) -> tokio_rustls::TlsAcceptor` | Wrap a built config in a tokio-rustls acceptor |
| `OcspResponseResolver` (trait) | Supply a per-handshake OCSP response |
| `StaticOcspResolver(pub Vec<u8>)` | An `OcspResponseResolver` returning a fixed staple |

### `OxiTlsStream<S>` *(feature `pure`)*

Unified wrapper over client and server `tokio-rustls` streams. Implements `AsyncRead`, `AsyncWrite`, and `oxitls_core::TlsStreamInfo`.

| Method | Description |
|--------|-------------|
| `from_client(stream, info)` / `from_server(stream, info)` | Construct from a handshaked tokio-rustls stream (also via `From`) |
| `early_data(&mut self)` | Access the 0-RTT early-data writer (client) |
| `connection_info(&self) -> Option<&ConnectionInfo>` | Negotiated version, cipher, ALPN, peer certs, SNI |
| `export_keying_material(..)` | RFC 5705 exported keying material |
| `get_ref(&self)` / `into_inner(self)` | Borrow or unwrap the underlying transport |

### Session-ticket resumption — `ticketer` *(feature `pure`)*

| Item | Description |
|------|-------------|
| `OxiTicketer` | `rustls::server::ProducesTickets` backed by Pure-Rust AES-256-GCM (no ring) |
| `OxiTicketer::new()` | Default 6-hour ticket lifetime; two random keys from OS entropy |
| `OxiTicketer::new_with_lifetime(u32)` | Custom lifetime in seconds |
| `OxiTicketer::rotate()` | Promote current → previous key, generate a fresh current key |

### Anti-replay — `anti_replay` *(feature `pure`)*

RFC 8446 §8 single-use ticket protection for 0-RTT, wrapping any `ProducesTickets`.

| Item | Description |
|------|-------------|
| `AntiReplayTicketer<T, C>` | Wraps a ticketer with a time-windowed single-use replay guard |
| `ReplayGuard<C>` | SHA-256-keyed fingerprint store; `check_and_record(ticket) -> ReplayVerdict` |
| `ReplayVerdict` | `Fresh` or `Replayed` |
| `Clock` (trait), `SystemClock`, `MockClock` | Monotonic clock abstraction (mockable for tests) |

### Connection introspection

| Item | Description |
|------|-------------|
| `TlsConnectionExt` (trait, feature `pure`) | `tls_connection_info()` for `tokio_rustls::{client,server}::TlsStream<S>` |
| `connection_info_from_state(&CommonState) -> ConnectionInfo` | Extract metadata from a completed handshake (re-export) |

### Feature-gated modules

| Module | Feature | Description |
|--------|---------|-------------|
| `h2` | `h2` | HTTP/2 over TLS (re-exports [`oxitls-h2`](https://crates.io/crates/oxitls-h2)); also `H2Error`, `H2Settings`, `H2Reason` |
| `rcgen_bridge` | `rcgen` | Pure-Rust certificate generation (re-exports [`oxitls-rcgen`](https://crates.io/crates/oxitls-rcgen)) |
| `aws_lc` | `aws-lc` | aws-lc-rs provider (`aws_lc_provider`, `AwsLcTlsProvider`, `provider()`) — **not** Pure Rust |
| `quic_preview` | `quic-preview` | `pure_quic_provider()` — the Pure-Rust provider for QUIC handshakes |

### Re-exports at the crate root

From `oxitls-core`: `TlsError`, `CipherSuite`, `ConnectionInfo`, `TlsVersion`, `AlertDescription`, `KeyLog`, `KeyLogPolicy`, `TlsStreamInfo`.

From the Pure-Rust adapter *(feature `pure`)*: `client_config`, `server_config`, `pure_provider`, `connection_info_from_state`, `supported_cipher_suites`, `supported_versions`, `RustcryptoConnector`, `RustcryptoAcceptor`, `ClientConfig`, `ServerConfig`, `RootCertStore`, `ServerName`.

Ergonomic rustls re-exports *(feature `pure`)*: `ProtocolVersion`, `SupportedProtocolVersion`, `SubjectPublicKeyInfoDer`, `ConnectFuture<IO>`, `AcceptFuture<IO>`.

When `generic-transport` is enabled, `ClientBuilder` / `ServerBuilder` implement the `oxitls_core::GenericTlsConnector` / `GenericTlsAcceptor` GAT traits.

## Feature Flags

| Feature | Default | Pure Rust | Description |
|---------|---------|-----------|-------------|
| `pure` | ✅ | ✅ | Wires rustls + RustCrypto; enables builders, streams, ticketer, anti-replay |
| `webpki-roots` | ✅ | ✅ | Mozilla CA bundle via `oxitls-webpki-roots` |
| `h2` | — | ✅ | HTTP/2 over TLS via `oxitls-h2` |
| `rcgen` | — | ✅ | Pure-Rust certificate generation via `oxitls-rcgen` |
| `quic-preview` | — | ✅ | Re-exports the Pure-Rust provider for QUIC (implies `pure`) |
| `generic-transport` | — | ✅ | GAT-based generic connector/acceptor traits |
| `post-quantum` | — | ✅ | X25519MLKEM768 hybrid KX namespace (implies adapter `post-quantum`) |
| `aws-lc` | — | ❌ (C/FFI) | aws-lc-rs provider via `oxitls-adapter-aws-lc` |
| `pkcs11` | — | ❌ (loads a C module) | PKCS#11 HSM/TPM signer via `oxitls-adapter-pkcs11` |

## Error type

Most APIs return [`oxitls_core::TlsError`](https://crates.io/crates/oxitls-core), re-exported as `oxitls::TlsError`:

| Variant | Description |
|---------|-------------|
| `Io(io::ErrorKind)` | An I/O error, identified by kind |
| `Handshake(String)` | TLS handshake failure |
| `BadCert(String)` | Invalid or unacceptable certificate |
| `InvalidConfig(String)` | The TLS configuration is invalid |
| `CertRevoked(String)` | Certificate revoked (CRL or OCSP) |
| `CertInvalid(String)` | Certificate invalid (bad signature, malformed DER, expired) |
| `ProtocolViolation(String)` | The peer violated the TLS protocol |
| `AlertReceived(AlertDescription)` | A TLS alert was received |
| `Other(String)` | Any other TLS error |

## Cross-references

- [`oxitls-core`](https://crates.io/crates/oxitls-core) — shared traits and types.
- [`oxitls-adapter-rustls-rustcrypto`](https://crates.io/crates/oxitls-adapter-rustls-rustcrypto) — the default Pure-Rust crypto provider.
- [`oxitls-adapter-aws-lc`](https://crates.io/crates/oxitls-adapter-aws-lc) — aws-lc-rs provider (opt-in, **not** Pure Rust).
- [`oxitls-adapter-pkcs11`](https://crates.io/crates/oxitls-adapter-pkcs11) — PKCS#11 HSM/TPM signer (opt-in, **not** Pure Rust).
- [`oxitls-webpki-roots`](https://crates.io/crates/oxitls-webpki-roots) — Mozilla CA bundle and intermediate-cert cache.
- [`oxitls-h2`](https://crates.io/crates/oxitls-h2) — HTTP/2 over TLS.
- [`oxitls-rcgen`](https://crates.io/crates/oxitls-rcgen) — Pure-Rust certificate generation.
- `oxitls-bench` — internal benchmarks.

## License

Apache-2.0 — COOLJAPAN OU (Team Kitasan)
