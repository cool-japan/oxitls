# oxitls-core — Core traits and types for OxiTLS

[![Crates.io](https://img.shields.io/crates/v/oxitls-core.svg)](https://crates.io/crates/oxitls-core)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

`oxitls-core` defines the foundational API surface shared across the OxiTLS ecosystem: error types, TLS version and cipher-suite enumerations, post-handshake connection metadata, key-logging policy, RFC 8446 alert codes, and the object-safe connector/acceptor traits that every OxiTLS adapter implements. It contains **no handshake logic** — concrete TLS providers live in the adapter crates (`oxitls-adapter-rustls-rustcrypto`, `oxitls-adapter-aws-lc`, `oxitls-adapter-pkcs11`) and are surfaced through the `oxitls` façade.

This crate is **Pure Rust** (`#![forbid(unsafe_code)]`). It builds on `rustls` for the underlying TLS state types; combined with the RustCrypto-backed provider (`oxitls-adapter-rustls-rustcrypto`) the whole stack contains no C/C++/Fortran. The OS-entropy adapter [`OsRng`] is sourced from `getrandom` and intentionally implements the `rand_core` 0.6 traits required by `rsa`, `ed25519-dalek`, and `x25519-dalek`.

## Installation

```toml
[dependencies]
oxitls-core = "0.3.1"
```

To opt into the generic (transport-preserving) connector/acceptor traits:

```toml
[dependencies]
oxitls-core = { version = "0.3.1", features = ["generic-transport"] }
```

## Quick Start

```rust
use oxitls_core::{CipherSuite, ConnectionInfoBuilder, TlsVersion};

// Build post-handshake connection metadata (adapters populate this for you).
let info = ConnectionInfoBuilder::new()
    .version(TlsVersion::Tls13)
    .cipher_suite(CipherSuite::Tls13Aes256GcmSha384)
    .alpn_protocol(b"h2".to_vec())
    .sni("example.com".to_string())
    .build();

assert_eq!(info.version, Some(TlsVersion::Tls13));
assert_eq!(info.alpn_protocol_str(), Some("h2"));
```

### Inspecting cipher suites

```rust
use oxitls_core::CipherSuite;

let suite = CipherSuite::Tls13Aes128GcmSha256;
assert_eq!(suite.iana_value(), [0x13, 0x01]);
assert!(suite.is_tls13());
assert_eq!(CipherSuite::from_iana([0x13, 0x01]), Some(suite));
```

### Implementing a connector

```rust,ignore
use std::future::Future;
use std::pin::Pin;
use oxitls_core::{TlsConnector, TlsError, TlsStream};

struct MyConnector { /* provider config */ }

impl TlsConnector for MyConnector {
    fn connect(
        &self,
        stream: TlsStream,
        server_name: rustls::pki_types::ServerName<'static>,
    ) -> Pin<Box<dyn Future<Output = Result<TlsStream, TlsError>> + Send + '_>> {
        Box::pin(async move {
            // perform the client handshake over `stream` …
            Ok(stream)
        })
    }
}
```

## API Overview

### `TlsVersion` enum

TLS protocol version. Implements `Display` and `FromStr` (accepts `"TLS 1.3"`, `"tls1.3"`, `"TLSv1.3"`, `"1.3"`, and the 1.2 equivalents).

| Variant | Meaning |
|---------|---------|
| `Tls12` | TLS 1.2 (RFC 5246) |
| `Tls13` | TLS 1.3 (RFC 8446) |

`TlsVersion::ALL` is a `&'static [TlsVersion]` of all versions in ascending order.

### `CipherSuite` enum

`#[non_exhaustive]` identifiers covering the TLS 1.3 mandatory suites and the common TLS 1.2 AEAD suites. Implements `Display`, `FromStr`, `Copy`, `Eq`, `Hash`.

| Variant | IANA | Protocol |
|---------|------|----------|
| `Tls13Aes128GcmSha256` | `13 01` | TLS 1.3 |
| `Tls13Aes256GcmSha384` | `13 02` | TLS 1.3 |
| `Tls13Chacha20Poly1305Sha256` | `13 03` | TLS 1.3 |
| `Tls12EcdheEcdsaAes128GcmSha256` | `C0 2B` | TLS 1.2 |
| `Tls12EcdheEcdsaAes256GcmSha384` | `C0 2C` | TLS 1.2 |
| `Tls12EcdheRsaAes128GcmSha256` | `C0 2F` | TLS 1.2 |
| `Tls12EcdheRsaAes256GcmSha384` | `C0 30` | TLS 1.2 |
| `Tls12EcdheEcdsaChacha20Poly1305Sha256` | `CC A9` | TLS 1.2 |
| `Tls12EcdheRsaChacha20Poly1305Sha256` | `CC A8` | TLS 1.2 |
| `Unknown` | `FF FF` | catch-all |

| Method | Description |
|--------|-------------|
| `iana_value()` | Returns the IANA two-byte identifier (`[0x00, 0x00]`/`[0xFF,0xFF]` semantics per docs) |
| `from_iana(bytes)` | Look up a suite from its IANA two-byte identifier → `Option<Self>` |
| `is_tls13()` | True for a TLS 1.3 suite |
| `is_tls12()` | True for a TLS 1.2 suite |
| `is_unknown()` | True for the `Unknown` catch-all |
| `CipherSuite::ALL` | `&'static [CipherSuite]` of all named suites (excludes `Unknown`) |

### `ConnectionInfo` struct

Metadata about a completed TLS connection, populated incrementally by adapter crates after the handshake. Implements `Clone`, `Default`.

| Field | Type | Description |
|-------|------|-------------|
| `version` | `Option<TlsVersion>` | Negotiated TLS protocol version |
| `cipher_suite` | `Option<CipherSuite>` | Negotiated cipher suite |
| `alpn_protocol` | `Option<Vec<u8>>` | Negotiated ALPN protocol bytes |
| `sni` | `Option<String>` | Server Name Indication value |
| `peer_certificates` | `Vec<Vec<u8>>` | DER-encoded peer certificates (leaf first) |

| Method | Description |
|--------|-------------|
| `new()` | Empty `ConnectionInfo` (all `None` / empty) |
| `with_version(v)` | Consuming setter for the TLS version |
| `with_cipher_suite(s)` | Consuming setter for the cipher suite |
| `with_alpn_protocol(p)` | Consuming setter for the ALPN bytes |
| `with_sni(s)` | Consuming setter for the SNI name |
| `with_peer_certificates(c)` | Consuming setter for the peer cert chain |
| `alpn_protocol_str()` | ALPN protocol as `&str` if valid UTF-8 |

### `ConnectionInfoBuilder` struct

Fluent builder for [`ConnectionInfo`] using snake_case setters (`version()`, `cipher_suite()`, `alpn_protocol()`, `sni()`, `peer_certificates()`) terminated by `build()`. Implements `Default`.

### Stream traits

| Item | Kind | Description |
|------|------|-------------|
| `TlsStream` | type alias | `Box<dyn TlsStreamTrait>` — a boxed async TLS stream |
| `TlsStreamTrait` | trait | Blanket trait alias for `AsyncRead + AsyncWrite + Send + Sync + Unpin` |
| `TlsConnector` | trait | Object-safe outbound connector: `connect(stream, server_name) -> Future<Result<TlsStream, TlsError>>` |
| `TlsAcceptor` | trait | Object-safe inbound acceptor: `accept(stream) -> Future<Result<TlsStream, TlsError>>` |
| `TlsStreamInfo` | trait | Exposes post-handshake `connection_info() -> Option<&ConnectionInfo>` (default returns `None`) |

`TlsConnector` and `TlsAcceptor` are object-safe (usable via `Box<dyn …>` / `Arc<dyn …>`).

### Generic transport traits (feature `generic-transport`)

Transport-preserving variants that retain the concrete underlying stream type `S` via a generic associated type, avoiding heap allocation of the transport (only the returned future is boxed). These traits are **not** object-safe — use them through generic bounds.

| Item | Description |
|------|-------------|
| `GenericTlsFuture<'a, T>` | `Pin<Box<dyn Future<Output = Result<T, TlsError>> + Send + 'a>>` |
| `GenericTlsConnector` | `connect<S>(stream, server_name) -> GenericTlsFuture<Self::Stream<S>>` |
| `GenericTlsAcceptor` | `accept<S>(stream) -> GenericTlsFuture<Self::Stream<S>>` |

### `TlsError` enum

`#[non_exhaustive]` error type. Implements `std::error::Error`, `Display`, `Clone`, `PartialEq`, and `From<io::Error>` / `From<rustls::Error>` (plus `From<TlsError> for io::Error`).

| Variant | Description |
|---------|-------------|
| `Io(io::ErrorKind)` | An I/O error, identified by its kind |
| `Handshake(String)` | A TLS handshake error |
| `BadCert(String)` | An invalid or unacceptable certificate |
| `InvalidConfig(String)` | The TLS configuration is invalid |
| `CertRevoked(String)` | A certificate has been revoked (CRL or OCSP) |
| `CertInvalid(String)` | Bad signature, malformed DER, expired, etc. |
| `ProtocolViolation(String)` | The peer violated the TLS protocol |
| `AlertReceived(AlertDescription)` | A TLS alert was received from the peer |
| `Other(String)` | Any other TLS error |

Predicate helpers: `is_handshake()`, `is_io()`, `is_cert()` (true for `BadCert`/`CertRevoked`/`CertInvalid`), `is_config()`, `is_protocol_violation()`.

### `alert` module — `AlertDescription`

`#[non_exhaustive]` enum of RFC 8446 §6 alert codes (also re-exported at the crate root). Implements `Display`, `Eq`, `Clone`, `From<u8>`, and `to_u8()`. Covers the standard alerts (`CloseNotify` = 0, `HandshakeFailure` = 40, `BadCertificate` = 42, `UnknownCa` = 48, `DecryptError` = 51, `ProtocolVersion` = 70, `NoApplicationProtocol` = 120, …) with an `Unknown(u8)` catch-all carrying any unrecognised code.

### `keylog` module

| Item | Description |
|------|-------------|
| `KeyLog` (trait) | `Send + Sync + Debug`; `log(label, client_random, secret)` records a session secret in NSS Key Log Format |
| `KeyLogPolicy` (enum) | `Disabled` (default) / `File(PathBuf)` (SSLKEYLOGFILE) / `Custom(Arc<dyn KeyLog>)`; `Clone`, `Debug` |

Both are re-exported at the crate root.

### `config` module — `TlsConfig` trait

Generic introspection trait implemented by adapter config structs so higher-level crates can read effective parameters without depending on adapter-specific types.

| Method | Description |
|--------|-------------|
| `protocol_versions()` | Enabled `&[TlsVersion]` |
| `alpn_protocols()` | Advertised ALPN identifiers (`&[Vec<u8>]`), in preference order |
| `sni_name()` | SNI server name, if any (`Option<&str>`) |
| `cipher_suites()` | Enabled `&[CipherSuite]` (default: empty = provider default) |

### `os_rng` module — `OsRng`

OS-entropy CSPRNG (`Clone`, `Copy`, `Debug`, `Default`) implementing the `rand_core` 0.6 `RngCore` + `CryptoRng` traits required by `rsa` 0.9, `ed25519-dalek` 2.x, and `x25519-dalek` 2.x. Entropy is drawn from `getrandom`, decoupling these crates from the workspace `rand`/`rand_core` 0.10. Re-exported at the crate root.

### `stream_info` module — `connection_info_from`

Helper for adapters to build a [`ConnectionInfo`] from a rustls connection state without orphan-rule problems. Re-exported at the crate root.

```rust,ignore
let info = oxitls_core::connection_info_from(&tls_conn).unwrap_or_default();
```

Accepts any `C: Deref<Target = rustls::CommonState>` and returns `None` until the handshake has completed. SNI is **not** populated here (only available on `ServerConnection`); call `with_sni()` afterwards if needed.

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `generic-transport` | off | Enables the transport-preserving `GenericTlsConnector` / `GenericTlsAcceptor` GAT traits and `GenericTlsFuture` |

## Cross-references

- **`oxitls`** — the façade that re-exports these types and wires up a provider.
- **`oxitls-adapter-rustls-rustcrypto`** — the default Pure-Rust provider implementing `TlsConnector` / `TlsAcceptor`.
- **`oxitls-adapter-aws-lc`**, **`oxitls-adapter-pkcs11`** — alternative providers.
- **`oxitls-h2`** — HTTP/2 over TLS streams; converts `H2Error` into [`TlsError`].
- **`oxitls-rcgen`** — certificate generation; errors surface as [`TlsError`].
- **`oxitls-webpki-roots`** — bundled Mozilla root CA store.

## License

Apache-2.0 — COOLJAPAN OU (Team Kitasan)
