# oxitls-adapter-aws-lc — aws-lc-rs backed rustls CryptoProvider for OxiTLS

[![Crates.io](https://img.shields.io/crates/v/oxitls-adapter-aws-lc.svg)](https://crates.io/crates/oxitls-adapter-aws-lc)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

`oxitls-adapter-aws-lc` is the **opt-in, non-Pure-Rust** crypto backend for the OxiTLS stack. It wires rustls to the [`aws-lc-rs`](https://crates.io/crates/aws-lc-rs) `CryptoProvider`, which is built on AWS-LC — a C cryptographic library. It exists for deployments that require AWS-LC's performance characteristics or its **FIPS 140-3** validated mode, and for parity testing against the Pure-Rust provider.

> ⚠️ **This crate is NOT Pure Rust.** The aws-lc-rs provider pulls C/FFI code (and, in FIPS builds, a C toolchain) into the build closure. To keep the COOLJAPAN Pure-Rust guarantee intact, **the entire provider is feature-gated**: the crate's `default` feature set is empty, so merely depending on this crate without enabling `aws-lc` brings in **no** C code. Enable the `aws-lc` feature only when you explicitly want the C-backed provider. The default closure of the [`oxitls`](https://crates.io/crates/oxitls) facade never touches it.

Like every OxiTLS adapter, this crate **never** calls `CryptoProvider::install_default()` — providers are always injected per `ClientConfig`/`ServerConfig`.

## Installation

```toml
[dependencies]
# Reserves the name but pulls in NO C code (default features are empty):
oxitls-adapter-aws-lc = "0.2.0"

# Opt in to the C-backed aws-lc-rs provider:
oxitls-adapter-aws-lc = { version = "0.2.0", features = ["aws-lc"] }
```

## Quick Start

All public provider items are gated behind `#[cfg(feature = "aws-lc")]`.

```rust,no_run
# #[cfg(feature = "aws-lc")]
# {
use oxitls_adapter_aws_lc::{aws_lc_provider, aws_lc_server_config};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

# fn load_cert() -> Vec<CertificateDer<'static>> { vec![] }
# fn load_key() -> PrivateKeyDer<'static> { unimplemented!() }
# fn example() -> Result<(), oxitls_core::TlsError> {
let certs: Vec<CertificateDer<'static>> = load_cert();
let key: PrivateKeyDer<'static> = load_key();

// One-shot server config (provider injected internally, ALPN optional):
let _server_cfg = aws_lc_server_config(certs, key, vec![b"h2".to_vec()])?;

// Or grab the bare provider for a custom rustls builder:
let provider = aws_lc_provider();
let _builder = rustls::ServerConfig::builder_with_provider(provider)
    .with_safe_default_protocol_versions()
    .map_err(|e| oxitls_core::TlsError::InvalidConfig(e.to_string()))?;
# Ok(())
# }
# }
```

## API Overview

> Every item below is compiled **only** when the `aws-lc` feature is enabled.

### Provider factories

| Function | Returns | Description |
|----------|---------|-------------|
| `aws_lc_provider()` | `Arc<rustls::crypto::CryptoProvider>` | The aws-lc-rs default provider, for per-config injection |
| `aws_lc_provider_tls12_only()` | `(Arc<CryptoProvider>, &'static [&SupportedProtocolVersion])` | The provider plus a TLS 1.2-only version slice |
| `aws_lc_provider_with_cipher_suites(&[SupportedCipherSuite])` | `Arc<CryptoProvider>` | Provider restricted to the given cipher suites |

### One-shot config builders

| Function | Description |
|----------|-------------|
| `aws_lc_client_config(roots, alpn) -> Result<ClientConfig, TlsError>` | Client config validating server certs against `roots`; empty `alpn` disables ALPN |
| `aws_lc_mtls_client_config(roots, client_cert_chain, client_key) -> Result<ClientConfig, TlsError>` | Mutual-TLS client config presenting a client certificate |
| `aws_lc_server_config(certs, key, alpn) -> Result<ServerConfig, TlsError>` | Single-cert server config; empty `alpn` disables ALPN |

### `AwsLcTlsProvider`

Ergonomic, `Clone`-able wrapper over the aws-lc-rs `CryptoProvider`.

| Method | Description |
|--------|-------------|
| `new()` / `default()` | Provider with the default aws-lc-rs configuration |
| `with_cipher_suites(&[SupportedCipherSuite])` | Provider restricted to the given cipher suites |
| `tls12_only(self) -> (Self, &'static [&SupportedProtocolVersion])` | Restrict to TLS 1.2 and return the required version slice |
| `is_fips(&self) -> bool` | Whether this provider is running in FIPS-approved mode |
| `cipher_suites(&self) -> Vec<String>` | Names of available cipher suites |
| `kx_groups(&self) -> Vec<String>` | Names of available key-exchange groups |
| `client_config(&self, roots) -> Result<ClientConfig, TlsError>` | Build a client config (no ALPN) |
| `mtls_client_config(&self, roots, cert_chain, key) -> Result<ClientConfig, TlsError>` | Build a mutual-TLS client config |
| `server_config(&self, cert_chain, key) -> Result<ServerConfig, TlsError>` | Build a server config (no ALPN) |
| `as_provider(&self) -> &Arc<CryptoProvider>` | Access the inner provider |

### FIPS introspection

| Function | Description |
|----------|-------------|
| `is_fips_mode() -> bool` | `true` only when aws-lc-rs was compiled with FIPS **and** the module initialised; `false` under a standard build |

### Session-ticket rotation

| Item | Description |
|------|-------------|
| `AwsLcTicketRotator` | A `rustls::server::ProducesTickets` implementation backed by aws-lc-rs AES-256-GCM with automatic key rotation |
| `AwsLcTicketRotator::new(Duration) -> Result<Arc<Self>, TlsError>` | Create a rotator and spawn the background rotation task (**requires a Tokio runtime**) |
| `AwsLcTicketRotator::generation(&self) -> u64` | Current rotation generation count |

Wire format: `nonce (12) ‖ ciphertext_with_tag (n + 16)`. Decryption tries the current key, then falls back to the previous key so tickets issued before a rotation stay valid. Ticket lifetime is `2 × rotation_interval` (clamped to ≥ 1 s). The background task is aborted on drop.

### Introspection helpers

| Function | Returns | Description |
|----------|---------|-------------|
| `supported_cipher_suites()` | `Vec<String>` | Cipher-suite names of the default aws-lc-rs provider |
| `supported_kx_groups()` | `Vec<String>` | Key-exchange-group names of the default aws-lc-rs provider |

### `error` module — conversion helpers

Because `aws_lc_rs::error::*` and `rustls::Error` are foreign types, the orphan rule blocks `From` impls; standalone functions are provided instead.

| Function | Maps to |
|----------|---------|
| `unspecified_to_tls_error(Unspecified)` | `TlsError::Other` |
| `key_rejected_to_tls_error(KeyRejected)` | `TlsError::InvalidConfig` |
| `rustls_error_to_tls_error(rustls::Error)` | The matching `TlsError` variant (mirrors `oxitls-core`) |

### Re-exports

`TlsError` (from `oxitls-core`); `AwsLcTlsProvider`, `aws_lc_provider`, `aws_lc_client_config`, `aws_lc_mtls_client_config`, `aws_lc_server_config`, `is_fips_mode`, `AwsLcTicketRotator` — all under `#[cfg(feature = "aws-lc")]`.

## Feature Flags

| Feature | Default | Pure Rust | Description |
|---------|---------|-----------|-------------|
| *(none)* | ✅ | ✅ | Name reserved; **no** C code in the build closure |
| `aws-lc` | — | ❌ (C/FFI) | Enables the aws-lc-rs provider via `rustls/aws_lc_rs`. Pulls AWS-LC C code |

## Error type

All fallible functions return [`oxitls_core::TlsError`](https://crates.io/crates/oxitls-core):

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
| `Other(String)` | Any other TLS error (e.g. RNG failure during key generation) |

## Cross-references

- [`oxitls`](https://crates.io/crates/oxitls) — the Pure-Rust TLS facade; exposes this provider behind its `aws-lc` feature (`oxitls::aws_lc`).
- [`oxitls-adapter-rustls-rustcrypto`](https://crates.io/crates/oxitls-adapter-rustls-rustcrypto) — the **default Pure-Rust** provider; prefer it unless you specifically need AWS-LC or FIPS.
- [`oxitls-core`](https://crates.io/crates/oxitls-core) — shared traits and types (`TlsError`, `ConnectionInfo`, …).
- [`oxitls-adapter-pkcs11`](https://crates.io/crates/oxitls-adapter-pkcs11) — PKCS#11 HSM/TPM signer (opt-in, **not** Pure Rust).

## License

Apache-2.0 — COOLJAPAN OU (Team Kitasan)
