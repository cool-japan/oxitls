# oxitls-adapter-rustls-rustcrypto — The Pure-Rust rustls CryptoProvider for OxiTLS

[![Crates.io](https://img.shields.io/crates/v/oxitls-adapter-rustls-rustcrypto.svg)](https://crates.io/crates/oxitls-adapter-rustls-rustcrypto)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

`oxitls-adapter-rustls-rustcrypto` is the **default Pure-Rust crypto backend** for the OxiTLS stack. It wires rustls to the [`rustls-rustcrypto`](https://crates.io/crates/rustls-rustcrypto) `CryptoProvider` — a 100% Rust implementation of TLS cryptography built on the RustCrypto crates (`p256`, `p384`, `ed25519-dalek`, `rsa`, `sha2`, …). No C, C++, or Fortran code enters the build closure: there is no `ring`, no `aws-lc-rs`, and no OpenSSL/libssl.

This crate provides everything needed to stand up a TLS client or server on the Pure-Rust provider: a per-config provider factory (it **never** calls `CryptoProvider::install_default()` — the provider is always injected per `ClientConfig`/`ServerConfig`), fluent `ClientConfig`/`ServerConfig` builders, `tokio-rustls`-backed connector/acceptor types, and a rich `verifier` module covering certificate pinning, CRL revocation, client-side OCSP stapling, Certificate Transparency (SCT) verification, and RFC 7250 raw public keys. The optional `post-quantum` feature reserves the namespace for the X25519MLKEM768 hybrid key-exchange group.

## Installation

```toml
[dependencies]
oxitls-adapter-rustls-rustcrypto = "0.1.1"

# With the post-quantum hybrid KX namespace (X25519MLKEM768):
oxitls-adapter-rustls-rustcrypto = { version = "0.1.1", features = ["post-quantum"] }
```

Most users should depend on the [`oxitls`](https://crates.io/crates/oxitls) facade instead, which re-exports this crate behind its default `pure` feature.

## Quick Start

### Server

```rust,no_run
use std::sync::Arc;
use oxitls_adapter_rustls_rustcrypto::{server_config, RustcryptoAcceptor};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

# fn load_cert() -> Vec<CertificateDer<'static>> { vec![] }
# fn load_key() -> PrivateKeyDer<'static> { unimplemented!() }
#[tokio::main]
async fn main() -> Result<(), oxitls_core::TlsError> {
    let certs: Vec<CertificateDer<'static>> = load_cert();
    let key: PrivateKeyDer<'static> = load_key();

    // `server_config` injects the Pure-Rust provider per-config.
    let cfg = server_config(certs, key)?;
    let acceptor = RustcryptoAcceptor::new(cfg);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8443").await
        .map_err(|e| oxitls_core::TlsError::Other(e.to_string()))?;
    let (tcp, _) = listener.accept().await
        .map_err(|e| oxitls_core::TlsError::Other(e.to_string()))?;
    let _tls = acceptor.accept_tcp(tcp).await?;
    Ok(())
}
```

### Client (fluent builder)

```rust,no_run
use oxitls_adapter_rustls_rustcrypto::RustcryptoClientConfigBuilder;
use rustls::RootCertStore;

# fn example() -> Result<(), oxitls_core::TlsError> {
let cfg = RustcryptoClientConfigBuilder::new()
    .with_roots(RootCertStore::empty())
    .with_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()])
    .build()?;
# Ok(())
# }
```

## API Overview

### Provider factories

| Function | Returns | Description |
|----------|---------|-------------|
| `pure_provider()` | `Arc<rustls::crypto::CryptoProvider>` | The Pure-Rust RustCrypto provider, for per-config injection |
| `pure_provider_with_pq()` *(feature `post-quantum`)* | `Arc<CryptoProvider>` | Same provider with `X25519MLKEM768` prepended to `kx_groups` (offered first in TLS 1.3 `ClientHello`) |

Neither function calls `install_default()`; inject via `ClientConfig::builder_with_provider` / `ServerConfig::builder_with_provider`.

### One-shot config builders

| Function | Description |
|----------|-------------|
| `client_config(root_store) -> Result<Arc<ClientConfig>, TlsError>` | Build a client config with safe default protocol versions and no client auth |
| `server_config(certs, key) -> Result<Arc<ServerConfig>, TlsError>` | Build a single-cert server config with no client auth |

### `RustcryptoClientConfigBuilder`

Fluent builder for `ClientConfig`. Chain methods, then call `build()`.

| Method | Description |
|--------|-------------|
| `new()` / `default()` | Empty root store, no pinning/CRL, keylog disabled, no ALPN |
| `with_roots(store)` | Set the root cert store for server-certificate validation |
| `with_pinned_certs(Vec<[u8; 32]>)` | Pin acceptable leaf certs by SHA-256 DER fingerprint |
| `with_crl(Vec<CertificateRevocationListDer>)` | Enable CRL-based revocation (ignored when pinning is set) |
| `with_keylog(KeyLogPolicy)` | Set the key-logging policy |
| `with_alpn(Vec<Vec<u8>>)` | Set the ALPN protocol list (preference order) |
| `with_intermediate_cache(Arc<IntermediateCertCache>)` | Record intermediate DER blobs after each successful handshake |
| `with_resumption_disabled()` | Disable session resumption entirely |
| `with_ocsp_policy(OcspClientPolicy)` | Validate the server's OCSP staple |
| `with_sct_policy(SctPolicy, CtLogList)` | Enforce embedded SCT / Certificate Transparency verification |
| `build() -> Result<ClientConfig, TlsError>` | Produce the config (verifier path: pinning > CRL > plain, then cache → OCSP → SCT wrappers) |

### `RustcryptoServerConfigBuilder`

Fluent builder for `ServerConfig`.

| Method | Description |
|--------|-------------|
| `new()` / `default()` | No cert/key, no client auth |
| `with_cert_and_key(certs, key)` | Set the certificate chain (leaf first) and private key |
| `with_ocsp_response(Vec<u8>)` | DER-encoded OCSP response for stapling (empty = ignored) |
| `with_client_auth(required, roots)` | Enable mutual TLS; `required=false` allows unauthenticated clients |
| `with_keylog(KeyLogPolicy)` | Set the key-logging policy |
| `with_alpn(Vec<Vec<u8>>)` | Set the ALPN protocol list |
| `with_ticketer(Arc<dyn ProducesTickets>)` | Use a custom session ticketer (e.g. cluster-shared) |
| `build() -> Result<ServerConfig, TlsError>` | Produce the config |

### Connector / Acceptor

| Type | Methods |
|------|---------|
| `RustcryptoConnector` | `new(Arc<ClientConfig>)`, `connect(server_name, stream)`, `connect_tcp(host, TcpStream) -> RustcryptoClientStream`. Also implements `oxitls_core::TlsConnector`. |
| `RustcryptoAcceptor` | `new(Arc<ServerConfig>)`, `accept(stream)`, `accept_tcp(TcpStream)`. Also implements `oxitls_core::TlsAcceptor`. |
| `RustcryptoClientStream` | A connected client stream with cached `ConnectionInfo`; implements `AsyncRead`, `AsyncWrite`, and `oxitls_core::TlsStreamInfo` |

### Convenience free functions

| Function | Description |
|----------|-------------|
| `connect_with_alpn(stream, host, alpn, roots) -> RustcryptoClientStream` | Build a client config with ALPN + roots and handshake in one call |
| `from_config_with_sni(stream, config, sni) -> RustcryptoClientStream` | Connect using an existing `Arc<ClientConfig>` and a string SNI |
| `accept_with_timeout(acceptor, stream, Duration)` | `accept_tcp` wrapped in a wall-clock timeout (`TlsError::Other` on timeout) |

### Introspection

| Function | Returns | Description |
|----------|---------|-------------|
| `supported_cipher_suites()` | `Vec<&'static str>` | Human-readable names of the provider's cipher suites |
| `supported_versions()` | `Vec<String>` | Supported TLS protocol versions (typically TLS 1.3 + TLS 1.2) |
| `connection_info_from_state(&rustls::CommonState)` | `oxitls_core::ConnectionInfo` | Extract version / cipher suite / ALPN from a completed handshake |

### `verifier` module

Custom server/client certificate verifiers, each implementing the relevant rustls verifier trait.

| Item | Kind | Description |
|------|------|-------------|
| `CertPinVerifier` | struct | SHA-256 leaf-fingerprint pinning over an inner verifier |
| `CrlAwareServerVerifier` | struct | CRL-backed revocation via `WebPkiServerVerifier` |
| `CustomServerVerifier` | struct | Inner verifier + a caller-supplied `CertPredicate` closure |
| `CertPredicate` | type alias | `dyn Fn(&CertificateDer, &[CertificateDer]) -> Result<ServerCertVerified, Error>` |
| `OcspClientVerifier` | struct | Client-side OCSP-staple validation (RFC 6960) wrapping an inner verifier |
| `OcspClientPolicy` | enum | `Disabled`, `SoftFail`, `HardRequire` |
| `SctVerifier` | struct | Certificate Transparency SCT verification (RFC 6962) with cryptographic signature checks |
| `SctPolicy` | enum | `Disabled`, `Permissive { min_distinct_logs }`, `Strict { min_distinct_logs }` |
| `CtLog`, `CtLogList`, `CtKeyAlg` | structs/enum | Trusted CT-log entries (`id`, `public_key_der`, `key_alg`); `CtKeyAlg` is `EcdsaP256Sha256` or `Ed25519` |
| `RawPublicKeyServerVerifier` | struct | RFC 7250 raw-public-key pinning (client checks server SPKI) |
| `RawPublicKeyClientVerifier` | struct | RFC 7250 raw-public-key pinning (server checks client SPKI, mTLS) |
| `server_raw_public_key_resolver(..)` | fn | Build a server cert resolver presenting a raw public key |
| `client_raw_public_key_resolver(..)` | fn | Build a client cert resolver presenting a raw public key |
| `known_ct_logs() -> &'static CtLogList` | fn | Embedded set of trusted CT-log public keys |

Lower-level SCT/OCSP plumbing (also public) includes `parse_sct_list`, `build_sct_signed_data`, `build_sct_signed_data_precert`, `precert_tbs_and_issuer_hash`, `verify_sct_signature`, and the `verifier::ocsp_crypto` helpers.

Top-level re-exports for convenience: `known_ct_logs`, `OcspClientPolicy`, `CtKeyAlg`, `CtLog`, `CtLogList`, `SctPolicy`.

### Post-quantum key exchange *(feature `post-quantum`)*

| Item | Description |
|------|-------------|
| `kx` module | X25519MLKEM768 hybrid KX (draft-ietf-tls-ecdhe-mlkem), TLS 1.3 only |
| `X25519MLKEM768` | `&'static dyn rustls::crypto::SupportedKxGroup`, wire value `0x11ec`; insert at index 0 of `kx_groups` |

The hybrid group concatenates an ML-KEM-768 share with an X25519 share (PQ-first) and exposes the classical X25519 component via `hybrid_component()` so non-PQ servers avoid a HelloRetryRequest. Backed by the `ml-kem` and `x25519-dalek` crates — still 100% Pure Rust.

### HPKE / Encrypted Client Hello *(feature `ech`)*

RFC 9180 base-mode HPKE provider, byte-exact against RFC 9180 Appendix A KAT vectors.

| Item | Description |
|------|-------------|
| `pure_hpke_suites() -> &'static [&'static dyn rustls::crypto::hpke::Hpke]` | Four suite statics: X25519/P-256 × AES-128-GCM/ChaCha20Poly1305 |
| `generate_ech_config_list(suite, config_id, public_name, max_name_len)` | Mint a publishable ECHConfigList from a fresh HPKE keypair; returns `GeneratedEchConfig { config_list, private_key }` |
| `GeneratedEchConfig` | Holds the publishable `config_list: Vec<u8>` and the operator's long-term `private_key` |

Internal modules: `hpke::kem` (DHKEM Encap/Decap over X25519 and P-256), `hpke::kdf` (LabeledExtract/LabeledExpand, HKDF-SHA256/SHA384), `hpke::aead` (Context seal/open, nonce management), `hpke::ech_config` (ECHConfigList serialisation), `hpke::vectors` (RFC 9180 KAT constants).

### Re-exported types

`ClientConfig`, `RootCertStore`, `ServerConfig` (from `rustls`); `CertificateDer`, `PrivateKeyDer`, `ServerName` (from `rustls-pki-types`); `TlsError` (from `oxitls-core`).

## Feature Flags

| Feature | Default | Pure Rust | Description |
|---------|---------|-----------|-------------|
| *(none)* | ✅ | ✅ | Pure-Rust rustls + RustCrypto provider, builders, verifiers |
| `post-quantum` | — | ✅ | X25519MLKEM768 hybrid KX group (`kx` module, `pure_provider_with_pq()`) |
| `ech` | — | ✅ | RFC 9180 HPKE base-mode for ECH: `pure_hpke_suites()`, `generate_ech_config_list(..)`; 4 suites (X25519/P-256 × AES-128-GCM/ChaCha20Poly1305); KAT-verified against RFC 9180 Appendix A |
| `cert-compression` | — | ✅ | RFC 8879 TLS certificate compression via OxiARC pure-Rust zlib (oxiarc-deflate) |

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
| `Other(String)` | Any other TLS error (e.g. handshake timeout) |

## Cross-references

- [`oxitls`](https://crates.io/crates/oxitls) — the Pure-Rust TLS facade; re-exports this adapter behind its `pure` feature.
- [`oxitls-core`](https://crates.io/crates/oxitls-core) — shared traits and types (`TlsError`, `ConnectionInfo`, `KeyLogPolicy`, `TlsConnector`, `TlsAcceptor`, `TlsStreamInfo`).
- [`oxitls-webpki-roots`](https://crates.io/crates/oxitls-webpki-roots) — Mozilla CA bundle and `IntermediateCertCache`.
- [`oxitls-rcgen`](https://crates.io/crates/oxitls-rcgen) — Pure-Rust certificate generation.
- [`oxitls-adapter-aws-lc`](https://crates.io/crates/oxitls-adapter-aws-lc) — aws-lc-rs provider (opt-in, **not** Pure Rust).
- [`oxitls-adapter-pkcs11`](https://crates.io/crates/oxitls-adapter-pkcs11) — PKCS#11 HSM/TPM signer (opt-in, **not** Pure Rust).

## License

Apache-2.0 — COOLJAPAN OU (Team Kitasan)
