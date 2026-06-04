# oxitls-adapter-pkcs11 — PKCS#11 HSM/TPM signing adapter for OxiTLS

[![Crates.io](https://img.shields.io/crates/v/oxitls-adapter-pkcs11.svg)](https://crates.io/crates/oxitls-adapter-pkcs11)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

`oxitls-adapter-pkcs11` lets OxiTLS servers keep their TLS private keys **inside a hardware security module (HSM) or TPM**. Instead of holding a private key in process memory, the rustls `SigningKey` delegates every signing operation to a PKCS#11 token over the [`cryptoki`](https://crates.io/crates/cryptoki) crate. This crate supplies a PKCS#11-backed `SigningKey`, a SNI-aware certificate resolver, a session pool, and a high-level provider that assembles a ready-to-use rustls `ServerConfig`. Supported key types are RSA, ECDSA P-256/P-384, and Ed25519.

> ⚠️ **This crate is NOT Pure Rust, and it requires an external runtime dependency.** The `cryptoki` crate dynamically loads a vendor-supplied PKCS#11 shared library (`.so` / `.dll` / `.dylib`) — C code outside the build closure — and a live token (HSM, TPM, or a software emulator such as SoftHSM2) must be present at run time. To preserve the COOLJAPAN Pure-Rust guarantee, **the entire bridge is feature-gated**: the crate's `default` feature set is empty, so merely depending on this crate without enabling `pkcs11` pulls in **no** non-Pure-Rust code. The default closure of the [`oxitls`](https://crates.io/crates/oxitls) facade never touches it.

The crypto provider used for the handshake itself is supplied by the caller, so the Pure-Rust [`oxitls-adapter-rustls-rustcrypto`](https://crates.io/crates/oxitls-adapter-rustls-rustcrypto) provider can perform all symmetric/KX work while only the asymmetric signature is offloaded to the HSM. Like every OxiTLS adapter, this crate **never** calls `CryptoProvider::install_default()`.

## Installation

```toml
[dependencies]
# Reserves the name but pulls in NO HSM/FFI code (default features are empty):
oxitls-adapter-pkcs11 = "0.1.1"

# Opt in to the PKCS#11 signing adapter:
oxitls-adapter-pkcs11 = { version = "0.1.1", features = ["pkcs11"] }
```

## Quick Start

All HSM-backed items are gated behind `#[cfg(feature = "pkcs11")]`.

```rust,no_run
# #[cfg(feature = "pkcs11")]
# {
use std::path::PathBuf;
use std::sync::Arc;
use secrecy::SecretString;
use oxitls_adapter_pkcs11::Pkcs11TlsProvider;

# fn example() -> Result<(), oxitls_adapter_pkcs11::Pkcs11Error> {
let provider = Pkcs11TlsProvider::new(
    PathBuf::from("/usr/lib/softhsm/libsofthsm2.so"),
    0,                            // slot index
    SecretString::from("1234"),   // user PIN
)?;

// The handshake crypto provider is Pure-Rust; only signing hits the HSM.
let crypto = Arc::new(rustls_rustcrypto::provider());
let _cfg = provider.server_config("my-cert", "my-key", crypto)?;
# Ok(())
# }
# }
```

### SoftHSM2 test setup

The integration tests are `#[ignore]`-gated and require a live token. To exercise them locally:

```text
# 1. Install SoftHSM2
brew install softhsm        # macOS
apt install softhsm2        # Debian/Ubuntu

# 2. Initialise a token
softhsm2-util --init-token --slot 0 --label oxitls-test --so-pin 5678 --pin 1234

# 3. Generate an EC P-256 key pair
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --slot 0 \
            --login --pin 1234 --keypairgen --key-type EC:prime256v1 --label test-ecdsa

# 4. Export env vars and run the ignored tests
export SOFTHSM2_MODULE=/usr/lib/softhsm/libsofthsm2.so
export SOFTHSM2_SLOT=0
export SOFTHSM2_PIN=1234
export SOFTHSM2_KEY_LABEL=test-ecdsa
export SOFTHSM2_CERT_LABEL=test-ecdsa
cargo test -p oxitls-adapter-pkcs11 --features pkcs11 -- --include-ignored
```

## API Overview

### Always available (no live HSM required)

These types are **not** feature-gated — they are usable for documentation and pattern-matching even without the `pkcs11` feature.

| Item | Kind | Description |
|------|------|-------------|
| `Pkcs11KeyInfo` | struct | Metadata for a key: `label`, `key_type`, `id` (`CKA_ID` bytes), `signing_capable` |
| `Pkcs11KeyType` | enum | `Rsa`, `EcdsaP256`, `EcdsaP384`, `Ed25519`, `Other(u64)` (raw `CKK_*`) |
| `Pkcs11Error` | enum | Production error type (see below) |
| `PkcsSignError` | enum | Legacy signer error type (kept for backward compatibility; `From<PkcsSignError>` for `Pkcs11Error`) |
| `TlsError` | re-export | `oxitls_core::TlsError` |

### `Pkcs11TlsProvider` *(feature `pkcs11`)*

High-level entry point: loads the module, opens a pooled set of sessions, and builds rustls configs.

| Method | Description |
|--------|-------------|
| `new(module_path, slot_index, pin) -> Result<Self, Pkcs11Error>` | Load the PKCS#11 module and open 4 logged-in sessions on the slot |
| `pool(&self) -> Arc<Pkcs11SessionPool>` | Clone the shared session pool |
| `signing_key(&self, label) -> Result<Arc<Pkcs11SigningKey>, Pkcs11Error>` | Build a signing key for the private key with the given `CKA_LABEL` |
| `cert_chain(&self, label) -> Result<Vec<CertificateDer<'static>>, Pkcs11Error>` | Fetch `CKO_CERTIFICATE` objects with the given label as DER |
| `server_config(&self, chain_label, key_label, provider) -> Result<ServerConfig, Pkcs11Error>` | Assemble a TLS 1.3 `ServerConfig` (cert from token, signing via HSM) |
| `server_config_sni(&self, sni_map, strict_sni, provider) -> Result<ServerConfig, Pkcs11Error>` | Multi-tenant SNI config; `sni_map: BTreeMap<host, (chain_label, key_label)>`, wildcard matching per RFC 6125 §6.4.3 |
| `list_keys(&self, label_filter) -> Result<Vec<Pkcs11KeyInfo>, Pkcs11Error>` | Enumerate `CKO_PRIVATE_KEY` objects (optionally filtered by label) |
| `import_cert(&self, cert_der, label) -> Result<(), Pkcs11Error>` | Import a DER certificate into the token under `label` |
| `slot(&self) -> Slot` | The chosen PKCS#11 slot |
| `module(&self) -> Arc<Pkcs11>` | The loaded `cryptoki` module |

> Note: distinguishing P-256 from P-384 requires an extra `CKA_EC_PARAMS` fetch, so `list_keys` currently classifies all `CKK_EC` keys as `EcdsaP256`.

### `Pkcs11SigningKey` *(feature `pkcs11`)*

A `rustls::sign::SigningKey` whose signatures are produced by the token.

| Method | Description |
|--------|-------------|
| `new(pool, key_label) -> Result<Self, Pkcs11Error>` | Pool-backed signing key; probes and caches the key algorithm at construction |
| `new_direct(module_path, slot, pin, key_label) -> Result<Self, PkcsSignError>` | Module-loading signing key that opens a fresh session per signature (legacy; prefer `new`) |

### `Pkcs11ServerCertResolver` *(feature `pkcs11`)*

A `rustls::server::ResolvesServerCert` that selects an HSM-backed `CertifiedKey` by SNI.

| Method | Description |
|--------|-------------|
| `new(chain, key)` | Single-certificate resolver |
| `with_sni_map(map)` | Multi-tenant resolver keyed by hostname (with wildcard support) |
| `with_strict_sni(bool)` | When `true`, reject connections whose SNI matches no entry |
| `lookup(&self, sni) -> Option<Arc<CertifiedKey>>` | Resolve the certified key for an SNI value |

### `Pkcs11SessionPool` / `PooledSession` *(feature `pkcs11`)*

| Item | Description |
|------|-------------|
| `Pkcs11SessionPool::new(module, slot, pin, capacity) -> Result<Self, Pkcs11Error>` | Open `capacity` logged-in sessions |
| `Pkcs11SessionPool::acquire(&self) -> Result<PooledSession<'_>, Pkcs11Error>` | Check out a session (`Pkcs11Error::SessionPoolExhausted` when none free) |
| `PooledSession::session(&self) -> &Session` | Borrow the underlying `cryptoki` session; returns to the pool on drop |

## Feature Flags

| Feature | Default | Pure Rust | Runtime requirement | Description |
|---------|---------|-----------|---------------------|-------------|
| *(none)* | ✅ | ✅ | none | Key-info types only; **no** FFI in the build closure |
| `pkcs11` | — | ❌ (loads a C PKCS#11 module) | a live HSM/TPM token (or SoftHSM2) | Enables the full signing adapter via `cryptoki`; also pulls in `secrecy`, `parking_lot`, and `tokio` |

## Error type — `Pkcs11Error`

| Variant | Description |
|---------|-------------|
| `InitError(String)` | Failed to load or initialize the PKCS#11 module/library |
| `SessionError(String)` | Failed to open, manage, or operate on a session |
| `KeyNotFound(String)` | No key or certificate object with the requested label was found |
| `SignError(String)` | The signing operation returned an error from the token |
| `SessionPoolExhausted` | The session pool has no available sessions |
| `HsmError { code: u32, msg: String }` | HSM-level error with the mapped `CKR_*` return code |
| `Unsupported(String)` | The operation is unsupported by this token/implementation |
| `LoadFailed(String)` | The PKCS#11 shared library could not be loaded |
| `Tls(String)` | A rustls-level error while building or using the TLS config |
| `Other(String)` | Catch-all |

The legacy `PkcsSignError` enum (`InitError`, `SessionError`, `KeyNotFound`, `SignError`, `InvalidSignatureLength { expected, got }`) is preserved for `new_direct` and converts into `Pkcs11Error` via `From`.

## Cross-references

- [`oxitls`](https://crates.io/crates/oxitls) — the Pure-Rust TLS facade; exposes this adapter behind its `pkcs11` feature.
- [`oxitls-adapter-rustls-rustcrypto`](https://crates.io/crates/oxitls-adapter-rustls-rustcrypto) — the **default Pure-Rust** crypto provider; pass its `pure_provider()` to `Pkcs11TlsProvider::server_config` so only the signature is offloaded to the HSM.
- [`oxitls-core`](https://crates.io/crates/oxitls-core) — shared traits and types (`TlsError`, …).
- [`oxitls-adapter-aws-lc`](https://crates.io/crates/oxitls-adapter-aws-lc) — aws-lc-rs provider (opt-in, **not** Pure Rust).

## License

Apache-2.0 — COOLJAPAN OU (Team Kitasan)
