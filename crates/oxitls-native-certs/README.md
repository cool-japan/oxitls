# oxitls-native-certs — OS-native certificate-store adapter for OxiTLS

[![Crates.io](https://img.shields.io/crates/v/oxitls-native-certs.svg)](https://crates.io/crates/oxitls-native-certs)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

`oxitls-native-certs` is the **quarantine crate** for OS-native certificate-store access in the OxiTLS ecosystem. It loads the platform's root CA store via `Security.framework` on macOS and `SChannel` on Windows; on Linux it reads the standard PEM bundle, keeping that path pure Rust.

> **Quarantine design**: because the macOS and Windows paths pull in platform FFI shims (`security-framework` / `schannel`), this functionality lives in its own opt-in crate rather than behind a feature flag on `oxitls-webpki-roots`. The `oxitls` facade and `oxitls-webpki-roots` remain **100% Pure Rust** — apps that need OS-native trust roots add this crate directly.

## When to use this crate

- You need to trust the same certificates as the OS (corporate CAs, user-installed roots).
- You are writing an application and can accept the FFI dependency on macOS/Windows.
- You want native roots **in addition to** the Mozilla bundle from `oxitls-webpki-roots`.

For most applications the bundled Mozilla CA bundle in `oxitls-webpki-roots` (the default `webpki-roots` feature of `oxitls`) is sufficient.

## Installation

```toml
[dependencies]
oxitls-native-certs = "0.2.1"
```

Note: `oxitls-native-certs` is **not** a feature of the `oxitls` facade — add it directly to your `Cargo.toml`.

## Quick Start

```rust,no_run
use oxitls_native_certs::load_native_roots;

#[tokio::main]
async fn main() -> Result<(), oxitls_core::TlsError> {
    let store = load_native_roots().await?;
    println!("Loaded {} native root(s)", store.len());
    Ok(())
}
```

### Combine with Mozilla roots

```rust,no_run
use oxitls_native_certs::load_native_roots;
use oxitls_webpki_roots::webpki_root_certs;
use oxitls_webpki_roots::merge_root_stores;

#[tokio::main]
async fn main() -> Result<(), oxitls_core::TlsError> {
    let mozilla = webpki_root_certs();
    let native = load_native_roots().await?;
    let combined = merge_root_stores(&[mozilla, native]);
    // Use `combined` with ClientBuilder::with_root_store_builder(...)
    Ok(())
}
```

## API

### `load_native_roots() -> Result<RootCertStore, TlsError>`

Loads the OS-native root certificate store into a `rustls::RootCertStore`.

| Platform | Source | FFI? |
|----------|--------|------|
| macOS | Security.framework (User/Admin/System trust domains) | Yes (`security-framework`) |
| Linux | First PEM bundle found in standard locations | No (pure Rust) |
| Windows | Current-user `ROOT` store via SChannel | Yes (`schannel`) |
| Other | Returns `TlsError::Other` | — |

The macOS and Windows calls are wrapped in `tokio::task::spawn_blocking` — Keychain and SChannel calls can take tens of milliseconds and would otherwise stall the async executor.

All loaders are best-effort: malformed certificates in the host store are skipped rather than aborting the entire load. An empty store is returned (not an error) if the OS store is accessible but contains no acceptable certificates — check `store.is_empty()` if a populated store is required.

## Platform notes

**macOS**: Queries trust settings across the User, Admin, and System domains. Certificates with `TrustRoot`, `TrustAsRoot`, or empty trust settings (which Apple docs define as "always trust") are included. Denied and unspecified-SSL certs are excluded.

**Linux**: Reads the first PEM bundle found at (in order):
1. `/etc/ssl/certs/ca-certificates.crt` (Debian/Ubuntu/Alpine)
2. `/etc/pki/tls/cert.pem` (RHEL/CentOS/Fedora)
3. `/etc/ssl/cert.pem` (OpenBSD-style / some musl distros)

**Windows**: Opens the current-user `ROOT` certificate store and collects all certs.

## Cross-references

- **`oxitls-webpki-roots`** — bundled Mozilla CA store (pure Rust, no FFI). The default trust source for the `oxitls` facade.
- **`oxitls`** — the facade; does NOT depend on this crate by default.
- **`oxitls-core`** — defines `TlsError`, returned by `load_native_roots()`.

## License

Apache-2.0 — COOLJAPAN OU (Team Kitasan)
