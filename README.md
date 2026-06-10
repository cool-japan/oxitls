# OxiTLS

OxiTLS is the COOLJAPAN-blessed Pure Rust TLS transport stack. It provides TLS
1.2 and 1.3 client and server support with a Pure-Rust `CryptoProvider` wired at
the default-feature path, while still offering opt-in `ffi` adapters for FIPS or
high-throughput consumers who knowingly accept the C dependency.

## Status: v0.1.2 — Active Development

All M0–M5 milestones complete, plus Waves 6–9, the v0.1.1 ECH/HPKE feature, and RFC 8879 cert compression.
**424 tests** passing across 9 subcrates (~26 000 SLOC).

## Why OxiTLS?

The Phase 1 audit of `oxigdal` confirmed that `ring` (C + assembly) leaks into
every workspace that touches the AWS / Azure / Google SDK chain via
`aws-config → aws-smithy-runtime → hyper-rustls → rustls → ring`. OxiTLS is the
ecosystem-wide remediation for that contamination.

## Crate Layout

| Crate | Purpose | Default? |
|-------|---------|---------|
| `oxitls-core` | Core traits, types, `OsRng` adapter | Yes |
| `oxitls-adapter-rustls-rustcrypto` | Pure-Rust CryptoProvider | Yes |
| `oxitls-webpki-roots` | Root store, intermediate cache, native roots | Yes |
| `oxitls-h2` | HTTP/2 over TLS (generic streams) | Optional |
| `oxitls-rcgen` | Pure-Rust X.509 certificate generation | Optional |
| `oxitls-adapter-aws-lc` | aws-lc-rs adapter (bounded FFI) | No (opt-in) |
| `oxitls-adapter-pkcs11` | HSM/TPM adapter via PKCS#11 (bounded FFI) | No (opt-in) |
| `oxitls` | High-level facade (`ClientBuilder`, `ServerBuilder`) | — |
| `oxitls-bench` | Benchmark harness (not published) | — |

## Features

```toml
[dependencies]
oxitls = "0.1.2"
# Pure Rust TLS + WebPKI roots (default)
# For HTTP/2:
oxitls = { version = "0.1.2", features = ["h2"] }
# For certificate generation:
oxitls = { version = "0.1.2", features = ["rcgen"] }
# For FIPS / high-throughput (C dependency, off by default):
oxitls = { version = "0.1.2", features = ["aws-lc"] }
# For HSM/TPM via PKCS#11 (C dependency, off by default):
oxitls = { version = "0.1.2", features = ["pkcs11"] }
# For post-quantum key exchange (X25519+ML-KEM-768):
oxitls = { version = "0.1.2", features = ["post-quantum"] }
```

## Quick Start

### TLS Client

```rust
use oxitls::{ClientBuilder, TlsError};

#[tokio::main]
async fn main() -> Result<(), TlsError> {
    let stream = ClientBuilder::new()
        .server_name("example.com")
        .connect("example.com:443")
        .await?;
    Ok(())
}
```

### TLS Server

```rust
use oxitls::{ServerBuilder, TlsError};

#[tokio::main]
async fn main() -> Result<(), TlsError> {
    let acceptor = ServerBuilder::new()
        .with_cert_pem(cert_pem, key_pem)?
        .with_alpn(&["h2", "http/1.1"])
        .build()?;
    Ok(())
}
```

### Certificate Generation (`oxitls-rcgen` feature)

```rust
use oxitls_rcgen::{generate_self_signed_ed25519, generate_ca, SigningAlgorithm};

let leaf = generate_self_signed_ed25519(&["localhost", "127.0.0.1"])?;
let ca = generate_ca("My Root CA", SigningAlgorithm::EcdsaP256)?;
```

## Replaces (FFI being eliminated)

- `openssl` / `openssl-sys`
- `native-tls`
- `ring` (as direct dep — stays off the default feature path)
- `aws-lc-rs` (off the default path; opt-in only via the `aws-lc` feature)

## Anchor Crates (Pure Rust)

- [`rustls`](https://crates.io/crates/rustls) — TLS protocol engine with pluggable `CryptoProvider`
- [`rustls-rustcrypto`](https://crates.io/crates/rustls-rustcrypto) — Pure-Rust provider backed by RustCrypto
- [`rustls-pki-types`](https://crates.io/crates/rustls-pki-types) — typed certificate, key, and private-key representations
- [`rustls-webpki`](https://crates.io/crates/rustls-webpki) — Pure-Rust X.509 path validation
- [`rcgen`](https://crates.io/crates/rcgen) — certificate generation (default-features = false)

## Key Capabilities

### Pure Rust TLS (default)
- TLS 1.3 and TLS 1.2 fallback
- ALPN negotiation and SNI dispatch
- mTLS (mutual TLS / client certificate authentication)
- Session resumption (tickets and session IDs)
- 0-RTT early data with anti-replay protection
- OCSP stapling (server-side injection + client-side verification)
- Certificate Transparency (SCT) verification
- CRL (Certificate Revocation List) checking
- Certificate pinning
- Key logging (`SSLKEYLOGFILE`) for Wireshark debugging
- Post-quantum key exchange: X25519+ML-KEM-768 (`post-quantum` feature)
- Encrypted Client Hello — RFC 9180 HPKE base-mode (`ech` feature): GREASE + real ECH config-list; KAT-verified against RFC 9180 Appendix A
- TLS certificate compression — RFC 8879 zlib via OxiARC Pure Rust (`cert-compression` feature)

### Certificate Generation (`oxitls-rcgen`)
- Ed25519, ECDSA-P256, ECDSA-P384, RSA-2048, RSA-4096 key pairs
- Self-signed, CA-signed, and intermediate CA certificates
- CSR generation and signing
- PKCS#12 (PFX) export
- X.509 extensions: SAN, EKU, name constraints, CRL distribution points, AIA/OCSP URL
- SubjectKeyIdentifier and AuthorityKeyIdentifier computation

### HTTP/2 (`oxitls-h2`)
- Generic stream type (not hardcoded to `TcpStream`)
- H2 settings builder (window size, frame size, concurrent streams)
- Server push support

### Root Store (`oxitls-webpki-roots`)
- Bundled WebPKI root certificates
- LRU intermediate certificate cache
- Filtering, merging, and exclusion by fingerprint
- Expiring roots support
- Platform native root store (`native-roots` feature)

### Opt-In FFI Adapters
- `oxitls-adapter-aws-lc`: aws-lc-rs CryptoProvider (FIPS, high throughput)
- `oxitls-adapter-pkcs11`: HSM/TPM via cryptoki PKCS#11 (SoftHSM tested)

## Inter-Oxi Dependencies

- **Depends on:** [`oxicrypto`](https://github.com/cool-japan/oxicrypto) for
  cryptographic primitives (AEAD, hash, MAC, signature, KEX, RNG).
- **Depended on by:** `oxigdal-cloud`, `oxigdal-gateway`, `oxigdal-websocket`,
  `oximedia-cloud`, `oxirouter`, `oxirag`, `oxigenai`, `oxillama`, `oxirs`.

## MSRV

Rust 1.89 (edition 2021)

## License

Apache-2.0

Copyright 2026 COOLJAPAN OU (Team Kitasan)
