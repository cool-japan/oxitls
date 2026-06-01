# oxitls-rcgen — Pure-Rust X.509 certificate generation for OxiTLS

[![Crates.io](https://img.shields.io/crates/v/oxitls-rcgen.svg)](https://crates.io/crates/oxitls-rcgen)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

`oxitls-rcgen` is the certificate-generation crate for the OxiTLS ecosystem. It bridges the [`rcgen`] X.509 builder to **OxiCrypto signing primitives** (`ed25519-dalek`, `p256`, `p384`, `rsa`) so that self-signed certificates, CA hierarchies, and CSR signing all happen with **no `ring` and no `aws-lc-rs`** in the dependency closure. The generated artifacts plug straight into a `rustls` `ClientConfig`/`ServerConfig` via `rustls-pki-types`.

The crate is **Pure Rust** (`#![forbid(unsafe_code)]`): key generation uses OS entropy through `getrandom`, signatures are produced by the RustCrypto crates, and PKCS#12 export uses the pure-Rust `p12` crate (no OpenSSL). It is surfaced through the `oxitls` façade behind the `rcgen` feature.

## Installation

```toml
[dependencies]
oxitls-rcgen = "0.1.0"
```

Via the façade:

```toml
[dependencies]
oxitls = { version = "0.1.0", features = ["rcgen"] }
```

## Quick Start

```rust,no_run
use oxitls_rcgen::{generate_self_signed_ed25519, generate_self_signed_p256};

# fn main() -> Result<(), oxitls_core::TlsError> {
// Ed25519 self-signed cert for localhost.
let ck = generate_self_signed_ed25519(&["localhost"])?;
// ck.cert_der  — DER bytes for rustls
// ck.pkcs8_der — PKCS#8 DER private key for rustls
// ck.cert_pem  — PEM-encoded certificate

// P-256 self-signed cert.
let _ck2 = generate_self_signed_p256(&["example.com"])?;

// Hand the leaf straight to rustls:
let (_chain, _key) = ck.to_rustls_cert_and_key();
# Ok(())
# }
```

### CA hierarchy

```rust,no_run
use oxitls_rcgen::{
    generate_ca, generate_intermediate_ca, generate_ca_signed_leaf, SigningAlgorithm,
};

# fn main() -> Result<(), oxitls_core::TlsError> {
// Root CA → intermediate CA → leaf, all Ed25519.
let root = generate_ca("My Root CA", SigningAlgorithm::Ed25519)?;
let intermediate = generate_intermediate_ca("My Intermediate CA", SigningAlgorithm::Ed25519, &root)?;
let leaf = generate_ca_signed_leaf(&["example.com"], SigningAlgorithm::Ed25519, &intermediate)?;

println!("{leaf}"); // multi-line Subject / Algorithm / SHA-256 / Not after summary
# Ok(())
# }
```

### CSR generation and signing

```rust,no_run
use oxitls_rcgen::{generate_ca, generate_csr, sign_csr, SigningAlgorithm};

# fn main() -> Result<(), oxitls_core::TlsError> {
let ca = generate_ca("My Root CA", SigningAlgorithm::Ed25519)?;

// The requester generates a CSR + keeps its private key.
let (csr, _private_key_pkcs8) = generate_csr("client.example.com", SigningAlgorithm::EcdsaP256)?;

// The CA signs the CSR, producing a 365-day leaf (no private key in the output).
let signed = sign_csr(&csr.der, &ca, 365)?;
let _cert_der = signed.cert_der;
# Ok(())
# }
```

## API Overview

### Self-signed certificate functions

Each returns a [`CertifiedKey`] (or [`TlsError`]). `subject_alt_names` are DNS names or IP strings used as Subject Alternative Names.

| Function | Algorithm |
|----------|-----------|
| `generate_self_signed_ed25519(sans)` | Ed25519 |
| `generate_self_signed_p256(sans)` | ECDSA P-256 / SHA-256 |
| `generate_self_signed_p384(sans)` | ECDSA P-384 / SHA-384 |
| `generate_self_signed_rsa2048(sans)` | RSA-2048 PKCS#1 v1.5 / SHA-256 |
| `generate_self_signed_rsa4096(sans)` | RSA-4096 PKCS#1 v1.5 / SHA-256 |
| `generate_self_signed(sans, alg)` | Dispatch over [`SigningAlgorithm`] |
| `self_signed_from_rsa2048_key(sans, key)` | Reuse a pre-generated [`OxiRsa2048Key`] |
| `self_signed_from_rsa4096_key(sans, key)` | Reuse a pre-generated [`OxiRsa4096Key`] |

> RSA key generation in pure Rust is expensive (RSA-2048 ~1 min, RSA-4096 several minutes without hardware acceleration); the `self_signed_from_rsa*_key` helpers let tests reuse a cached key.

### CA certificate functions

| Function | Description |
|----------|-------------|
| `generate_ca(subject_cn, alg)` | Root CA — `IsCa::Ca(Unconstrained)`, KeyUsage `KeyCertSign \| CrlSign \| DigitalSignature` → [`CaCertifiedKey`] |
| `generate_intermediate_ca(subject_cn, alg, parent)` | Intermediate CA — `BasicConstraints::Constrained(0)` by default, signed by `parent` |
| `generate_ca_signed_leaf(sans, alg, ca)` | Leaf (server) certificate signed by `ca` |
| `generate_ca_signed_client_cert(sans, alg, ca)` | Leaf **client** certificate with `id-kp-clientAuth` EKU for mTLS → [`CertifiedKey`] |

### `CertifiedKey` struct

A leaf certificate plus its private key. Fields: `cert_der: Vec<u8>`, `pkcs8_der: Vec<u8>`, `cert_pem: String`. Implements `Display` (a multi-line `Subject` / `Algorithm` / `SHA-256` / `Not after` summary).

| Method | Description |
|--------|-------------|
| `fingerprint_sha256()` | SHA-256 of the DER cert (`[u8; 32]`), matching `openssl x509 -fingerprint -sha256` |
| `key_pem()` | Private key as PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----`) |
| `not_after()` | Parsed `notAfter` timestamp → `Option<time::OffsetDateTime>` |
| `to_pkcs12(password, friendly_name)` | Export a password-protected PKCS#12 / PFX blob (pure-Rust `p12`, RFC 7292 §B.1 3DES profile) |
| `to_rustls_cert_and_key()` | Infallible: `(Vec<CertificateDer>, PrivateKeyDer)` for low-level rustls config |
| `to_rustls_certified_key()` | `rustls::sign::CertifiedKey` loaded via the Pure-Rust crypto provider |

### `CaCertifiedKey` struct

A CA certificate that can sign children. Holds the underlying [`CertifiedKey`] plus the issuer params/signer needed for signing.

| Method | Description |
|--------|-------------|
| `as_certified_key()` | Borrow the underlying [`CertifiedKey`] for DER/PEM/fingerprint access |

### `SigningAlgorithm` enum

Algorithm selector (`Debug`, `Clone`, `Copy`, `Eq`): `Ed25519`, `EcdsaP256`, `EcdsaP384`, `Rsa2048`, `Rsa4096`.

### `CertificateParamsBuilder`

Fluent builder over [`rcgen::CertificateParams`] (terminated by `build()` → `Result<CertificateParams, TlsError>`, or `build_with_spki(spki)` to supply explicit SPKI bytes for the SKI).

| Method | Sets |
|--------|------|
| `with_common_name(cn)` | Subject Common Name |
| `with_dns_names(&[..])` | DNS SANs |
| `with_ip_addresses(&[..])` | IP-address SANs (unparsable entries are skipped) |
| `with_ca()` / `with_ca_path_length(n)` | Mark as CA (unconstrained / path-length `n`) |
| `with_server_auth()` / `with_client_auth()` | ServerAuth / ClientAuth EKU |
| `with_code_signing()` / `with_email_protection()` / `with_ocsp_signing()` | Additional EKUs |
| `with_digital_signature()` / `with_key_cert_sign()` / `with_crl_sign()` | Individual key usages |
| `with_key_usages(vec)` / `with_extended_key_usages(vec)` | Replace all (extended) key usages |
| `with_serial_number(n)` | Explicit serial number |
| `with_validity(not_before, not_after)` | Explicit validity window |
| `with_name_constraints(permitted, excluded)` | NameConstraints extension (CA only) |
| `with_subject_key_id(bytes)` | Override SKI (default = SHA-256(SPKI)) |
| `with_authority_key_id(bytes)` / `with_authority_key_id_from_issuer()` | Explicit / issuer-derived AKI |
| `with_crl_distribution_point(uri)` | Append a CRL Distribution Point URI |
| `with_ocsp_responder_url(url)` | OCSP responder URL (Authority Information Access) |

### `CertChainBuilder`

Assembles a certificate chain from DER components.

| Method | Description |
|--------|-------------|
| `with_leaf(der)` / `with_intermediate(der)` / `with_root(der)` | Add chain components |
| `build()` | `Vec<Vec<u8>>` of DER certs (leaf-first) |
| `build_rustls()` | `Vec<rustls_pki_types::CertificateDer<'static>>` |

### `csr` module

| Item | Description |
|------|-------------|
| `generate_csr(subject_cn, alg)` | Generate a fresh CSR → `(CsrBytes, Vec<u8>)` (CSR + PKCS#8 private key; the key stays with the caller) |
| `sign_csr(csr_der, ca, validity_days)` | Sign a CSR with a CA → [`SignedCertificate`] (no private key in the output) |
| `CsrBytes` | A serialized PKCS#10 CSR: `der: Vec<u8>`, `pem: String` |
| `SignedCertificate` | An issued certificate: `cert_der: Vec<u8>`, `cert_pem: String` |

> **Signature verification:** `sign_csr` does **not** verify the inbound CSR's self-signature (to stay free of `ring` via `x509-parser`'s `verify` feature). Production callers receiving CSRs from untrusted parties must verify the signature out-of-band.

### `keypair` module — OxiCrypto signing keys

Each type implements rcgen's `SigningKey` + `PublicKeyData` pair without touching `ring`/`aws-lc-rs`, and exposes `generate()` (OS entropy) plus `pkcs8_der()` for hand-off to rustls.

| Type | rcgen algorithm | Notes |
|------|-----------------|-------|
| `OxiEd25519Key` | `PKCS_ED25519` | `generate()`, `from_seed([u8; 32])`, `pkcs8_der()` |
| `OxiEcdsaP256Key` | `PKCS_ECDSA_P256_SHA256` | `generate()`, `pkcs8_der()` |
| `OxiEcdsaP384Key` | `PKCS_ECDSA_P384_SHA384` | `generate()`, `pkcs8_der()` |
| `OxiRsa2048Key` | `PKCS_RSA_SHA256` (2048-bit) | `generate()`, `from_pkcs8_der(der)`, `pkcs8_der()` |
| `OxiRsa4096Key` | `PKCS_RSA_SHA256` (4096-bit) | `generate()`, `from_pkcs8_der(der)`, `pkcs8_der()` |

## Benchmarks

The crate ships three `criterion` benchmark targets (run with `cargo bench -p oxitls-rcgen`):

| Bench | Measures |
|-------|----------|
| `cert_gen` | Self-signed certificate generation per algorithm |
| `chain_build` | Building a leaf → intermediate → root chain |
| `pkcs12` | PKCS#12 / PFX export cost |

## Cross-references

- **`oxitls`** — the façade; enable this crate via the `rcgen` feature.
- **`oxitls-core`** — defines [`TlsError`] and the `OsRng` adapter used for RSA key generation.
- **`oxitls-adapter-rustls-rustcrypto`** — the Pure-Rust crypto provider used by `to_rustls_certified_key()`.
- **`oxitls-webpki-roots`** — root CA store for verifying chains during a handshake.
- **`oxitls-h2`** — generate the certs used in an HTTP/2-over-TLS handshake.

## License

Apache-2.0 — COOLJAPAN OU (Team Kitasan)
