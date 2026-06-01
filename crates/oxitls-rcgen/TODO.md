# oxitls-rcgen TODO

## Status
Working certificate generation crate (~345 SLOC across lib.rs, cert.rs, keypair.rs)
backed by OxiCrypto signing primitives. Supports Ed25519 and ECDSA P-256 self-signed
certificate generation with SAN (DNS + IP), KeyUsage, ExtendedKeyUsage, and PKCS#8
DER export. Both algorithms validated via live TLS 1.3 loopback handshakes. No ring
or aws-lc-rs in the dependency closure.

## Core Implementation
- [x] Add RSA-2048 key pair support: `OxiRsa2048Key` implementing rcgen's `SigningKey` + `PublicKeyData` via `rsa` crate (~200 SLOC)
- [x] Add RSA-4096 key pair support: `OxiRsa4096Key` for higher security requirements (~50 SLOC incremental on RSA-2048)
- [x] Add ECDSA P-384 key pair support: `OxiEcdsaP384Key` via `p384` crate (~120 SLOC)
- [x] Add CA certificate generation: `generate_ca(subject, alg) -> CaCertifiedKey` with `IsCa::Ca(BasicConstraints::Unconstrained)` (~100 SLOC)
- [x] Add intermediate CA generation: `generate_intermediate_ca(subject, alg, parent_ca) -> CaCertifiedKey` with path length constraints (~80 SLOC)
- [x] Add CSR (Certificate Signing Request) generation: `generate_csr(subject, alg) -> CsrBytes` (~80 SLOC)
- [x] Add CSR signing: `sign_csr(csr_bytes, ca_key, validity_days) -> CertifiedKey` (~100 SLOC)
- [x] Add certificate chain building: `CertChainBuilder` that assembles leaf + intermediates + root (~120 SLOC)
- [x] Add PKCS#12 export: `CertifiedKey::to_pkcs12(password) -> Vec<u8>` for browser/Java import (~100 SLOC)
- [x] Add PEM key export: `CertifiedKey::key_pem() -> String` returning PKCS#8 PEM (~20 SLOC)
- [x] Add custom validity period: `CertificateParamsBuilder::with_validity(not_before, not_after)` (~40 SLOC)
- [x] Add custom key usage extensions: `CertificateParamsBuilder::with_key_usages(usages)` (~30 SLOC)
- [x] Add custom extended key usage: client auth, code signing, email protection, OCSP signing (~40 SLOC)
- [x] Add Subject Key Identifier (SKI) and Authority Key Identifier (AKI) extension control (~50 SLOC)
- [x] Add CRL Distribution Points extension support (~40 SLOC)
- [x] Add Authority Information Access (AIA) extension for OCSP responder URL (~40 SLOC)
- [x] Add Name Constraints extension for CA certificates (~60 SLOC)
- [x] Add certificate serial number control: `CertificateParamsBuilder::with_serial(BigUint)` (~20 SLOC)

## API Improvements
- [x] Add `SigningAlgorithm::Rsa2048`, `Rsa4096`, `EcdsaP384` variants to the enum
- [x] Add `CertifiedKey::fingerprint_sha256() -> [u8; 32]` for certificate identification
- [x] Add `CertifiedKey::subject_name() -> String` accessor
- [x] Add `CertifiedKey::not_after() -> SystemTime` for expiration checking
- [x] Add `CertifiedKey::to_rustls_certified_key() -> rustls::sign::CertifiedKey` convenience conversion
- [x] Add `CaCertifiedKey` type distinguishing CA certs from leaf certs at the type level
- [x] Add `CertificateParamsBuilder` for fluent certificate parameter construction
- [x] Implement `Display` for `CertifiedKey` showing subject, algorithm, fingerprint

## Testing
- [x] Test: RSA-2048 self-signed cert generation + loopback TLS 1.3 handshake
- [x] Test: RSA-4096 self-signed cert generation + loopback TLS 1.3 handshake
- [x] Test: ECDSA P-384 self-signed cert generation + loopback TLS 1.3 handshake
- [x] Test: CA cert signs leaf cert; leaf validated against CA root store
- [x] Test: intermediate CA chain (root -> intermediate -> leaf) validates
- [x] Test: CSR generation + signing produces a valid cert
- [x] Test: PKCS#12 export round-trips (export then re-import)
- [x] Test: PEM export format validation (BEGIN CERTIFICATE / BEGIN PRIVATE KEY headers)
- [x] Test: custom validity period (1 day, 365 days, 10 years)
- [x] Test: certificate with multiple SANs (DNS + IP + email) all present in output
- [x] Test: Name Constraints on CA restricts leaf cert subject
- [x] Test: expired certificate rejected by rustls verifier
- [x] Test: `fingerprint_sha256()` matches OpenSSL-computed fingerprint of the same DER

## Performance
- [x] Benchmark Ed25519 key generation + cert signing (target: < 1ms)
- [x] Benchmark P-256 key generation + cert signing (target: < 5ms)
- [x] Benchmark RSA-2048 key generation + cert signing (target: < 500ms)
- [x] Benchmark RSA-4096 key generation + cert signing (expected: ~2-5s; document)
- [x] Benchmark certificate chain building (3-cert chain)
- [x] Benchmark PKCS#12 export with password-based encryption

## Integration
- [x] Wire into `oxitls` facade: `rcgen_bridge` module re-exports all new key types and CA functions
- [x] Wire into `oxitls-bench`: benchmark cert-gen alongside handshake benchmarks — `crates/oxitls-bench/benches/cert_gen.rs` confirmed
- [x] Wire into `oxihttp` integration tests: replace rcgen dev-dep usage with oxitls-rcgen — oxihttp tests import `oxitls::rcgen_bridge`; no raw `rcgen =` dep in oxihttp Cargo.toml; 2026-05-29
- [x] Wire into `oxiquic` integration tests: QUIC handshake certs via oxitls-rcgen
- [x] Coordinate with `oxitls-adapter-rustls-rustcrypto` for `to_rustls_certified_key()` conversion
