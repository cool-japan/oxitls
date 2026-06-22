# oxitls-webpki-roots — Bundled Mozilla root CA store for OxiTLS

[![Crates.io](https://img.shields.io/crates/v/oxitls-webpki-roots.svg)](https://crates.io/crates/oxitls-webpki-roots)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

`oxitls-webpki-roots` provides the trust-anchor layer for the OxiTLS ecosystem. It wraps the [`webpki-roots`] Mozilla CA bundle behind a cached `webpki_root_certs()` accessor, adds a flexible `RootStoreBuilder` for combining bundled roots with custom PEM/DER certificates (and excluding specific anchors by fingerprint), and offers introspection via `TrustAnchorInfo`, an LRU `IntermediateCertCache`, and expiration helpers. OS-native certificate-store loading lives in the separate `oxitls-native-certs` crate (apps that need it depend on it directly).

This crate is **100% Pure Rust** (`#![forbid(unsafe_code)]`): the Mozilla bundle, PEM parsing (`rustls-pemfile`), fingerprinting (`sha2`), and the LRU cache (`lru`) are all pure Rust. There is **no `native-roots` feature** — OS-native certificate-store loading (which pulls in platform FFI shims on macOS / Windows) has moved to the dedicated `oxitls-native-certs` crate, which apps add directly when they need it.

## Installation

```toml
[dependencies]
oxitls-webpki-roots = "0.2.0"
```

Via the façade (this crate is the default `webpki-roots` feature of `oxitls`):

```toml
[dependencies]
oxitls = { version = "0.2.0", features = ["webpki-roots"] }
```

## Quick Start

```rust
use oxitls_webpki_roots::webpki_root_certs;

// A `rustls::RootCertStore` pre-populated with the Mozilla CA bundle.
let roots = webpki_root_certs();
assert!(!roots.is_empty());
```

### Custom root store

```rust
use oxitls_webpki_roots::RootStoreBuilder;

let store = RootStoreBuilder::new()
    .with_webpki_roots()                    // start from the Mozilla bundle
    .add_pem(b"-----BEGIN CERTIFICATE-----\n...".to_vec()) // add an internal CA
    .build();

assert!(!store.is_empty());
```

### Introspection

```rust
use oxitls_webpki_roots::{list_trust_anchors, root_cert_count};

println!("bundle contains {} trust anchors", root_cert_count());
for info in list_trust_anchors() {
    println!("{info}"); // SPKI-SHA256:<hex> (subject N bytes)
}
```

## API Overview

### Root store accessors

| Function | Description |
|----------|-------------|
| `webpki_root_certs()` | A `RootCertStore` of the Mozilla CA bundle; built once and cached via `OnceLock`, returns a cheap clone |
| `webpki_root_certs_arc()` | `Arc<RootCertStore>` sharing the cached store without cloning the inner `Vec` |
| `webpki_root_certs_filtered(filter)` | A `RootCertStore` containing only anchors accepted by `filter: impl Fn(&TrustAnchor) -> bool` |
| `root_cert_count()` | Number of trust anchors in the Mozilla bundle (compile-time constant) |
| `root_store_from_anchors(&[TrustAnchor<'static>])` | Build a `RootCertStore` from a slice of trust anchors |
| `merge_root_stores(&[RootCertStore])` | Merge multiple stores into one (duplicate subjects are harmless) |
| `list_trust_anchors()` | `Vec<TrustAnchorInfo>` summarising every anchor in the bundle |

### `RootStoreBuilder`

Builder for a custom `RootCertStore` (`Default`). Combine bundled roots with extra PEM/DER certificates and exclude anchors by fingerprint. The exclusion list is applied to the webpki roots after all roots are added; invalid added certificates are skipped silently (forgiving builder semantics).

| Method | Description |
|--------|-------------|
| `new()` | Empty builder (no roots included) |
| `with_webpki_roots()` | Include the Mozilla CA bundle |
| `add_der(cert_der)` | Add a single DER-encoded root |
| `add_pem(pem_data)` | Add root(s) from PEM data (may contain several certs) |
| `exclude_fingerprint([u8; 32])` | Exclude a webpki anchor by its SPKI SHA-256 fingerprint |
| `build()` | Build the `RootCertStore` |

### `TrustAnchorInfo`

Summary of a single trust anchor (`Debug`, `Clone`, `Display` — emits `SPKI-SHA256:<hex> (subject N bytes)`).

| Field | Type | Description |
|-------|------|-------------|
| `subject_der` | `Vec<u8>` | Subject distinguished name (DER-encoded) |
| `spki_sha256` | `[u8; 32]` | SHA-256 fingerprint of the Subject Public Key Info |
| `not_after` | `Option<time::OffsetDateTime>` | Optional expiration timestamp |

| Method | Description |
|--------|-------------|
| `from_trust_anchor(&TrustAnchor)` | Construct from a rustls trust anchor |
| `from_cert_der(&[u8])` | Construct from a DER cert (returns `None` if unparsable) |
| `subject_dn()` | Borrow the subject DN bytes |
| `fingerprint_sha256()` | Borrow the SPKI SHA-256 fingerprint |
| `with_not_after(ts)` | Builder setter for the expiration timestamp |

### `expiring` module — expiration introspection

| Function | Description |
|----------|-------------|
| `expiring_roots(within_days)` | Iterate the bundled roots expiring within `within_days`. **Always returns empty** — `webpki-roots` exposes only the trust-anchor subset, with no reachable `notAfter` (see module docs) |
| `expiring_roots_from_ders(&[CertificateDer], within_days)` | Parse full DER certificates and return [`TrustAnchorInfo`] for those expiring within `within_days`; unparsable certs are skipped |
| `parse_not_after(&[u8])` | Parse the `notAfter` of one DER cert → `Option<time::OffsetDateTime>` |

### `intermediate_cache` module

| Item | Description |
|------|-------------|
| `fingerprint_sha256(&[u8])` | SHA-256 of an arbitrary DER blob → `[u8; 32]` |
| `IntermediateCertCache` | Bounded LRU cache of intermediate certs keyed by SHA-256 fingerprint, backed by `RwLock<LruCache>` |

`IntermediateCertCache` is **synchronous** by design (rustls verifier callbacks are synchronous). Lock poisoning maps to [`oxitls_core::TlsError::Other`] rather than panicking.

| Method | Description |
|--------|-------------|
| `new(NonZeroUsize)` | Create a cache with a fixed capacity |
| `insert(cert)` | Insert a cert, return its SHA-256 fingerprint |
| `get(&fp)` | Look up (via `peek`, does not promote) |
| `touch(&fp)` | Look up and LRU-promote (write lock) |
| `contains(&fp)` | Membership check (no promote) |
| `len()` / `is_empty()` / `capacity()` | Cache stats |
| `clear()` | Remove all entries |

All methods return `Result<…, TlsError>` (poison-safe).

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `dhat-heap` | off | Enables the `dhat` heap profiler as the global allocator in benchmarks |

> This crate is 100% Pure Rust — no feature pulls in platform FFI. OS-native certificate-store loading lives in the separate `oxitls-native-certs` crate.

## Benchmarks

Two `criterion` targets (run with `cargo bench -p oxitls-webpki-roots`):

| Bench | Measures |
|-------|----------|
| `webpki_roots_construction` | Cost of constructing the root store |
| `root_store_memory` | Root-store memory footprint (pairs with the `dhat-heap` feature) |

## Cross-references

- **`oxitls`** — the façade; this crate is the default `webpki-roots` feature.
- **`oxitls-core`** — defines [`TlsError`], returned by the cache.
- **`oxitls-native-certs`** — opt-in quarantine crate for OS-native certificate-store loading (formerly the `native-roots` feature here); add it directly when you need platform trust roots.
- **`oxitls-adapter-rustls-rustcrypto`** — the Pure-Rust provider that verifies certificates against this root store.
- **`oxitls-rcgen`** — generate the CA certificates you add via `RootStoreBuilder`.

## License

Apache-2.0 — COOLJAPAN OU (Team Kitasan)
