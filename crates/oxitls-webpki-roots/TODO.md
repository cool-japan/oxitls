# oxitls-webpki-roots TODO

## Status
Root store management crate (~250 SLOC) with `webpki_root_certs()` (OnceLock-cached),
`RootStoreBuilder` (add_pem/add_der/exclude_fingerprint), `TrustAnchorInfo` for
introspection, filtered root loading, and root store merging.

## Core Implementation
- [x] Add `webpki_root_certs_filtered(filter: impl Fn(&TrustAnchor) -> bool) -> RootCertStore` for selective root inclusion (~40 SLOC)
- [x] Add `root_cert_count() -> usize` to expose the number of trust anchors without building a full store (~10 SLOC)
- [x] Add `TrustAnchorInfo` struct with subject DN, SHA-256 fingerprint (~80 SLOC)
- [x] Add `list_trust_anchors() -> Vec<TrustAnchorInfo>` for root store introspection (~60 SLOC)
- [x] Add `RootStoreBuilder` with methods `add_pem(data)`, `add_der(bytes)`, `exclude_fingerprint(sha256)`, `build() -> RootCertStore` (~200 SLOC)
- [x] Add intermediate certificate caching: `IntermediateCertCache` backed by an in-memory LRU (~300 SLOC)
- [x] Add `merge_root_stores(stores: &[RootCertStore]) -> RootCertStore` for combining multiple trust sources (~30 SLOC)
- [x] Add platform native root store loading (macOS Keychain, Linux /etc/ssl/certs) behind `native-roots` feature flag (~150 SLOC)
- [x] Add root CA expiration checking: `expiring_roots(within_days: u32) -> Vec<TrustAnchorInfo>` (~50 SLOC)

## API Improvements
- [x] Add `Default` impl for `RootStoreBuilder` that includes webpki roots
- [x] Add `From<webpki_root_certs()>` impl for types used in oxitls facade builder — premise off: no `WebpkiRootCerts` type needed; `webpki_root_certs()` already returns `RootCertStore` directly (usable as-is); 2026-05-29
- [x] Add `Display` impl for `TrustAnchorInfo` showing subject DN and fingerprint
- [x] Make `webpki_root_certs()` return a cached `Arc<RootCertStore>` via `OnceLock` to avoid repeated construction

## Testing
- [x] Test: `root_cert_count()` returns value > 100 (Mozilla bundle has ~150 roots) — Wave 7 (`root_cert_count_exceeds_100` in wave7_roots.rs + `root_cert_count_above_100` in roots_tests.rs); 2026-05-29
- [x] Test: `webpki_root_certs_filtered()` with always-true filter equals unfiltered store — Wave 7 (`filtered_always_true_matches_unfiltered` in wave7_roots.rs); 2026-05-29
- [x] Test: `webpki_root_certs_filtered()` with always-false filter returns empty store — Wave 7 (`filtered_always_false_is_empty` in wave7_roots.rs); 2026-05-29
- [x] Test: `list_trust_anchors()` returns non-empty list with valid fingerprints — Wave 7 (`list_trust_anchors_nonempty_with_valid_fingerprints` in wave7_roots.rs); 2026-05-29
- [x] Test: `RootStoreBuilder` with custom PEM file adds exactly one root — Wave 7 (`root_store_builder_custom_pem_gives_one_root` in wave7_roots.rs); 2026-05-29
- [x] Test: `merge_root_stores()` with disjoint stores produces union — Wave 7 (`merge_disjoint_single_cert_stores_gives_two` in wave7_roots.rs); 2026-05-29
- [x] Test: `IntermediateCertCache` insert-then-lookup round-trip — (covered by `intermediate_cache_roundtrip` + `intermediate_cache_capacity_eviction` in roots_tests.rs); 2026-05-29
- [x] Test: `expiring_roots()` with 365000 days returns all roots; with 0 days returns none or few

## Performance
- [x] Benchmark `webpki_root_certs()` construction time (currently ~2ms on first call)
- [x] Benchmark `OnceLock`-cached vs uncached root store construction
- [x] Benchmark `IntermediateCertCache` lookup latency under contention (multi-threaded)
- [x] Profile memory footprint of full root store (~150 certs)

## Integration
- [x] Wire `RootStoreBuilder` into `oxitls` facade `ClientBuilder::with_root_store_builder()` — implemented in crates/oxitls/src/tls13/client.rs:331
- [x] Coordinate with `oxitls-adapter-rustls-rustcrypto` for intermediate cert cache injection — `IntermediateCertCache` used in `client_builder.rs` (`with_intermediate_cache(Arc<IntermediateCertCache>)`); 2026-05-29
- [x] Coordinate with `oxihttp-client` for per-client root store customization — `with_webpki_roots()` implemented in oxihttp-client/src/lib.rs and tls.rs; 2026-05-29
- [x] Coordinate with `oxiquic-tls` for QUIC client root store sharing
