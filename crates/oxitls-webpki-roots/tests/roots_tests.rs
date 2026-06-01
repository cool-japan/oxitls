//! Integration tests for `oxitls-webpki-roots`.
//!
//! The tests cover Slice C's deliverables:
//! 1. Trust-anchor bundle: count, filter, list, root-store construction.
//! 2. `RootStoreBuilder` custom-PEM round-trip.
//! 3. `merge_root_stores` union semantics.
//! 4. `IntermediateCertCache` insert/lookup/eviction.
//! 5. `expiring_roots_from_ders` window semantics (works with real DERs;
//!    bundled-roots variant is documented as always empty).
//! 6. `root_store_from_anchors` helper.
//!
//! The custom PEM is the stable, publicly distributed **ISRG Root X1**
//! certificate from Let's Encrypt (`notAfter = 2035-06-04`). It is checked
//! into `tests/fixtures/test_ca.pem` so the tests have zero external
//! dependencies.

use oxitls_webpki_roots::{
    expiring_roots, expiring_roots_from_ders, list_trust_anchors, merge_root_stores,
    root_cert_count, root_store_from_anchors, webpki_root_certs, webpki_root_certs_filtered,
    IntermediateCertCache, RootStoreBuilder,
};
use rustls_pki_types::CertificateDer;
use std::num::NonZeroUsize;

const TEST_CA_PEM: &[u8] = include_bytes!("fixtures/test_ca.pem");

fn pem_to_der(pem: &[u8]) -> CertificateDer<'static> {
    let mut cursor = std::io::Cursor::new(pem);
    let certs: Vec<_> = rustls_pemfile::certs(&mut cursor)
        .collect::<Result<_, _>>()
        .expect("test PEM must parse");
    assert_eq!(certs.len(), 1, "fixture must contain exactly one cert");
    certs.into_iter().next().expect("one cert").into_owned()
}

// ── Trust-anchor bundle ──────────────────────────────────────────────────────

#[test]
fn root_cert_count_above_100() {
    let count = root_cert_count();
    assert!(count > 100, "expected >100 trust anchors, got {count}");
}

#[test]
fn filter_all_true_equals_unfiltered() {
    let filtered = webpki_root_certs_filtered(|_| true);
    let count = root_cert_count();
    assert_eq!(filtered.len(), count);
}

#[test]
fn filter_all_false_empty() {
    let filtered = webpki_root_certs_filtered(|_| false);
    assert_eq!(filtered.len(), 0);
}

#[test]
fn list_trust_anchors_nonempty() {
    let anchors = list_trust_anchors();
    assert!(!anchors.is_empty());
    for a in &anchors {
        assert!(!a.subject_dn().is_empty());
        assert_eq!(a.fingerprint_sha256().len(), 32);
        // Bundle anchors don't carry notAfter (see TrustAnchorInfo docs).
        assert!(a.not_after.is_none());
    }
}

// ── RootStoreBuilder ─────────────────────────────────────────────────────────

#[test]
fn root_store_builder_custom_pem_single_cert() {
    // Start fresh (no webpki roots) — adding exactly one PEM cert.
    let store = RootStoreBuilder::new()
        .add_pem(TEST_CA_PEM.to_vec())
        .build();
    assert_eq!(store.len(), 1, "exactly one cert added via add_pem");
}

#[test]
fn root_store_builder_with_webpki_then_custom_pem() {
    let base_count = root_cert_count();
    let store = RootStoreBuilder::new()
        .with_webpki_roots()
        .add_pem(TEST_CA_PEM.to_vec())
        .build();
    // webpki bundle already contains ISRG Root X1, but add() pushes the cert
    // anyway — rustls does not deduplicate. So count is base + 1.
    assert_eq!(store.len(), base_count + 1);
}

// ── Merge ────────────────────────────────────────────────────────────────────

#[test]
fn merge_disjoint_stores_union() {
    // Store A: full webpki roots.
    let a = webpki_root_certs();
    let a_len = a.len();
    // Store B: only the ISRG cert (a disjoint single anchor in terms of
    // "stores"; the cert itself overlaps the bundle but as a separate store
    // it adds one anchor to the merged Vec).
    let b = RootStoreBuilder::new()
        .add_pem(TEST_CA_PEM.to_vec())
        .build();
    let b_len = b.len();
    let merged = merge_root_stores(&[a, b]);
    assert_eq!(merged.len(), a_len + b_len);
}

// ── IntermediateCertCache ────────────────────────────────────────────────────

#[test]
fn intermediate_cache_roundtrip() {
    let cap = NonZeroUsize::new(4).expect("non-zero");
    let cache = IntermediateCertCache::new(cap);

    let a = CertificateDer::from(vec![1u8, 2, 3, 4, 5]);
    let b = CertificateDer::from(vec![9u8, 8, 7, 6, 5, 4]);

    let fp_a = cache.insert(a.clone()).expect("insert a");
    let fp_b = cache.insert(b.clone()).expect("insert b");
    assert_ne!(fp_a, fp_b, "different bytes → different fingerprints");

    let got_a = cache.get(&fp_a).expect("get a");
    let got_b = cache.get(&fp_b).expect("get b");
    assert_eq!(got_a, Some(a));
    assert_eq!(got_b, Some(b));

    assert_eq!(cache.len().expect("len"), 2);
    assert!(!cache.is_empty().expect("is_empty"));
    assert!(cache.contains(&fp_a).expect("contains"));
}

#[test]
fn intermediate_cache_capacity_eviction() {
    let cap = NonZeroUsize::new(2).expect("non-zero");
    let cache = IntermediateCertCache::new(cap);

    let a = CertificateDer::from(vec![0u8; 16]);
    let b = CertificateDer::from(vec![1u8; 16]);
    let c = CertificateDer::from(vec![2u8; 16]);

    let fp_a = cache.insert(a).expect("insert a");
    let fp_b = cache.insert(b.clone()).expect("insert b");
    let fp_c = cache.insert(c.clone()).expect("insert c");

    // `a` was LRU when `c` was inserted → evicted.
    assert_eq!(cache.get(&fp_a).expect("get a"), None);
    assert_eq!(cache.get(&fp_b).expect("get b"), Some(b));
    assert_eq!(cache.get(&fp_c).expect("get c"), Some(c));
}

// ── expiring_roots ───────────────────────────────────────────────────────────

#[test]
fn expiring_roots_window_all_inclusive_empty_for_bundle() {
    // Documented limitation: the public helper iterates the trust-anchor
    // bundle which has no `notAfter`, so this always returns `Vec::new()`.
    let v = expiring_roots(365_000);
    assert!(
        v.is_empty(),
        "bundle helper has no notAfter; expected empty result"
    );
}

#[test]
fn expiring_roots_window_all_inclusive_real_der() {
    // Real DER path — feed the ISRG cert; 365_000 days covers everything.
    let cert = pem_to_der(TEST_CA_PEM);
    let v = expiring_roots_from_ders(&[cert], 365_000);
    assert_eq!(v.len(), 1, "ISRG cert expires before 365k-day window");
    let info = &v[0];
    assert_eq!(info.fingerprint_sha256().len(), 32);
    assert!(
        info.not_after.is_some(),
        "from_cert_der populates not_after"
    );
}

#[test]
fn expiring_roots_window_zero_empty_or_few() {
    // ISRG Root X1 expires in 2035 — window=0 means "expires before now",
    // which it does not, so the result should be empty.
    let cert = pem_to_der(TEST_CA_PEM);
    let v = expiring_roots_from_ders(&[cert], 0);
    assert!(
        v.is_empty(),
        "ISRG not expiring within 0 days; got {} entries",
        v.len()
    );
}

#[test]
fn expiring_roots_handles_invalid_der_gracefully() {
    let garbage = CertificateDer::from(vec![0xFF, 0xFE, 0xFD, 0xFC]);
    let v = expiring_roots_from_ders(&[garbage], 30);
    assert!(v.is_empty(), "invalid DER must be skipped, not panicked");
}

// ── root_store_from_anchors ──────────────────────────────────────────────────

#[test]
fn root_store_from_anchors_roundtrip() {
    let store = root_store_from_anchors(webpki_roots::TLS_SERVER_ROOTS);
    assert!(!store.is_empty());
    assert_eq!(store.len(), root_cert_count());
}

#[test]
fn root_store_from_anchors_empty_input() {
    let store = root_store_from_anchors(&[]);
    assert!(store.is_empty());
}
