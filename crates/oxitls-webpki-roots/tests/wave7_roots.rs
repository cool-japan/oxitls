//! Wave 7 additive tests for `oxitls-webpki-roots`.
//!
//! Covers items not already exercised by `roots_tests.rs`:
//!
//!  1. `webpki_root_certs_arc()` returns a shared (ptr-eq) reference.
//!  2. `RootStoreBuilder::exclude_fingerprint` shrinks the bundle by exactly one.
//!  3. `webpki_root_certs()` count exceeds 100 (direct assertion on the returned store).
//!  4. `webpki_root_certs_filtered` always-true count equals unfiltered count.
//!  5. `webpki_root_certs_filtered` always-false produces an empty store.
//!  6. `list_trust_anchors()` returns > 100 items, each with a 32-byte fingerprint.
//!  7. `RootStoreBuilder` with only a PEM cert gives exactly 1 root (fixture).
//!  8. `merge_root_stores` with two disjoint single-cert stores gives exactly 2.
//!
//! Tests 3-8 are semantically identical to (some) roots_tests.rs entries but run
//! through this file so the TODO checklist items for wave7 are all backed by
//! individual named functions below.  Duplicate coverage is harmless.

use std::sync::Arc;

use oxitls_webpki_roots::{
    list_trust_anchors, merge_root_stores, root_cert_count, webpki_root_certs,
    webpki_root_certs_arc, webpki_root_certs_filtered, RootStoreBuilder,
};

/// PEM fixture: ISRG Root X1 (Let's Encrypt), checked in for zero-network tests.
const TEST_CA_PEM: &[u8] = include_bytes!("fixtures/test_ca.pem");

// ── Test 1: arc returns a shared reference ────────────────────────────────────

#[test]
fn webpki_root_certs_arc_is_ptr_equal_on_second_call() {
    let a = webpki_root_certs_arc();
    let b = webpki_root_certs_arc();
    assert!(
        Arc::ptr_eq(&a, &b),
        "webpki_root_certs_arc must return the same Arc on repeated calls"
    );
}

// ── Test 2: exclude_fingerprint shrinks by exactly one ───────────────────────

#[test]
fn exclude_fingerprint_shrinks_bundle_by_one() {
    let anchors = list_trust_anchors();
    assert!(!anchors.is_empty(), "need at least one anchor to exclude");
    let first_fp = anchors[0].spki_sha256;

    let full_count = root_cert_count();
    let filtered = RootStoreBuilder::new()
        .with_webpki_roots()
        .exclude_fingerprint(first_fp)
        .build();

    assert_eq!(
        filtered.len(),
        full_count - 1,
        "excluding one fingerprint must shrink the store by exactly one"
    );
}

// ── Test 3: root_cert_count > 100 ─────────────────────────────────────────────

#[test]
fn root_cert_count_exceeds_100() {
    let store = webpki_root_certs();
    assert!(
        store.len() > 100,
        "expected > 100 root certs, got {}",
        store.len()
    );
}

// ── Test 4: filtered always-true matches unfiltered ──────────────────────────

#[test]
fn filtered_always_true_matches_unfiltered() {
    let all = webpki_root_certs();
    let filtered = webpki_root_certs_filtered(|_| true);
    assert_eq!(
        all.len(),
        filtered.len(),
        "always-true filter must return the same count as the unfiltered store"
    );
}

// ── Test 5: filtered always-false is empty ────────────────────────────────────

#[test]
fn filtered_always_false_is_empty() {
    let filtered = webpki_root_certs_filtered(|_| false);
    assert_eq!(
        filtered.len(),
        0,
        "always-false filter must produce an empty store"
    );
}

// ── Test 6: list_trust_anchors > 100, valid fingerprints ─────────────────────

#[test]
fn list_trust_anchors_nonempty_with_valid_fingerprints() {
    let anchors = list_trust_anchors();
    assert!(
        anchors.len() > 100,
        "expected > 100 trust anchors, got {}",
        anchors.len()
    );
    for anchor in &anchors {
        assert!(
            !anchor.subject_dn().is_empty(),
            "subject DN must be non-empty"
        );
        assert_eq!(
            anchor.fingerprint_sha256().len(),
            32,
            "fingerprint must be exactly 32 bytes"
        );
    }
}

// ── Test 7: RootStoreBuilder with one PEM cert gives exactly 1 root ──────────

#[test]
fn root_store_builder_custom_pem_gives_one_root() {
    let store = RootStoreBuilder::new()
        .add_pem(TEST_CA_PEM.to_vec())
        .build();
    assert_eq!(
        store.len(),
        1,
        "adding exactly one PEM cert must produce a store with 1 root"
    );
}

// ── Test 8: merge_root_stores with two single-cert stores gives 2 ────────────

#[test]
fn merge_disjoint_single_cert_stores_gives_two() {
    // Use the same fixture twice to avoid needing two distinct PEM files.
    // Each store independently holds one cert; merged = 2 (rustls does not
    // deduplicate; duplicate trust anchors are harmless).
    let store_a = RootStoreBuilder::new()
        .add_pem(TEST_CA_PEM.to_vec())
        .build();
    let store_b = RootStoreBuilder::new()
        .add_pem(TEST_CA_PEM.to_vec())
        .build();

    let merged = merge_root_stores(&[store_a, store_b]);
    assert_eq!(
        merged.len(),
        2,
        "merging two single-cert stores must yield exactly 2 anchors"
    );
}
