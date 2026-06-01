//! Tests for RFC 6962 §3.2 precert signed-data reconstruction.
//!
//! Covers:
//! 1. `precert_tbs_strips_only_sct_extension` — the helper removes only the
//!    SCT list OID extension and leaves all other extensions intact.
//! 2. `precert_signed_data_format` — byte layout of the `precert_entry` payload
//!    produced by `build_sct_signed_data_precert`.
//! 3. `issuer_key_hash_matches_independent_computation` — ground-truth check
//!    that `issuer_key_hash` equals SHA-256 of the raw SPKI bytes from
//!    x509-parser.
//! 4. `tbs_reencode_fidelity` — the re-encoded TBS (with no extension removed)
//!    round-trips identically to the raw TBS bytes, confirming x509-cert's
//!    `to_der` is faithful for rcgen-generated certs.

use sha2::{Digest as _, Sha256};
use x509_parser::prelude::FromDer as _;

use oxitls_adapter_rustls_rustcrypto::verifier::sct::{
    build_sct_signed_data_precert, precert_tbs_and_issuer_hash, ParsedSct,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Build a minimal fake SCT with known field values for byte-layout tests.
fn make_sct(timestamp_ms: u64) -> ParsedSct {
    ParsedSct {
        sct_version: 0x00,
        log_id: [0u8; 32],
        timestamp_ms,
        extensions: Vec::new(),
        hash_alg: 0x04,
        sig_alg: 0x03,
        signature: Vec::new(),
    }
}

/// Build a minimal fake SCT that carries a 2-byte extensions payload.
fn make_sct_with_ext(timestamp_ms: u64, ext: Vec<u8>) -> ParsedSct {
    ParsedSct {
        sct_version: 0x00,
        log_id: [0u8; 32],
        timestamp_ms,
        extensions: ext,
        hash_alg: 0x04,
        sig_alg: 0x03,
        signature: Vec::new(),
    }
}

/// Generate a self-signed issuer CA cert and a leaf cert (issued by it) that
/// contains the SCT list OID extension plus a second custom extension.
///
/// Returns `(issuer_der, leaf_der)`.
fn build_issuer_and_leaf() -> (Vec<u8>, Vec<u8>) {
    use rcgen::{CertificateParams, Issuer, KeyPair};

    // ── Issuer CA ─────────────────────────────────────────────────────────────
    let issuer_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("issuer key gen");
    let mut issuer_params = CertificateParams::new(Vec::<String>::new()).expect("issuer params");
    issuer_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let issuer_cert = issuer_params
        .self_signed(&issuer_key)
        .expect("issuer self-sign");
    let issuer_der = issuer_cert.der().to_vec();
    // Build an Issuer for signing the leaf cert.
    let issuer = Issuer::from_params(&issuer_params, &issuer_key);

    // ── Leaf cert ─────────────────────────────────────────────────────────────
    let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("leaf key gen");
    let mut leaf_params =
        CertificateParams::new(vec!["leaf.example.com".to_string()]).expect("leaf params");

    // Extension 1: fake SCT list (OID 1.3.6.1.4.1.11129.2.4.2) — dummy value
    let sct_list_oid: &[u64] = &[1, 3, 6, 1, 4, 1, 11129, 2, 4, 2];
    let fake_sct_list_value = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let sct_ext = rcgen::CustomExtension::from_oid_content(sct_list_oid, fake_sct_list_value);
    leaf_params.custom_extensions.push(sct_ext);

    // Extension 2: a second non-SCT custom extension (arbitrary OID 1.2.3.4)
    let other_oid: &[u64] = &[1, 2, 3, 4];
    let other_ext = rcgen::CustomExtension::from_oid_content(other_oid, vec![0xCA, 0xFE]);
    leaf_params.custom_extensions.push(other_ext);

    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &issuer)
        .expect("leaf sign");
    let leaf_der = leaf_cert.der().to_vec();

    (issuer_der, leaf_der)
}

// ── Test 1: SCT extension is stripped, other extensions are preserved ─────────

#[test]
fn precert_tbs_strips_only_sct_extension() {
    let (issuer_der, leaf_der) = build_issuer_and_leaf();

    let (_issuer_key_hash, tbs_no_sct) =
        precert_tbs_and_issuer_hash(&leaf_der, &issuer_der).expect("precert reconstruct");

    // Parse the reconstructed TBS with x509-parser and check extensions.
    let (_, tbs) = x509_parser::prelude::TbsCertificate::from_der(&tbs_no_sct)
        .expect("parse reconstructed TBS");

    const SCT_LIST_OID_STR: &str = "1.3.6.1.4.1.11129.2.4.2";
    const OTHER_OID_STR: &str = "1.2.3.4";

    let extensions: Vec<_> = tbs.extensions().iter().collect();

    // SCT extension MUST be absent.
    assert!(
        extensions
            .iter()
            .all(|e| e.oid.to_id_string() != SCT_LIST_OID_STR),
        "SCT list extension must be absent from reconstructed TBS; found it present"
    );

    // The non-SCT extension MUST still be present.
    assert!(
        extensions
            .iter()
            .any(|e| e.oid.to_id_string() == OTHER_OID_STR),
        "non-SCT extension 1.2.3.4 must be retained in reconstructed TBS"
    );
}

// ── Test 2: precert_entry byte layout ────────────────────────────────────────

#[test]
fn precert_signed_data_format() {
    let timestamp_ms: u64 = 0x0102_0304_0506_0708;
    let sct = make_sct(timestamp_ms);

    let tbs_no_sct = vec![0xAA, 0xBB, 0xCC]; // 3-byte placeholder TBS
    let issuer_key_hash = [0x5Au8; 32];

    let blob = build_sct_signed_data_precert(&sct, &tbs_no_sct, &issuer_key_hash);

    // Minimum expected length:
    // 1 (version) + 1 (sig_type) + 8 (timestamp) + 2 (entry_type) +
    // 32 (issuer_key_hash) + 3 (u24 tbs_len) + 3 (tbs) + 2 (u16 ext_len) + 0 (no exts)
    assert_eq!(blob.len(), 1 + 1 + 8 + 2 + 32 + 3 + 3 + 2);

    // Byte 0: version = 0x00
    assert_eq!(blob[0], 0x00, "version must be 0x00");

    // Byte 1: signature_type = 0x00 (certificate_timestamp)
    assert_eq!(blob[1], 0x00, "signature_type must be 0x00");

    // Bytes 2..10: timestamp big-endian
    let ts_bytes = &blob[2..10];
    assert_eq!(
        u64::from_be_bytes(ts_bytes.try_into().expect("8 bytes")),
        timestamp_ms,
        "timestamp must be at bytes 2..10"
    );

    // Bytes 10..12: entry_type = 0x0001 (precert_entry)
    assert_eq!(blob[10], 0x00, "entry_type high byte must be 0x00");
    assert_eq!(blob[11], 0x01, "entry_type low byte must be 0x01");

    // Bytes 12..44: issuer_key_hash (32 bytes)
    assert_eq!(
        &blob[12..44],
        &[0x5Au8; 32],
        "issuer_key_hash at bytes 12..44"
    );

    // Bytes 44..47: u24_be(tbs_len) = 3
    assert_eq!(&blob[44..47], &[0x00, 0x00, 0x03], "u24 tbs_len = 3");

    // Bytes 47..50: tbs bytes
    assert_eq!(
        &blob[47..50],
        &[0xAA, 0xBB, 0xCC],
        "tbs content at bytes 47..50"
    );

    // Bytes 50..52: u16_be(ext_len) = 0
    assert_eq!(&blob[50..52], &[0x00, 0x00], "u16 ext_len = 0");
}

// ── Test 3: precert_entry with non-empty extensions ──────────────────────────

#[test]
fn precert_signed_data_with_extensions() {
    let timestamp_ms: u64 = 0xDEAD_BEEF_CAFE_F00D;
    let ext_payload = vec![0x11, 0x22, 0x33];
    let sct = make_sct_with_ext(timestamp_ms, ext_payload.clone());

    let tbs_no_sct = vec![0x01, 0x02];
    let issuer_key_hash = [0xBBu8; 32];

    let blob = build_sct_signed_data_precert(&sct, &tbs_no_sct, &issuer_key_hash);

    // u16_be(ext_len) = 3 at position 2+8+2+32+3+2 = 49
    let ext_len_pos = 1 + 1 + 8 + 2 + 32 + 3 + 2;
    let ext_len = u16::from_be_bytes([blob[ext_len_pos], blob[ext_len_pos + 1]]);
    assert_eq!(ext_len, 3, "ext_len must be 3");

    // extensions payload immediately follows
    assert_eq!(&blob[ext_len_pos + 2..ext_len_pos + 5], &[0x11, 0x22, 0x33]);
}

// ── Test 4: issuer_key_hash matches independent SHA-256 computation ───────────

#[test]
fn issuer_key_hash_matches_independent_computation() {
    let (issuer_der, leaf_der) = build_issuer_and_leaf();

    // Helper-computed hash.
    let (helper_hash, _tbs) =
        precert_tbs_and_issuer_hash(&leaf_der, &issuer_der).expect("precert reconstruct");

    // Independent computation via x509-parser's raw SPKI bytes.
    let (_, issuer_parsed) =
        x509_parser::parse_x509_certificate(&issuer_der).expect("parse issuer cert");
    let raw_spki = issuer_parsed.tbs_certificate.public_key().raw;
    let expected_hash: [u8; 32] = Sha256::digest(raw_spki).into();

    assert_eq!(
        helper_hash, expected_hash,
        "issuer_key_hash must equal SHA-256 of raw SPKI bytes"
    );
}

// ── Test 5: TBS re-encode fidelity ────────────────────────────────────────────
//
// A cert with NO SCT extension: the helper must return a TBS DER that is
// byte-for-byte identical to the raw TBS reported by x509-parser.
// This confirms x509-cert's `to_der` is faithful for rcgen-generated certs.

#[test]
fn tbs_reencode_fidelity() {
    use rcgen::{CertificateParams, Issuer, KeyPair};

    // Build a plain issuer + leaf with NO SCT extension.
    let issuer_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("issuer key");
    let mut issuer_params = CertificateParams::new(Vec::<String>::new()).expect("issuer params");
    issuer_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let issuer_cert = issuer_params
        .self_signed(&issuer_key)
        .expect("issuer self-sign");
    let issuer_der = issuer_cert.der().to_vec();
    let issuer = Issuer::from_params(&issuer_params, &issuer_key);

    let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("leaf key");
    let leaf_params =
        CertificateParams::new(vec!["fidelity.test".to_string()]).expect("leaf params");
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &issuer)
        .expect("leaf sign");
    let leaf_der = leaf_cert.der().to_vec();

    // Run the helper (it will strip nothing since there is no SCT extension).
    let (_issuer_key_hash, reencoded_tbs) =
        precert_tbs_and_issuer_hash(&leaf_der, &issuer_der).expect("precert reconstruct");

    // Get the raw TBS from x509-parser.
    let (_, leaf_parsed) = x509_parser::parse_x509_certificate(&leaf_der).expect("parse leaf cert");
    let raw_tbs: &[u8] = leaf_parsed.tbs_certificate.as_ref();

    assert_eq!(
        reencoded_tbs.as_slice(),
        raw_tbs,
        "re-encoded TBS must be byte-for-byte identical to raw TBS (fidelity check)"
    );
}
