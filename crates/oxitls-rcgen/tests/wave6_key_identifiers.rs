//! Wave 6 integration tests: Subject Key Identifier (SKI) and Authority Key
//! Identifier (AKI) extension control via `CertificateParamsBuilder`.
//!
//! All tests self-sign the generated params so that they remain in-crate scope
//! without needing to expose `sign_child` publicly.  The signed cert is then
//! parsed with `x509-parser` and the extension values are verified against what
//! was configured on the builder.

use oxitls_rcgen::{CertificateParamsBuilder, OxiEd25519Key};
use rcgen::PublicKeyData;
use x509_parser::prelude::*;

// ── helpers ──────────────────────────────────────────────────────────────────

/// Parse a DER certificate and return the `SubjectKeyIdentifier` bytes, if
/// the extension is present.
fn extract_ski(cert_der: &[u8]) -> Option<Vec<u8>> {
    let (_, parsed) = X509Certificate::from_der(cert_der).ok()?;
    for ext in parsed.extensions() {
        if let ParsedExtension::SubjectKeyIdentifier(ki) = ext.parsed_extension() {
            return Some(ki.0.to_vec());
        }
    }
    None
}

/// Parse a DER certificate and return the AKI `keyIdentifier` bytes, if the
/// `AuthorityKeyIdentifier` extension is present and carries a `keyIdentifier`.
fn extract_aki(cert_der: &[u8]) -> Option<Vec<u8>> {
    let (_, parsed) = X509Certificate::from_der(cert_der).ok()?;
    for ext in parsed.extensions() {
        if let ParsedExtension::AuthorityKeyIdentifier(aki) = ext.parsed_extension() {
            if let Some(ki) = &aki.key_identifier {
                return Some(ki.0.to_vec());
            }
        }
    }
    None
}

// ── Test 1: explicit SKI appears in the certificate ───────────────────────────

/// When `with_subject_key_id` supplies explicit bytes the SKI extension must
/// carry exactly those bytes, not the SHA-256(SPKI) default.
#[test]
fn explicit_ski_appears_in_cert() {
    let custom_ski: Vec<u8> = vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14,
    ]; // 20 bytes

    let key = OxiEd25519Key::generate().expect("keygen");
    let spki = PublicKeyData::subject_public_key_info(&key);

    let params = CertificateParamsBuilder::new()
        .with_common_name("SKI Test")
        .with_ca()
        .with_subject_key_id(custom_ski.clone())
        .build_with_spki(&spki)
        .expect("build params");

    let cert = params.self_signed(&key).expect("self-sign");
    let cert_der = cert.der().to_vec();

    let ski = extract_ski(&cert_der).expect("SKI extension must be present");
    assert_eq!(
        ski, custom_ski,
        "SKI bytes must match the value supplied via with_subject_key_id"
    );
}

// ── Test 2: explicit AKI appears in the certificate ───────────────────────────

/// When `with_authority_key_id` supplies explicit bytes the AKI extension must
/// carry exactly those bytes as the `keyIdentifier` field.
#[test]
fn explicit_aki_appears_in_cert() {
    let aki_bytes: Vec<u8> = vec![
        0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    ]; // 20 bytes

    let key = OxiEd25519Key::generate().expect("keygen");
    let spki = PublicKeyData::subject_public_key_info(&key);

    let params = CertificateParamsBuilder::new()
        .with_common_name("AKI Test")
        .with_ca()
        .with_authority_key_id(aki_bytes.clone())
        .build_with_spki(&spki)
        .expect("build params");

    let cert = params.self_signed(&key).expect("self-sign");
    let cert_der = cert.der().to_vec();

    let aki = extract_aki(&cert_der).expect("AKI extension must be present");
    assert_eq!(
        aki, aki_bytes,
        "AKI keyIdentifier must match the value supplied via with_authority_key_id"
    );
}

// ── Test 3: AKI from issuer links to the cert's own SKI (self-signed) ─────────

/// For a self-signed certificate the issuer and subject are the same entity, so
/// `use_authority_key_identifier_extension = true` must produce an AKI whose
/// `keyIdentifier` equals the cert's own SKI.
#[test]
fn aki_from_issuer_equals_own_ski() {
    let key = OxiEd25519Key::generate().expect("keygen");
    let spki = PublicKeyData::subject_public_key_info(&key);

    let params = CertificateParamsBuilder::new()
        .with_common_name("AKI-from-Issuer Test")
        .with_ca()
        .with_authority_key_id_from_issuer()
        .build_with_spki(&spki)
        .expect("build params");

    let cert = params.self_signed(&key).expect("self-sign");
    let cert_der = cert.der().to_vec();

    let ski = extract_ski(&cert_der).expect("SKI must be present");
    let aki = extract_aki(&cert_der).expect("AKI must be present when from_issuer is set");
    assert_eq!(
        aki, ski,
        "For a self-signed cert the AKI keyIdentifier must equal the SKI"
    );
}

// ── Test 4: backward-compatibility — default has SKI but no AKI ──────────────

/// Without any SKI/AKI setters:
/// - SKI must be present (SHA-256 of SPKI, 32 bytes).
/// - AKI must NOT be present (was never emitted before these changes).
#[test]
fn default_unchanged_backward_compat() {
    use sha2::{Digest, Sha256};

    let key = OxiEd25519Key::generate().expect("keygen");
    let spki = PublicKeyData::subject_public_key_info(&key);
    let expected_ski: Vec<u8> = Sha256::digest(&spki).to_vec();

    let params = CertificateParamsBuilder::new()
        .with_common_name("Backward Compat Test")
        .with_ca()
        .build_with_spki(&spki)
        .expect("build params");

    let cert = params.self_signed(&key).expect("self-sign");
    let cert_der = cert.der().to_vec();

    // SKI must exist and equal SHA-256(SPKI).
    let ski = extract_ski(&cert_der).expect("SKI must be present by default");
    assert_eq!(
        ski, expected_ski,
        "Default SKI must be SHA-256 of the subjectPublicKeyInfo"
    );

    // AKI must NOT be present (backward-compatible default).
    assert!(
        extract_aki(&cert_der).is_none(),
        "AKI must not appear in a cert built without any AKI setter (backward compat)"
    );
}
