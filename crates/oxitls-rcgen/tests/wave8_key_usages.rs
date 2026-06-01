//! Wave 8 tests: bulk key-usage / extended-key-usage setters and
//! `CertifiedKey::to_rustls_cert_and_key`.
//!
//! All extension content is verified via `x509-parser` round-trips so that we
//! confirm the DER is not merely *present* but also correctly *parsed*.

use oxitls_rcgen::{CertificateParamsBuilder, OxiEd25519Key};
use rcgen::{ExtendedKeyUsagePurpose, KeyUsagePurpose, PublicKeyData};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use x509_parser::prelude::*;

// ── 1. Bulk key-usages sets exactly the requested flags ───────────────────────

#[test]
fn bulk_key_usages_sets_all() {
    let key = OxiEd25519Key::generate().expect("keygen");
    let spki = PublicKeyData::subject_public_key_info(&key);

    let params = CertificateParamsBuilder::new()
        .with_common_name("BulkKU Test")
        .with_ca()
        .with_key_usages(vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
        ])
        .build_with_spki(&spki)
        .expect("build params");

    let cert = params.self_signed(&key).expect("self-sign");
    let cert_der = cert.der().to_vec();

    let (_, parsed) = X509Certificate::from_der(&cert_der).expect("parse cert DER");
    let ku = parsed
        .key_usage()
        .expect("KU parse ok")
        .expect("KU extension must be present")
        .value;

    assert!(
        ku.digital_signature(),
        "DigitalSignature must be set in parsed KU"
    );
    assert!(ku.key_cert_sign(), "KeyCertSign must be set in parsed KU");
}

// ── 2. Bulk EKU sets exactly the requested flags ──────────────────────────────

#[test]
fn bulk_extended_key_usages_sets_all() {
    let key = OxiEd25519Key::generate().expect("keygen");
    let spki = PublicKeyData::subject_public_key_info(&key);

    let params = CertificateParamsBuilder::new()
        .with_common_name("BulkEKU Test")
        .with_ca()
        .with_extended_key_usages(vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ])
        .build_with_spki(&spki)
        .expect("build params");

    let cert = params.self_signed(&key).expect("self-sign");
    let cert_der = cert.der().to_vec();

    let (_, parsed) = X509Certificate::from_der(&cert_der).expect("parse cert DER");
    let eku = parsed
        .extended_key_usage()
        .expect("EKU parse ok")
        .expect("EKU extension must be present")
        .value;

    assert!(eku.server_auth, "server_auth must be set in parsed EKU");
    assert!(eku.client_auth, "client_auth must be set in parsed EKU");
}

// ── 3. Bulk setter replaces earlier individual calls ─────────────────────────

#[test]
fn bulk_key_usages_replaces_individual() {
    let key = OxiEd25519Key::generate().expect("keygen");
    let spki = PublicKeyData::subject_public_key_info(&key);

    // Individual setter appends DigitalSignature; bulk REPLACES with only KeyCertSign.
    let params = CertificateParamsBuilder::new()
        .with_common_name("BulkReplace Test")
        .with_ca()
        .with_digital_signature()
        .with_key_usages(vec![KeyUsagePurpose::KeyCertSign])
        .build_with_spki(&spki)
        .expect("build params");

    let cert = params.self_signed(&key).expect("self-sign");
    let cert_der = cert.der().to_vec();

    let (_, parsed) = X509Certificate::from_der(&cert_der).expect("parse cert DER");
    let ku = parsed
        .key_usage()
        .expect("KU parse ok")
        .expect("KU extension must be present")
        .value;

    assert!(
        ku.key_cert_sign(),
        "KeyCertSign should be set after bulk replace"
    );
    assert!(
        !ku.digital_signature(),
        "DigitalSignature should have been replaced away by bulk setter"
    );
}

// ── 4. to_rustls_cert_and_key round-trips through pki-types ──────────────────

#[test]
fn to_rustls_cert_and_key_round_trips() {
    // generate_self_signed_ed25519 is the simplest path to a CertifiedKey
    let ck = oxitls_rcgen::generate_self_signed_ed25519(&["localhost"])
        .expect("generate self-signed cert");

    let (certs, key) = ck.to_rustls_cert_and_key();

    assert!(!certs.is_empty(), "cert chain must not be empty");
    assert!(
        !certs[0].as_ref().is_empty(),
        "leaf certificate DER must not be empty"
    );

    match &key {
        PrivateKeyDer::Pkcs8(k) => {
            assert!(
                !k.secret_pkcs8_der().is_empty(),
                "PKCS#8 key bytes must not be empty"
            );
        }
        _other => panic!("expected PKCS#8 key, got a different variant"),
    }

    // Verify the returned types are usable as CertificateDer<'static>
    let _: CertificateDer<'static> = certs.into_iter().next().expect("cert");
}
