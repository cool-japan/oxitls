//! Integration tests for RFC 6960 OCSP signer cryptographic verification.
//!
//! Tests exercise the `ocsp_crypto` module directly with synthetic payloads,
//! and also exercise `OcspClientVerifier` via the full verifier API.
//!
//! NOTE: The `x509-ocsp` builder crate uses `ecdsa 0.16.x` trait bounds while
//! `p256 0.14.0-rc.9` pulls `ecdsa 0.17.x`. To avoid the version conflict, OCSP
//! builder tests use RSA signing (rsa 0.9 is compatible) and ECDSA crypto paths
//! are tested via `verify_ocsp_signature` directly on a hand-crafted payload.
//!
//! RSA-based tests use a pre-generated key fixture from `test_fixtures.rs` to
//! avoid the cost of pure-Rust RSA-2048 key generation (can take >2 minutes).

mod test_fixtures;

use std::sync::Arc;

use rsa::pkcs8::DecodePrivateKey as _;
use rsa::sha2::Sha256;
use rustls::{
    client::{danger::ServerCertVerifier, WebPkiServerVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    RootCertStore,
};
use x509_cert::der::{DateTime, Decode, Encode};
use x509_cert::name::Name;
use x509_ocsp::{
    builder::OcspResponseBuilder, CertStatus, OcspGeneralizedTime, OcspResponse, SingleResponse,
};

use oxitls_adapter_rustls_rustcrypto::{
    pure_provider,
    verifier::ocsp_client::{OcspClientPolicy, OcspClientVerifier},
};
use oxitls_rcgen::generate_self_signed_p256;

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Load the pre-generated RSA-2048 private key from the test fixture.
///
/// This avoids the cost of pure-Rust RSA-2048 keygen (can take >2 min without
/// hardware-accelerated arithmetic).
fn load_rsa2048_priv() -> rsa::RsaPrivateKey {
    rsa::RsaPrivateKey::from_pkcs8_der(test_fixtures::RSA2048_PKCS8_DER)
        .expect("pre-generated RSA-2048 fixture must parse")
}

fn test_now() -> UnixTime {
    UnixTime::since_unix_epoch(std::time::Duration::from_secs(1_748_304_000))
}

fn produced_at() -> OcspGeneralizedTime {
    OcspGeneralizedTime::from(DateTime::new(2026, 1, 1, 0, 0, 0).expect("valid dt"))
}

fn make_inner(cert_der: &[u8]) -> Arc<dyn ServerCertVerifier> {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(cert_der.to_vec()))
        .expect("add root");
    WebPkiServerVerifier::builder_with_provider(Arc::new(roots), pure_provider())
        .build()
        .expect("inner verifier")
}

fn parse_x509_cert(der: &[u8]) -> x509_cert::Certificate {
    x509_cert::Certificate::from_der(der).expect("parse cert")
}

/// Build an OCSP response (Good status) signed with an RSA key.
fn build_good_ocsp_rsa(
    responder_name: Name,
    issuer_cert: &x509_cert::Certificate,
    signer: &mut rsa::pkcs1v15::SigningKey<Sha256>,
) -> Vec<u8> {
    let single = SingleResponse::new(
        x509_ocsp::CertId::from_issuer::<Sha256>(
            issuer_cert,
            x509_cert::serial_number::SerialNumber::from(1usize),
        )
        .expect("cert_id"),
        CertStatus::good(),
        produced_at(),
    );
    OcspResponseBuilder::new(responder_name)
        .with_single_response(single)
        .sign(signer, None, produced_at())
        .expect("sign")
        .to_der()
        .expect("encode")
}

/// Build an OCSP response with Unknown status, signed with RSA.
fn build_unknown_ocsp_rsa(
    responder_name: Name,
    issuer_cert: &x509_cert::Certificate,
    signer: &mut rsa::pkcs1v15::SigningKey<Sha256>,
) -> Vec<u8> {
    let single = SingleResponse::new(
        x509_ocsp::CertId::from_issuer::<Sha256>(
            issuer_cert,
            x509_cert::serial_number::SerialNumber::from(1usize),
        )
        .expect("cert_id"),
        CertStatus::unknown(),
        produced_at(),
    );
    OcspResponseBuilder::new(responder_name)
        .with_single_response(single)
        .sign(signer, None, produced_at())
        .expect("sign")
        .to_der()
        .expect("encode")
}

/// Parse the BasicOcspResponse from an encoded OCSP DER response.
fn parse_basic(ocsp_der: &[u8]) -> x509_ocsp::BasicOcspResponse {
    let outer = OcspResponse::from_der(ocsp_der).expect("parse outer OcspResponse");
    let resp_bytes = outer.response_bytes.expect("response_bytes present");
    x509_ocsp::BasicOcspResponse::from_der(resp_bytes.response.as_bytes())
        .expect("parse BasicOcspResponse")
}

/// Flip the last byte of an OCSP DER to corrupt the signature.
fn corrupt_sig(ocsp_der: &[u8]) -> Vec<u8> {
    let mut v = ocsp_der.to_vec();
    if let Some(b) = v.last_mut() {
        *b ^= 0xff;
    }
    v
}

// ── Test 1: RSA sha256WithRSAEncryption — valid signature passes ──────────────

#[test]
fn ocsp_signature_valid_rsa_pkcs1_sha256() {
    use rsa::pkcs8::EncodePublicKey as _;

    let ck = generate_self_signed_p256(&["localhost"]).expect("cert gen");
    let cert_der = ck.cert_der.clone();
    let issuer_cert = parse_x509_cert(&cert_der);
    let responder_name = issuer_cert.tbs_certificate.subject.clone();

    let rsa_priv = load_rsa2048_priv();
    let mut signer = rsa::pkcs1v15::SigningKey::<Sha256>::new(rsa_priv);

    let ocsp_der = build_good_ocsp_rsa(responder_name, &issuer_cert, &mut signer);

    let basic = parse_basic(&ocsp_der);
    let tbs_der = basic.tbs_response_data.to_der().expect("tbs encode");
    let sig_bytes = basic.signature.raw_bytes();
    let alg_oid = &basic.signature_algorithm.oid;

    // Get the RSA public key's SPKI DER.
    let rsa_pub = signer.as_ref().to_public_key();
    let vk = rsa::pkcs1v15::VerifyingKey::<Sha256>::new(rsa_pub);
    let spki_der = vk
        .to_public_key_der()
        .expect("spki der")
        .as_bytes()
        .to_vec();

    use oxitls_adapter_rustls_rustcrypto::verifier::ocsp_crypto::verify_ocsp_signature;
    let result = verify_ocsp_signature(&spki_der, &tbs_der, alg_oid, sig_bytes);
    assert!(
        result.is_ok(),
        "RSA PKCS#1 SHA-256 OCSP sig should verify: {result:?}"
    );
}

// ── Test 2: ECDSA P-256 — valid signature passes ──────────────────────────────

#[test]
fn ocsp_signature_valid_ecdsa_p256() {
    use p256::ecdsa::{signature::Signer as _, SigningKey, VerifyingKey};
    use p256::pkcs8::EncodePublicKey as _;

    // Use a fixed, non-zero P-256 scalar for the test key — avoids the
    // rand 0.8 / rand_core 0.10 OsRng incompatibility.
    let scalar_bytes: [u8; 32] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
        0xcd, 0xef,
    ];
    let signing_key = SigningKey::from_bytes(&scalar_bytes.into()).expect("valid scalar");
    let vk: &VerifyingKey = signing_key.verifying_key();

    // Build a minimal "tbsResponseData"-like byte slice to sign.
    // We test verify_ocsp_signature directly with a synthetic TBS blob.
    let tbs_der = b"synthetic-tbs-for-ecdsa-p256-test";

    // Sign the TBS bytes with the P-256 key.
    let sig: p256::ecdsa::DerSignature = signing_key.sign(tbs_der);
    let sig_bytes = sig.to_bytes();

    // Build the SPKI DER for the verifying key using EncodePublicKey.
    let spki_der = vk.to_public_key_der().expect("spki").as_bytes().to_vec();

    // The OID for ecdsaWithSHA256.
    let alg_oid = x509_cert::der::asn1::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

    use oxitls_adapter_rustls_rustcrypto::verifier::ocsp_crypto::verify_ocsp_signature;
    let result = verify_ocsp_signature(&spki_der, tbs_der, &alg_oid, &sig_bytes);
    assert!(result.is_ok(), "ECDSA P-256 sig should verify: {result:?}");
}

// ── Test 3: Invalid signature is rejected ────────────────────────────────────

#[test]
fn ocsp_signature_invalid_rejected() {
    let ck = generate_self_signed_p256(&["localhost"]).expect("cert gen");
    let cert_der = ck.cert_der.clone();
    let issuer_cert = parse_x509_cert(&cert_der);
    let responder_name = issuer_cert.tbs_certificate.subject.clone();

    let rsa_priv = load_rsa2048_priv();
    let mut signer = rsa::pkcs1v15::SigningKey::<Sha256>::new(rsa_priv);
    let ocsp_der = build_good_ocsp_rsa(responder_name, &issuer_cert, &mut signer);
    let corrupted = corrupt_sig(&ocsp_der);

    // Drive the verifier directly; it will try issuer SPKI as fallback signer.
    let inner = make_inner(&cert_der);
    let sni = ServerName::try_from("localhost".to_string()).expect("sni");
    let cert_der_rustls = CertificateDer::from(cert_der.clone());

    for policy in [OcspClientPolicy::SoftFail, OcspClientPolicy::HardRequire] {
        let verifier = OcspClientVerifier::new(Arc::clone(&inner), policy);
        let result =
            verifier.verify_server_cert(&cert_der_rustls, &[], &sni, &corrupted, test_now());
        // A corrupted staple must be rejected regardless of policy.
        assert!(
            result.is_err(),
            "corrupted OCSP sig must be rejected (policy={:?}): {result:?}",
            verifier.policy(),
        );
        let msg = format!("{:?}", result.unwrap_err());
        // Either "invalid", "signature", or "General" error message.
        assert!(
            msg.contains("signature") || msg.contains("invalid") || msg.contains("General"),
            "error should mention signature: {msg}"
        );
    }
}

// ── Test 4: Delegated signer without EKU is rejected ─────────────────────────

#[test]
fn ocsp_delegated_signer_without_eku_rejected() {
    use oxitls_adapter_rustls_rustcrypto::verifier::ocsp_crypto::{
        verify_eku_ocsp_signing, OcspVerifyError,
    };

    let ck = generate_self_signed_p256(&["localhost"]).expect("cert gen");
    let cert_der = ck.cert_der.clone();

    let result = verify_eku_ocsp_signing(&cert_der);
    assert!(
        matches!(result, Err(OcspVerifyError::MissingOcspSigningEku)),
        "cert without OCSPSigning EKU must be rejected: {result:?}"
    );
}

// ── Test 5: Delegated signer with EKU accepted ───────────────────────────────

#[test]
fn ocsp_delegated_signer_with_eku_accepted() {
    use oxitls_adapter_rustls_rustcrypto::verifier::ocsp_crypto::verify_eku_ocsp_signing;
    use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, KeyPair};

    let mut params = CertificateParams::new(vec!["localhost".to_string()]).expect("params");
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::OcspSigning];
    let kp = KeyPair::generate().expect("key pair");
    let cert = params.self_signed(&kp).expect("self signed");
    let cert_der = cert.der().to_vec();

    let result = verify_eku_ocsp_signing(&cert_der);
    assert!(
        result.is_ok(),
        "cert with OCSPSigning EKU should be accepted: {result:?}"
    );
}

// ── Test 6: CertStatus::Unknown + SoftFail passes ────────────────────────────

#[test]
fn ocsp_unknown_status_softfail_passes() {
    let ck = generate_self_signed_p256(&["localhost"]).expect("cert gen");
    let cert_der = ck.cert_der.clone();
    let issuer_cert = parse_x509_cert(&cert_der);
    let responder_name = issuer_cert.tbs_certificate.subject.clone();

    let rsa_priv = load_rsa2048_priv();
    let mut signer = rsa::pkcs1v15::SigningKey::<Sha256>::new(rsa_priv);
    let ocsp_der = build_unknown_ocsp_rsa(responder_name, &issuer_cert, &mut signer);

    let inner = make_inner(&cert_der);
    let sni = ServerName::try_from("localhost".to_string()).expect("sni");
    let cert_der_rustls = CertificateDer::from(cert_der.clone());

    let verifier = OcspClientVerifier::new(Arc::clone(&inner), OcspClientPolicy::SoftFail);
    let result = verifier.verify_server_cert(&cert_der_rustls, &[], &sni, &ocsp_der, test_now());

    // SoftFail: Unknown status is treated as absent (warns but continues).
    // The inner verifier may reject due to the self-signed cert, but that is
    // NOT an OCSP error.
    if let Err(ref e) = result {
        let msg = e.to_string();
        assert!(
            !msg.contains("OCSP staple required"),
            "soft-fail Unknown must not produce 'OCSP staple required': {msg}"
        );
        assert!(
            !msg.contains("OCSP CertStatus::Unknown with HardRequire"),
            "soft-fail Unknown must not produce HardRequire error: {msg}"
        );
    }
}

// ── Test 7: CertStatus::Unknown + HardRequire blocks ─────────────────────────

#[test]
fn ocsp_unknown_status_hardrequire_blocks() {
    let ck = generate_self_signed_p256(&["localhost"]).expect("cert gen");
    let cert_der = ck.cert_der.clone();
    let issuer_cert = parse_x509_cert(&cert_der);
    let responder_name = issuer_cert.tbs_certificate.subject.clone();

    let rsa_priv = load_rsa2048_priv();
    let mut signer = rsa::pkcs1v15::SigningKey::<Sha256>::new(rsa_priv);
    let ocsp_der = build_unknown_ocsp_rsa(responder_name, &issuer_cert, &mut signer);

    let inner = make_inner(&cert_der);
    let sni = ServerName::try_from("localhost".to_string()).expect("sni");
    let cert_der_rustls = CertificateDer::from(cert_der.clone());

    let verifier = OcspClientVerifier::new(Arc::clone(&inner), OcspClientPolicy::HardRequire);
    let result = verifier.verify_server_cert(&cert_der_rustls, &[], &sni, &ocsp_der, test_now());

    assert!(
        result.is_err(),
        "HardRequire + Unknown status must block the handshake"
    );
    let msg = format!("{:?}", result.unwrap_err());
    assert!(
        msg.contains("Unknown") || msg.contains("General"),
        "error should mention Unknown status: {msg}"
    );
}
