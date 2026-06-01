//! Integration tests for RFC 6962 SCT / Certificate Transparency verification.
//!
//! Tests exercise:
//! 1. `parse_sct_list` wire-format parsing (round-trip fields).
//! 2. `verify_sct_signature` with a freshly-generated Ed25519 signing key.
//! 3. `verify_sct_signature` with a freshly-generated ECDSA P-256 signing key.
//! 4. `verify_sct_signature` rejection of a corrupted signature.
//! 5. `known_ct_logs()` returns a non-empty list with distinct IDs.
//!
//! NOTE: We avoid `rand 0.8` OsRng with `p256 0.14.0-rc.9` because p256 uses
//! `rand_core 0.10` while rand 0.8 uses `rand_core 0.6`. Fixed test scalars are
//! used for ECDSA P-256 key generation. Ed25519 uses `ed25519_dalek::SigningKey::from_bytes`.

use sha2::{Digest as _, Sha256};

use oxitls_adapter_rustls_rustcrypto::verifier::{
    ct_logs::known_ct_logs,
    sct::{
        build_sct_signed_data, parse_sct_list, verify_sct_signature, CtKeyAlg, CtLog, ParsedSct,
        SctVerifyError,
    },
};

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Build a minimal SCT wire-format list with one entry.
///
/// Wire format per RFC 6962 §3.3:
///   u16-BE  total_list_len
///   u16-BE  sct_entry_len
///   [sct_entry_len bytes]:
///     u8      version (0x00)
///     [32]    log_id
///     u64-BE  timestamp_ms
///     u16-BE  ext_len  (0 = no extensions)
///     u8      hash_alg
///     u8      sig_alg
///     u16-BE  sig_len
///     [sig_len bytes]  signature
fn build_sct_wire(
    log_id: &[u8; 32],
    timestamp_ms: u64,
    hash_alg: u8,
    sig_alg: u8,
    sig_bytes: &[u8],
) -> Vec<u8> {
    let sig_len = sig_bytes.len();
    // sct_entry_len = 1 + 32 + 8 + 2 + 1 + 1 + 2 + sig_len
    let entry_len = 1 + 32 + 8 + 2 + 1 + 1 + 2 + sig_len;
    // total list = 2 (per-entry length prefix) + entry_len
    let list_len = 2 + entry_len;

    let mut buf = Vec::with_capacity(2 + list_len);

    // Outer u16 = total list length.
    buf.push(((list_len >> 8) & 0xff) as u8);
    buf.push((list_len & 0xff) as u8);

    // Per-entry u16 = entry length.
    buf.push(((entry_len >> 8) & 0xff) as u8);
    buf.push((entry_len & 0xff) as u8);

    // Version = 0x00.
    buf.push(0x00);

    // log_id (32 bytes).
    buf.extend_from_slice(log_id);

    // timestamp_ms (u64 BE).
    buf.extend_from_slice(&timestamp_ms.to_be_bytes());

    // ext_len = 0 (no extensions).
    buf.push(0x00);
    buf.push(0x00);

    // hash_alg + sig_alg.
    buf.push(hash_alg);
    buf.push(sig_alg);

    // sig_len + signature.
    buf.push(((sig_len >> 8) & 0xff) as u8);
    buf.push((sig_len & 0xff) as u8);
    buf.extend_from_slice(sig_bytes);

    buf
}

/// Build a synthetic SPKI DER for a raw Ed25519 public key (32 bytes).
///
/// The ASN.1 structure is:
/// ```text
/// SEQUENCE {
///   SEQUENCE {
///     OID 1.3.101.112  -- id-EdDSA / id-Ed25519
///   }
///   BIT STRING { 0x00 (no unused bits) || <32-byte raw key> }
/// }
/// ```
fn ed25519_spki_der(raw_pub: &[u8; 32]) -> Vec<u8> {
    // OID 1.3.101.112 DER = 06 03 2b 65 70
    let oid_bytes: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];
    let alg_seq_len = oid_bytes.len();
    let alg_seq = {
        let mut v = Vec::with_capacity(2 + alg_seq_len);
        v.push(0x30); // SEQUENCE
        v.push(alg_seq_len as u8);
        v.extend_from_slice(oid_bytes);
        v
    };

    // BIT STRING: 0x04 03 00 <32 bytes>
    let bit_string = {
        let mut v = Vec::with_capacity(2 + 1 + 32);
        v.push(0x03); // BIT STRING tag
        v.push(1 + 32); // length = 33 (1 unused-bits byte + 32 key bytes)
        v.push(0x00); // 0 unused bits
        v.extend_from_slice(raw_pub);
        v
    };

    let inner_len = alg_seq.len() + bit_string.len();
    let mut outer = Vec::with_capacity(2 + inner_len);
    outer.push(0x30); // outer SEQUENCE tag
    outer.push(inner_len as u8);
    outer.extend_from_slice(&alg_seq);
    outer.extend_from_slice(&bit_string);
    outer
}

/// Compute SHA-256 of `data` and return 32-byte array — used as log_id.
fn sha256_id(data: &[u8]) -> [u8; 32] {
    let hash = Sha256::digest(data);
    let mut id = [0u8; 32];
    id.copy_from_slice(&hash);
    id
}

// ── Test 1: Parser round-trip ─────────────────────────────────────────────────

#[test]
fn sct_parser_roundtrip_extended() {
    let log_id = [0x42u8; 32];
    let timestamp_ms: u64 = 1_748_304_000_000;
    let fake_sig = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22];
    let hash_alg = 0x04; // sha256
    let sig_alg = 0x03; // ecdsa

    let wire = build_sct_wire(&log_id, timestamp_ms, hash_alg, sig_alg, &fake_sig);

    let scts = parse_sct_list(&wire).expect("parse_sct_list should succeed");
    assert_eq!(scts.len(), 1, "should parse exactly one SCT");

    let sct = &scts[0];
    assert_eq!(sct.sct_version, 0x00, "version should be 0");
    assert_eq!(sct.log_id, log_id, "log_id should match");
    assert_eq!(sct.timestamp_ms, timestamp_ms, "timestamp should match");
    assert_eq!(
        sct.extensions,
        Vec::<u8>::new(),
        "extensions should be empty"
    );
    assert_eq!(sct.hash_alg, hash_alg, "hash_alg should match");
    assert_eq!(sct.sig_alg, sig_alg, "sig_alg should match");
    assert_eq!(
        sct.signature,
        fake_sig.as_slice(),
        "signature bytes should match"
    );
}

// ── Test 2: Ed25519 valid signature passes ────────────────────────────────────

#[test]
fn sct_signature_valid_ed25519() {
    use ed25519_dalek::{Signer as _, SigningKey};

    // Use a fixed 32-byte private key seed to avoid OsRng.
    let seed: [u8; 32] = [
        0x3c, 0x4a, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
        0xee, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        0x0d, 0x0e,
    ];
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    let raw_pub: [u8; 32] = verifying_key.to_bytes();

    // Build the SPKI DER for Ed25519 public key.
    let spki_der = ed25519_spki_der(&raw_pub);

    // Log ID = SHA-256 of SPKI DER.
    let log_id = sha256_id(&spki_der);

    // Fake certificate DER (just some bytes; the test verifies crypto, not cert parsing).
    let cert_der = b"fake-cert-der-for-sct-ed25519-test";

    // Build a ParsedSct with timestamp and no extensions.
    let timestamp_ms: u64 = 1_748_304_000_000;
    let sct_without_sig = ParsedSct {
        sct_version: 0x00,
        log_id,
        timestamp_ms,
        extensions: Vec::new(),
        hash_alg: 0x04,
        sig_alg: 0x07, // ed25519
        signature: Vec::new(),
    };

    // Build the signed data using the helper.
    let signed_data = build_sct_signed_data(&sct_without_sig, cert_der);

    // Sign with Ed25519.
    let sig: ed25519_dalek::Signature = signing_key.sign(&signed_data);
    let sig_bytes = sig.to_bytes().to_vec();

    // Build the final SCT with the real signature.
    let sct = ParsedSct {
        signature: sig_bytes,
        ..sct_without_sig
    };

    // Create a CtLog entry using the SPKI DER.
    let log = CtLog {
        id: log_id,
        public_key_der: spki_der,
        key_alg: CtKeyAlg::Ed25519,
    };

    let result = verify_sct_signature(&log, &signed_data, &sct);
    assert!(
        result.is_ok(),
        "Ed25519 SCT signature should verify: {result:?}"
    );
}

// ── Test 3: ECDSA P-256 valid signature passes ────────────────────────────────

#[test]
fn sct_signature_valid_ecdsa_p256() {
    use p256::ecdsa::{signature::Signer as _, DerSignature, SigningKey, VerifyingKey};
    use p256::pkcs8::EncodePublicKey as _;

    // Fixed P-256 scalar — avoids rand 0.8 / rand_core 0.10 incompatibility.
    let scalar_bytes: [u8; 32] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
        0xcd, 0xef,
    ];
    let signing_key = SigningKey::from_bytes(&scalar_bytes.into()).expect("valid scalar");
    let vk: &VerifyingKey = signing_key.verifying_key();

    // SPKI DER for the verifying key.
    let spki_der = vk
        .to_public_key_der()
        .expect("spki der")
        .as_bytes()
        .to_vec();

    // Log ID = SHA-256 of SPKI DER.
    let log_id = sha256_id(&spki_der);

    // Fake cert DER.
    let cert_der = b"fake-cert-der-for-sct-p256-test";

    // Build ParsedSct (signature filled in after signing).
    let timestamp_ms: u64 = 1_748_304_000_000;
    let sct_without_sig = ParsedSct {
        sct_version: 0x00,
        log_id,
        timestamp_ms,
        extensions: Vec::new(),
        hash_alg: 0x04,
        sig_alg: 0x03, // ecdsa
        signature: Vec::new(),
    };

    // Build the RFC 6962 §3.2 signed_data blob.
    let signed_data = build_sct_signed_data(&sct_without_sig, cert_der);

    // Sign with P-256.
    let sig: DerSignature = signing_key.sign(&signed_data);
    let sig_bytes = sig.to_bytes().to_vec();

    let sct = ParsedSct {
        signature: sig_bytes,
        ..sct_without_sig
    };

    // Create a CtLog entry.
    let log = CtLog {
        id: log_id,
        public_key_der: spki_der,
        key_alg: CtKeyAlg::EcdsaP256Sha256,
    };

    let result = verify_sct_signature(&log, &signed_data, &sct);
    assert!(
        result.is_ok(),
        "ECDSA P-256 SCT signature should verify: {result:?}"
    );
}

// ── Test 4: Invalid signature is rejected ────────────────────────────────────

#[test]
fn sct_signature_invalid_rejected() {
    use p256::ecdsa::{signature::Signer as _, DerSignature, SigningKey, VerifyingKey};
    use p256::pkcs8::EncodePublicKey as _;

    let scalar_bytes: [u8; 32] = [
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
        0x32, 0x10,
    ];
    let signing_key = SigningKey::from_bytes(&scalar_bytes.into()).expect("valid scalar");
    let vk: &VerifyingKey = signing_key.verifying_key();
    let spki_der = vk
        .to_public_key_der()
        .expect("spki der")
        .as_bytes()
        .to_vec();
    let log_id = sha256_id(&spki_der);

    let cert_der = b"fake-cert-for-corrupt-sig-test";
    let timestamp_ms: u64 = 1_748_304_000_001;

    let sct_without_sig = ParsedSct {
        sct_version: 0x00,
        log_id,
        timestamp_ms,
        extensions: Vec::new(),
        hash_alg: 0x04,
        sig_alg: 0x03,
        signature: Vec::new(),
    };
    let signed_data = build_sct_signed_data(&sct_without_sig, cert_der);

    let sig: DerSignature = signing_key.sign(&signed_data);
    let mut sig_bytes = sig.to_bytes().to_vec();

    // Corrupt the last byte of the signature.
    if let Some(last) = sig_bytes.last_mut() {
        *last ^= 0xff;
    }

    let sct = ParsedSct {
        signature: sig_bytes,
        ..sct_without_sig
    };

    let log = CtLog {
        id: log_id,
        public_key_der: spki_der,
        key_alg: CtKeyAlg::EcdsaP256Sha256,
    };

    let result = verify_sct_signature(&log, &signed_data, &sct);
    assert!(result.is_err(), "corrupted SCT signature must be rejected");
    // Error should indicate signature invalidity or decode failure.
    let err = result.unwrap_err();
    let err_msg = format!("{err:?}");
    assert!(
        matches!(
            err,
            SctVerifyError::SignatureInvalid | SctVerifyError::SigDecode(_)
        ),
        "error should be SignatureInvalid or SigDecode: {err_msg}"
    );
}

// ── Test 5: known_ct_logs returns non-empty list with distinct IDs ────────────

#[test]
fn known_ct_logs_nonempty_and_distinct_ids() {
    let logs = known_ct_logs();

    assert!(!logs.is_empty(), "known_ct_logs() must not be empty");

    // All log IDs must be distinct.
    let mut ids = std::collections::HashSet::new();
    for log in &logs.0 {
        let inserted = ids.insert(log.id);
        assert!(
            inserted,
            "duplicate log ID found: {}",
            log.id
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join("")
        );
    }

    // All logs must use ECDSA P-256 SHA-256 (our current known logs).
    for log in &logs.0 {
        assert!(
            matches!(log.key_alg, CtKeyAlg::EcdsaP256Sha256),
            "expected all known CT logs to use EcdsaP256Sha256"
        );
    }

    // There must be at least 2 distinct trusted logs (practical minimum for CT).
    assert!(
        logs.0.len() >= 2,
        "known_ct_logs() should contain at least 2 logs, got {}",
        logs.0.len()
    );
}
