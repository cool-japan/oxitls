//! Wave 4 coverage tests for oxitls-core type expansion.

use oxitls_core::{CipherSuite, ConnectionInfo, TlsError, TlsVersion};

// ── From<rustls::Error> ──────────────────────────────────────────────────────

#[test]
fn from_rustls_error_maps_no_certs_to_cert_invalid() {
    let e = rustls::Error::NoCertificatesPresented;
    let t: TlsError = e.into();
    assert!(
        matches!(t, TlsError::CertInvalid(_)),
        "expected CertInvalid, got {t:?}"
    );
}

#[test]
fn from_rustls_error_maps_peer_incompatible_to_protocol_violation() {
    let e = rustls::Error::PeerIncompatible(rustls::PeerIncompatible::Tls12NotOffered);
    let t: TlsError = e.into();
    assert!(
        matches!(t, TlsError::ProtocolViolation(_)),
        "expected ProtocolViolation, got {t:?}"
    );
}

#[test]
fn from_rustls_error_maps_peer_misbehaved_to_protocol_violation() {
    let e = rustls::Error::PeerMisbehaved(rustls::PeerMisbehaved::UnsolicitedCertExtension);
    let t: TlsError = e.into();
    assert!(
        matches!(t, TlsError::ProtocolViolation(_)),
        "expected ProtocolViolation, got {t:?}"
    );
}

#[test]
fn from_rustls_error_maps_alert_to_handshake() {
    let e = rustls::Error::AlertReceived(rustls::AlertDescription::HandshakeFailure);
    let t: TlsError = e.into();
    assert!(
        matches!(t, TlsError::Handshake(_)),
        "expected Handshake, got {t:?}"
    );
}

#[test]
fn from_rustls_error_fallback_maps_to_other() {
    // DecryptError is a message-level error that does not match the specific arms
    // and should fall through to TlsError::Other.
    let e = rustls::Error::DecryptError;
    let t: TlsError = e.into();
    assert!(matches!(t, TlsError::Other(_)), "expected Other, got {t:?}");
}

#[test]
fn from_rustls_error_general_fault_maps_to_other() {
    let e = rustls::Error::General("some general fault".to_string());
    let t: TlsError = e.into();
    assert!(
        matches!(t, TlsError::Other(_)),
        "expected Other for General, got {t:?}"
    );
}

// ── CertInvalid and ProtocolViolation predicates ─────────────────────────────

#[test]
fn cert_invalid_is_cert() {
    let e = TlsError::CertInvalid("reason".to_string());
    assert!(e.is_cert(), "CertInvalid should be a cert error");
    assert!(!e.is_handshake());
    assert!(!e.is_io());
}

#[test]
fn protocol_violation_predicate() {
    let e = TlsError::ProtocolViolation("something".to_string());
    assert!(e.is_protocol_violation());
    assert!(!e.is_cert());
}

#[test]
fn cert_invalid_display() {
    let e = TlsError::CertInvalid("BadSignature".to_string());
    assert!(
        e.to_string().starts_with("invalid certificate:"),
        "unexpected display: {e}"
    );
}

#[test]
fn protocol_violation_display() {
    let e = TlsError::ProtocolViolation("misbehaved".to_string());
    assert!(
        e.to_string().starts_with("protocol violation:"),
        "unexpected display: {e}"
    );
}

// ── CipherSuite::Unknown ─────────────────────────────────────────────────────

#[test]
fn cipher_suite_unknown_iana_value() {
    assert_eq!(CipherSuite::Unknown.iana_value(), [0xFF, 0xFF]);
}

#[test]
fn cipher_suite_unknown_is_not_tls13() {
    // Unknown is not a TLS 1.3 suite.
    assert!(!CipherSuite::Unknown.is_tls13());
    // is_tls12() is defined as !is_tls13(), so Unknown returns true here.
    // We check is_unknown() to distinguish it from known TLS 1.2 suites.
    assert!(CipherSuite::Unknown.is_unknown());
}

#[test]
fn cipher_suite_unknown_display() {
    assert_eq!(CipherSuite::Unknown.to_string(), "UNKNOWN");
}

#[test]
fn cipher_suite_unknown_from_str() {
    let s: CipherSuite = "UNKNOWN".parse().expect("should parse UNKNOWN");
    assert_eq!(s, CipherSuite::Unknown);
}

// ── connection_info_from compiles and type-checks ────────────────────────────

/// Compile-time proof that `connection_info_from` is exported with the expected
/// signature.  We cannot instantiate `CommonState` directly (it has no public
/// constructor), but we can verify the generic monomorphises against a concrete
/// type that `Deref`s to `CommonState`.
///
/// `rustls::Connection` implements `Deref<Target = CommonState>`.
///
/// This test is intentionally empty at runtime — the assertion is that it
/// compiles at all.
#[test]
fn connection_info_from_signature_is_exported() {
    // Use the function as a value to confirm it is accessible and has the
    // correct bound.  `rustls::Connection` → `Deref<Target = CommonState>`.
    let _ = oxitls_core::connection_info_from::<rustls::Connection>;
}

// ── ConnectionInfo builder round-trip ────────────────────────────────────────

#[test]
fn connection_info_with_all_fields() {
    let info = ConnectionInfo::new()
        .with_version(TlsVersion::Tls13)
        .with_cipher_suite(CipherSuite::Tls13Aes256GcmSha384)
        .with_alpn_protocol(b"h2".to_vec())
        .with_sni("secure.example.com".to_string());

    assert_eq!(info.version, Some(TlsVersion::Tls13));
    assert_eq!(info.cipher_suite, Some(CipherSuite::Tls13Aes256GcmSha384));
    assert_eq!(info.alpn_protocol_str(), Some("h2"));
    assert_eq!(info.sni.as_deref(), Some("secure.example.com"));
}
