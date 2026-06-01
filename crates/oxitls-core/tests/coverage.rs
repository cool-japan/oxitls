// Integration tests for oxitls-core coverage (Wave 3, Slice K)
//
// These tests verify the public API surface of oxitls-core from the
// perspective of downstream crate consumers: Display formatting, From
// conversions, AlertDescription exhaustiveness, ConnectionInfoBuilder
// round-trips, and TlsVersion/CipherSuite Display↔FromStr cycles.

use oxitls_core::{AlertDescription, CipherSuite, ConnectionInfoBuilder, TlsError, TlsVersion};
use std::io;
use std::str::FromStr;

// ─── TlsError Display ────────────────────────────────────────────────────────

#[test]
fn tls_error_display_all_variants() {
    // Every TlsError variant must produce a non-empty, meaningful Display
    // string that does NOT degenerate to a bare Debug repr.
    let cases: &[(TlsError, &str)] = &[
        (TlsError::Io(io::ErrorKind::BrokenPipe), "I/O error:"),
        (
            TlsError::Handshake("bad handshake".into()),
            "handshake error:",
        ),
        (TlsError::BadCert("leaf expired".into()), "bad certificate:"),
        (TlsError::InvalidConfig("no cert".into()), "invalid config:"),
        (
            TlsError::CertRevoked("revoked by CRL".into()),
            "certificate revoked:",
        ),
        (
            TlsError::AlertReceived(AlertDescription::HandshakeFailure),
            "TLS alert received:",
        ),
        (TlsError::Other("catch-all".into()), "TLS error:"),
    ];

    for (err, prefix) in cases {
        let s = err.to_string();
        assert!(
            !s.is_empty(),
            "Display produced empty string for variant: {err:?}"
        );
        assert!(
            s.starts_with(prefix),
            "Expected Display to start with {prefix:?}, got: {s:?}"
        );
    }
}

// ─── From<io::Error> for TlsError ────────────────────────────────────────────

#[test]
fn from_io_error_produces_io_variant() {
    let kinds = [
        io::ErrorKind::BrokenPipe,
        io::ErrorKind::ConnectionReset,
        io::ErrorKind::ConnectionRefused,
        io::ErrorKind::TimedOut,
        io::ErrorKind::UnexpectedEof,
        io::ErrorKind::PermissionDenied,
    ];

    for kind in kinds {
        let io_err = io::Error::new(kind, "test payload");
        let tls_err: TlsError = io_err.into();
        assert!(
            matches!(tls_err, TlsError::Io(_)),
            "Expected TlsError::Io for kind {kind:?}, got: {tls_err:?}"
        );
        // Verify the stored kind matches the original.
        if let TlsError::Io(stored_kind) = tls_err {
            assert_eq!(
                stored_kind, kind,
                "Stored io::ErrorKind {stored_kind:?} != original {kind:?}"
            );
        }
    }
}

#[test]
fn from_tls_error_to_io_error_round_trip() {
    // TlsError -> io::Error conversion must not panic and must produce a
    // sensible ErrorKind for each variant.
    let cases: Vec<(TlsError, io::ErrorKind)> = vec![
        (
            TlsError::Io(io::ErrorKind::BrokenPipe),
            io::ErrorKind::BrokenPipe,
        ),
        (
            TlsError::Handshake("hs".into()),
            io::ErrorKind::ConnectionAborted,
        ),
        (TlsError::BadCert("bc".into()), io::ErrorKind::InvalidData),
        (
            TlsError::InvalidConfig("ic".into()),
            io::ErrorKind::InvalidInput,
        ),
        (
            TlsError::CertRevoked("cr".into()),
            io::ErrorKind::PermissionDenied,
        ),
        (
            TlsError::AlertReceived(AlertDescription::CloseNotify),
            io::ErrorKind::ConnectionAborted,
        ),
    ];

    for (tls_err, expected_kind) in cases {
        let io_err: io::Error = tls_err.into();
        assert_eq!(
            io_err.kind(),
            expected_kind,
            "io::Error kind mismatch for TlsError variant"
        );
    }
}

// ─── AlertDescription Exhaustiveness ─────────────────────────────────────────

#[test]
fn alert_description_exhaustive_from_u8() {
    // Every byte 0..=255 must be accepted without panic.
    for b in 0u8..=255 {
        let desc = AlertDescription::from(b);
        // to_u8() must return the same byte for named variants,
        // and Unknown(b) must also round-trip correctly.
        let back = desc.to_u8();
        if !matches!(desc, AlertDescription::Unknown(_)) {
            assert_eq!(
                back, b,
                "Named variant round-trip failed for byte {b}: back={back}"
            );
        } else {
            // Unknown variant stores the original byte.
            assert_eq!(back, b, "Unknown({b}) round-trip failed");
        }
        // Display must produce a non-empty string for every value.
        let s = desc.to_string();
        assert!(!s.is_empty(), "AlertDescription Display empty for byte {b}");
    }
}

#[test]
fn alert_description_known_rfc_codes() {
    // Spot-check specific RFC 8446 §6 code points.
    let known: &[(u8, AlertDescription)] = &[
        (0, AlertDescription::CloseNotify),
        (10, AlertDescription::UnexpectedMessage),
        (20, AlertDescription::BadRecordMac),
        (22, AlertDescription::RecordOverflow),
        (40, AlertDescription::HandshakeFailure),
        (42, AlertDescription::BadCertificate),
        (43, AlertDescription::UnsupportedCertificate),
        (44, AlertDescription::CertificateRevoked),
        (45, AlertDescription::CertificateExpired),
        (46, AlertDescription::CertificateUnknown),
        (47, AlertDescription::IllegalParameter),
        (48, AlertDescription::UnknownCa),
        (49, AlertDescription::AccessDenied),
        (50, AlertDescription::DecodeError),
        (51, AlertDescription::DecryptError),
        (70, AlertDescription::ProtocolVersion),
        (71, AlertDescription::InsufficientSecurity),
        (80, AlertDescription::InternalError),
        (86, AlertDescription::InappropriateFallback),
        (90, AlertDescription::UserCanceled),
        (109, AlertDescription::MissingExtension),
        (110, AlertDescription::UnsupportedExtension),
        (112, AlertDescription::UnrecognizedName),
        (113, AlertDescription::BadCertificateStatusResponse),
        (115, AlertDescription::UnknownPskIdentity),
        (116, AlertDescription::CertificateRequired),
        (120, AlertDescription::NoApplicationProtocol),
    ];

    for (code, expected) in known {
        let desc = AlertDescription::from(*code);
        assert_eq!(
            &desc, expected,
            "from({code}) produced wrong variant: {desc:?}"
        );
        assert_eq!(
            desc.to_u8(),
            *code,
            "to_u8() round-trip failed for code {code}"
        );
    }

    // An unrecognised code must map to Unknown(n).
    let u = AlertDescription::from(255u8);
    assert_eq!(u, AlertDescription::Unknown(255));
    assert_eq!(u.to_u8(), 255);
}

// ─── ConnectionInfoBuilder ────────────────────────────────────────────────────

#[test]
fn connection_info_builder_round_trip() {
    let alpn = b"h2".to_vec();
    let certs: Vec<Vec<u8>> = vec![vec![0x30, 0x82, 0x01, 0x00]]; // dummy DER prefix

    let info = ConnectionInfoBuilder::new()
        .version(TlsVersion::Tls13)
        .cipher_suite(CipherSuite::Tls13Aes256GcmSha384)
        .alpn_protocol(alpn.clone())
        .sni("example.com".to_string())
        .peer_certificates(certs.clone())
        .build();

    assert_eq!(info.version, Some(TlsVersion::Tls13), "version mismatch");
    assert_eq!(
        info.cipher_suite,
        Some(CipherSuite::Tls13Aes256GcmSha384),
        "cipher_suite mismatch"
    );
    assert_eq!(
        info.alpn_protocol,
        Some(alpn.clone()),
        "alpn_protocol mismatch"
    );
    assert_eq!(info.sni.as_deref(), Some("example.com"), "sni mismatch");
    assert_eq!(info.peer_certificates, certs, "peer_certificates mismatch");
    // Convenience accessor for UTF-8 ALPN.
    assert_eq!(info.alpn_protocol_str(), Some("h2"), "alpn_protocol_str");
}

#[test]
fn connection_info_builder_defaults_are_none() {
    let info = ConnectionInfoBuilder::new().build();

    assert_eq!(info.version, None);
    assert_eq!(info.cipher_suite, None);
    assert_eq!(info.alpn_protocol, None);
    assert_eq!(info.sni, None);
    assert!(
        info.peer_certificates.is_empty(),
        "peer_certificates should be empty by default"
    );
    assert_eq!(
        info.alpn_protocol_str(),
        None,
        "alpn_protocol_str should be None when no ALPN"
    );
}

#[test]
fn connection_info_builder_partial_fields() {
    // Verify that fields omitted from the builder stay None.
    let info = ConnectionInfoBuilder::new()
        .version(TlsVersion::Tls12)
        .build();

    assert_eq!(info.version, Some(TlsVersion::Tls12));
    assert_eq!(info.cipher_suite, None, "unset cipher_suite must be None");
    assert_eq!(info.sni, None, "unset sni must be None");
}

// ─── TlsVersion Display ↔ FromStr round-trip ──────────────────────────────────

#[test]
fn tls_version_round_trip_display_fromstr_all_variants() {
    // Exhaustively iterate TlsVersion::ALL — every variant must survive the
    // Display → FromStr cycle without loss of information.
    for &version in TlsVersion::ALL {
        let s = version.to_string();
        assert!(
            !s.is_empty(),
            "TlsVersion Display produced empty string for {version:?}"
        );
        let back = TlsVersion::from_str(&s)
            .unwrap_or_else(|e| panic!("TlsVersion::from_str({s:?}) failed for {version:?}: {e}"));
        assert_eq!(
            version, back,
            "TlsVersion round-trip failed for {version:?}: Display={s:?}"
        );
    }
}

#[test]
fn tls_version_display_strings() {
    assert_eq!(TlsVersion::Tls12.to_string(), "TLS 1.2");
    assert_eq!(TlsVersion::Tls13.to_string(), "TLS 1.3");
}

#[test]
fn tls_version_from_str_error_on_unknown() {
    let result = TlsVersion::from_str("TLS 2.0");
    assert!(
        result.is_err(),
        "Expected error for unknown version string, got: {result:?}"
    );
}

// ─── CipherSuite Display ↔ FromStr round-trip ─────────────────────────────────

#[test]
fn cipher_suite_round_trip_display_fromstr_all_variants() {
    // Exhaustively iterate CipherSuite::ALL — every variant must survive the
    // Display → FromStr cycle without loss of information.
    for &suite in CipherSuite::ALL {
        let s = suite.to_string();
        assert!(
            !s.is_empty(),
            "CipherSuite Display produced empty string for {suite:?}"
        );
        let back = CipherSuite::from_str(&s)
            .unwrap_or_else(|e| panic!("CipherSuite::from_str({s:?}) failed for {suite:?}: {e}"));
        assert_eq!(
            suite, back,
            "CipherSuite round-trip failed for {suite:?}: Display={s:?}"
        );
    }
}

#[test]
fn cipher_suite_iana_names_spot_check() {
    // Verify the human-readable IANA names produced by Display.
    let expected: &[(CipherSuite, &str)] = &[
        (CipherSuite::Tls13Aes128GcmSha256, "TLS_AES_128_GCM_SHA256"),
        (CipherSuite::Tls13Aes256GcmSha384, "TLS_AES_256_GCM_SHA384"),
        (
            CipherSuite::Tls13Chacha20Poly1305Sha256,
            "TLS_CHACHA20_POLY1305_SHA256",
        ),
        (
            CipherSuite::Tls12EcdheRsaAes128GcmSha256,
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        ),
        (
            CipherSuite::Tls12EcdheRsaAes256GcmSha384,
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        ),
        (
            CipherSuite::Tls12EcdheEcdsaAes128GcmSha256,
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        ),
        (
            CipherSuite::Tls12EcdheEcdsaChacha20Poly1305Sha256,
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        ),
        (
            CipherSuite::Tls12EcdheRsaChacha20Poly1305Sha256,
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        ),
    ];

    for (suite, name) in expected {
        assert_eq!(&suite.to_string(), name, "Display mismatch for {suite:?}");
    }
}

#[test]
fn cipher_suite_from_str_error_on_unknown() {
    let result = CipherSuite::from_str("NOT_A_REAL_CIPHER_SUITE");
    assert!(
        result.is_err(),
        "Expected error for unknown cipher suite string, got: {result:?}"
    );
}
