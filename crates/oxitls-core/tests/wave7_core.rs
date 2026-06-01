use oxitls_core::TlsError;
use std::io;

#[test]
fn tls_error_clone_preserves_variant() {
    let original = TlsError::Other("test error".to_string());
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn tls_error_io_from_kind_clones() {
    let err = TlsError::from(io::Error::from(io::ErrorKind::ConnectionRefused));
    let cloned = err.clone();
    assert_eq!(err, cloned);
}

#[test]
fn tls_error_partial_eq_same_variant() {
    let e1 = TlsError::Other("same".into());
    let e2 = TlsError::Other("same".into());
    assert_eq!(e1, e2);
}

#[test]
fn tls_error_partial_eq_different_message() {
    let e1 = TlsError::Other("a".into());
    let e2 = TlsError::Other("b".into());
    assert_ne!(e1, e2);
}

#[test]
fn tls_error_partial_eq_different_variants() {
    let e_other = TlsError::Other("msg".into());
    let e_handshake = TlsError::Handshake("msg".into());
    assert_ne!(e_other, e_handshake);
}

#[test]
fn tls_error_io_variant_partial_eq() {
    let e1 = TlsError::Io(io::ErrorKind::ConnectionRefused);
    let e2 = TlsError::Io(io::ErrorKind::ConnectionRefused);
    assert_eq!(e1, e2);

    let e3 = TlsError::Io(io::ErrorKind::BrokenPipe);
    assert_ne!(e1, e3);
}

#[test]
fn tls_error_clone_all_variants() {
    use oxitls_core::AlertDescription;
    let variants: Vec<TlsError> = vec![
        TlsError::Io(io::ErrorKind::Other),
        TlsError::Handshake("hs".into()),
        TlsError::BadCert("bc".into()),
        TlsError::InvalidConfig("ic".into()),
        TlsError::CertRevoked("cr".into()),
        TlsError::CertInvalid("ci".into()),
        TlsError::ProtocolViolation("pv".into()),
        TlsError::AlertReceived(AlertDescription::HandshakeFailure),
        TlsError::Other("ot".into()),
    ];
    for v in &variants {
        let cloned = v.clone();
        assert_eq!(v, &cloned);
    }
}

// Compile-time test: TlsConnector is object-safe
#[allow(dead_code)]
fn _connector_is_object_safe(_: &dyn oxitls_core::TlsConnector) {}

// Compile-time test: TlsAcceptor is object-safe
#[allow(dead_code)]
fn _acceptor_is_object_safe(_: &dyn oxitls_core::TlsAcceptor) {}
