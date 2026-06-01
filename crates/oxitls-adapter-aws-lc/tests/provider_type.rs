//! Integration tests for `AwsLcTlsProvider`, `supported_cipher_suites()`, and
//! `supported_kx_groups()`.

#[cfg(feature = "aws-lc")]
mod tests {
    use oxitls_adapter_aws_lc::{supported_cipher_suites, supported_kx_groups, AwsLcTlsProvider};

    #[test]
    fn supported_cipher_suites_nonempty() {
        let suites = supported_cipher_suites();
        assert!(!suites.is_empty(), "Expected at least one cipher suite");
        assert!(suites.len() >= 2, "Expected multiple cipher suites");
    }

    #[test]
    fn supported_kx_groups_nonempty() {
        let groups = supported_kx_groups();
        assert!(!groups.is_empty(), "Expected at least one KX group");
    }

    #[test]
    fn aws_lc_tls_provider_new_and_debug() {
        let provider = AwsLcTlsProvider::new();
        let debug_str = format!("{provider:?}");
        assert!(
            debug_str.contains("AwsLcTlsProvider"),
            "Debug output should contain type name, got: {debug_str}"
        );
    }

    #[test]
    fn aws_lc_tls_provider_cipher_suites_nonempty() {
        let provider = AwsLcTlsProvider::new();
        let suites = provider.cipher_suites();
        assert!(
            !suites.is_empty(),
            "Provider should expose at least one cipher suite"
        );
    }

    #[test]
    fn aws_lc_tls_provider_kx_groups_nonempty() {
        let provider = AwsLcTlsProvider::new();
        let groups = provider.kx_groups();
        assert!(
            !groups.is_empty(),
            "Provider should expose at least one KX group"
        );
    }

    #[test]
    fn aws_lc_tls_provider_default_equals_new() {
        let a = AwsLcTlsProvider::new();
        let b = AwsLcTlsProvider::default();
        assert_eq!(
            a.cipher_suites(),
            b.cipher_suites(),
            "default() and new() should produce identical cipher suite lists"
        );
    }

    #[test]
    fn rustls_error_to_tls_error_maps_to_other() {
        use oxitls_core::TlsError;
        let err = TlsError::from(rustls::Error::General("test error".into()));
        match err {
            TlsError::Other(msg) => assert!(
                msg.contains("test error"),
                "Expected 'test error' in message, got: {msg}"
            ),
            other => panic!("Expected TlsError::Other variant, got: {other:?}"),
        }
    }

    #[test]
    fn rustls_error_conversion_via_adapter_function() {
        use oxitls_adapter_aws_lc::error::rustls_error_to_tls_error;
        use oxitls_core::TlsError;

        let err = rustls_error_to_tls_error(rustls::Error::General("adapter error".into()));
        match err {
            TlsError::Other(msg) => assert!(msg.contains("adapter error")),
            other => panic!("Expected TlsError::Other, got: {other:?}"),
        }
    }

    #[test]
    fn rustls_error_cert_invalid_converts_correctly() {
        use oxitls_adapter_aws_lc::error::rustls_error_to_tls_error;
        use oxitls_core::TlsError;
        use rustls::CertificateError;

        let err =
            rustls_error_to_tls_error(rustls::Error::InvalidCertificate(CertificateError::Expired));
        match err {
            TlsError::CertInvalid(_) => {}
            other => panic!("Expected TlsError::CertInvalid, got: {other:?}"),
        }
    }
}
