//! Error-path integration tests for the aws-lc-rs TLS adapter.
//!
//! These tests verify that TLS handshakes fail with the expected errors when
//! presented with incorrect hostnames, untrusted certificates, and other
//! common misconfiguration scenarios.
//!
//! Run with:
//! ```bash
//! cargo test -p oxitls-adapter-aws-lc --features aws-lc -E 'test(error_path)'
//! ```

#[cfg(feature = "aws-lc")]
mod error_path_tests {
    use oxitls_adapter_aws_lc::aws_lc_provider;
    use oxitls_adapter_rustls_rustcrypto::pure_provider;
    use oxitls_rcgen::generate_self_signed_ed25519;
    use rustls::{ClientConfig, RootCertStore, ServerConfig};
    use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // ── Loopback helpers ──────────────────────────────────────────────────────

    /// Build a server TLS config (aws-lc provider) for `cert_der` / `key_der`.
    fn aws_lc_server_cfg(
        cert_der: rustls_pki_types::CertificateDer<'static>,
        key_der: PrivateKeyDer<'static>,
    ) -> Arc<ServerConfig> {
        let cfg = ServerConfig::builder_with_provider(aws_lc_provider())
            .with_safe_default_protocol_versions()
            .expect("server protocol versions")
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .expect("server cert/key");
        Arc::new(cfg)
    }

    /// Build a client TLS config (aws-lc provider) trusting `roots`.
    fn aws_lc_client_cfg(roots: RootCertStore) -> Arc<ClientConfig> {
        let cfg = ClientConfig::builder_with_provider(aws_lc_provider())
            .with_safe_default_protocol_versions()
            .expect("client protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        Arc::new(cfg)
    }

    /// Spawn a server task that accepts one TLS connection and echoes data.
    ///
    /// Returns a `DuplexStream` connected to the server side.
    async fn spawn_server(server_cfg: Arc<ServerConfig>) -> tokio::io::DuplexStream {
        let (client_side, server_side) = tokio::io::duplex(65536);

        tokio::spawn(async move {
            let acceptor = tokio_rustls::TlsAcceptor::from(server_cfg);
            match acceptor.accept(server_side).await {
                Ok(mut tls) => {
                    // Drain any incoming bytes and echo them back.
                    let mut buf = vec![0u8; 1024];
                    loop {
                        match tls.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if tls.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                }
                Err(_) => {
                    // Handshake failure — normal for error-path tests.
                }
            }
        });

        client_side
    }

    // ── Test: wrong hostname ──────────────────────────────────────────────────

    /// A client that connects with the wrong SNI hostname should be rejected.
    ///
    /// The certificate is issued for `correct.example.com`; the client
    /// presents `wrong.example.com` as the server name.
    #[tokio::test]
    async fn aws_lc_wrong_hostname_fails() {
        let ck = generate_self_signed_ed25519(&["correct.example.com"]).expect("cert gen");
        let cert_der = rustls_pki_types::CertificateDer::from(ck.cert_der.clone());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.pkcs8_der.clone()));

        let server_cfg = aws_lc_server_cfg(cert_der.clone(), key_der);

        // Trust the server cert in the client's root store.
        let mut roots = RootCertStore::empty();
        roots.add(cert_der).expect("add root");
        let client_cfg = aws_lc_client_cfg(roots);

        let client_stream = spawn_server(server_cfg).await;

        let connector = tokio_rustls::TlsConnector::from(client_cfg);
        // Wrong hostname — the client should reject the certificate.
        let server_name = ServerName::try_from("wrong.example.com")
            .expect("parse sni")
            .to_owned();
        let result = connector.connect(server_name, client_stream).await;

        assert!(
            result.is_err(),
            "expected TLS handshake to fail for wrong hostname, but it succeeded"
        );
    }

    // ── Test: self-signed without trust anchor ────────────────────────────────

    /// A self-signed certificate not present in the root store must be
    /// rejected by the client with an `UnknownIssuer`-equivalent error.
    #[tokio::test]
    async fn aws_lc_self_signed_without_anchor_fails() {
        let ck = generate_self_signed_ed25519(&["untrusted.example.com"]).expect("cert gen");
        let cert_der = rustls_pki_types::CertificateDer::from(ck.cert_der.clone());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.pkcs8_der.clone()));

        let server_cfg = aws_lc_server_cfg(cert_der, key_der);

        // Empty root store — the self-signed cert is NOT trusted.
        let roots = RootCertStore::empty();
        let client_cfg = aws_lc_client_cfg(roots);

        let client_stream = spawn_server(server_cfg).await;

        let connector = tokio_rustls::TlsConnector::from(client_cfg);
        let server_name = ServerName::try_from("untrusted.example.com")
            .expect("parse sni")
            .to_owned();
        let result = connector.connect(server_name, client_stream).await;

        assert!(
            result.is_err(),
            "expected TLS handshake to fail for untrusted self-signed cert"
        );
    }

    // ── Test: cross-provider wrong hostname ───────────────────────────────────

    /// Same as `aws_lc_wrong_hostname_fails` but using a pure-Rust client
    /// (rustcrypto) against an aws-lc server.  Verifies that the failure is
    /// a protocol-level rejection, not an aws-lc-specific quirk.
    #[tokio::test]
    async fn cross_provider_wrong_hostname_fails() {
        let ck = generate_self_signed_ed25519(&["server.example.com"]).expect("cert gen");
        let cert_der = rustls_pki_types::CertificateDer::from(ck.cert_der.clone());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.pkcs8_der.clone()));

        // Server uses aws-lc provider.
        let server_cfg = aws_lc_server_cfg(cert_der.clone(), key_der);

        // Client uses pure-Rust provider.
        let mut roots = RootCertStore::empty();
        roots.add(cert_der).expect("add root");
        let client_cfg = Arc::new(
            ClientConfig::builder_with_provider(pure_provider())
                .with_safe_default_protocol_versions()
                .expect("client protocol versions")
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );

        let client_stream = spawn_server(server_cfg).await;

        let connector = tokio_rustls::TlsConnector::from(client_cfg);
        // Wrong hostname.
        let server_name = ServerName::try_from("different.example.com")
            .expect("parse sni")
            .to_owned();
        let result = connector.connect(server_name, client_stream).await;

        assert!(
            result.is_err(),
            "expected cross-provider TLS handshake to fail for wrong hostname"
        );
    }

    // ── Test: TlsError display is non-empty ───────────────────────────────────

    /// Sanity-check: every `TlsError` variant must produce a non-empty
    /// `Display` string (regression guard for accidental empty fmt impls).
    #[test]
    fn aws_lc_error_display_non_empty() {
        use oxitls_core::TlsError;

        let cases = [
            TlsError::Io(std::io::ErrorKind::BrokenPipe),
            TlsError::Handshake("aws-lc handshake error".to_string()),
            TlsError::BadCert("aws-lc bad cert".to_string()),
            TlsError::InvalidConfig("aws-lc invalid config".to_string()),
            TlsError::CertRevoked("aws-lc cert revoked".to_string()),
            TlsError::Other("aws-lc test error".to_string()),
        ];

        for err in &cases {
            let display = format!("{err}");
            assert!(
                !display.is_empty(),
                "TlsError::{err:?} Display should not be empty"
            );
        }
    }

    // ── Test: expired cert (deferred) ─────────────────────────────────────────
    //
    // NOTE: Testing with an expired certificate is deferred because
    // `oxitls-rcgen` (backed by rcgen 0.14 default features) does not expose
    // a stable API for setting a custom `not_after` timestamp without pulling
    // in the `ring` feature.  This can be enabled once oxitls-rcgen adds
    // `CertificateParamsBuilder::with_not_after(time: OffsetDateTime)`.
}
