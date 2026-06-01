//! Integration tests for the aws-lc FIPS adapter scaffold.
//!
//! All tests are gated on `#[cfg(feature = "aws-lc")]`.
//!
//! Run with:
//! ```bash
//! cargo nextest run -p oxitls-adapter-aws-lc --features aws-lc
//! ```

#[cfg(feature = "aws-lc")]
mod tests {
    use oxitls_adapter_aws_lc::{
        aws_lc_client_config, aws_lc_mtls_client_config, aws_lc_provider,
        aws_lc_provider_tls12_only, aws_lc_provider_with_cipher_suites, aws_lc_server_config,
        is_fips_mode, AwsLcTicketRotator,
    };
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use rustls::RootCertStore;
    use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Generate a self-signed cert + key for `localhost` via rcgen.
    fn make_cert() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".to_string()])
                .expect("rcgen cert gen failed");
        let cert_der = cert.der().clone();
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
        (cert_der, key_der)
    }

    /// Build a `RootCertStore` containing a single trusted cert.
    fn root_store_from(cert: &CertificateDer<'static>) -> RootCertStore {
        let mut store = RootCertStore::empty();
        store.add(cert.clone()).expect("add cert to root store");
        store
    }

    // ── Loopback handshake helper ─────────────────────────────────────────────

    /// Perform a full TLS loopback handshake.
    ///
    /// Returns `(client_negotiated_proto, server_negotiated_proto)` where each
    /// is the ALPN string, or `None` if no ALPN was negotiated.
    async fn do_loopback(
        server_cfg: rustls::ServerConfig,
        client_cfg: rustls::ClientConfig,
        send_msg: &[u8],
    ) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
        let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
        let connector = TlsConnector::from(Arc::new(client_cfg));

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("local_addr").port();

        let send_msg = send_msg.to_vec();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("tcp accept");
            let mut tls = acceptor.accept(stream).await.expect("tls accept");
            let proto = tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
            // Echo back the message.
            let mut buf = vec![0u8; 64];
            let n = tls.read(&mut buf).await.unwrap_or(0);
            tls.write_all(&buf[..n]).await.ok();
            tls.shutdown().await.ok();
            proto
        });

        let tcp = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("tcp connect");
        let server_name = rustls_pki_types::ServerName::try_from("localhost")
            .expect("server name")
            .to_owned();
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .expect("tls connect");
        let client_proto = tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
        tls.write_all(send_msg.as_slice()).await.ok();

        let mut buf = vec![0u8; 64];
        let _read_n = tls.read(&mut buf).await.ok();
        tls.shutdown().await.ok();

        let server_proto = server.await.expect("server task");
        (client_proto, server_proto)
    }

    // ── Test 1: TLS 1.3 loopback ─────────────────────────────────────────────

    #[tokio::test]
    async fn tls13_loopback_handshake() {
        let (cert_der, key_der) = make_cert();
        let roots = root_store_from(&cert_der);

        let server_cfg =
            aws_lc_server_config(vec![cert_der], key_der, vec![]).expect("server config");
        let client_cfg = aws_lc_client_config(roots, vec![]).expect("client config");

        do_loopback(server_cfg, client_cfg, b"hello tls13").await;
    }

    // ── Test 2: TLS 1.2 loopback ─────────────────────────────────────────────

    #[tokio::test]
    async fn tls12_loopback_handshake() {
        let (cert_der, key_der) = make_cert();
        let roots = root_store_from(&cert_der);

        let (provider12, versions12) = aws_lc_provider_tls12_only();

        let server_cfg = rustls::ServerConfig::builder_with_provider(provider12.clone())
            .with_protocol_versions(versions12)
            .expect("server tls12 versions")
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .expect("server cert");

        let client_cfg = rustls::ClientConfig::builder_with_provider(provider12)
            .with_protocol_versions(versions12)
            .expect("client tls12 versions")
            .with_root_certificates(roots)
            .with_no_client_auth();

        do_loopback(server_cfg, client_cfg, b"hello tls12").await;
    }

    // ── Test 3: mTLS loopback ─────────────────────────────────────────────────

    #[tokio::test]
    async fn mtls_loopback_handshake() {
        let (server_cert, server_key) = make_cert();
        let (client_cert, client_key) = make_cert();

        let server_roots = root_store_from(&server_cert);
        let client_roots = root_store_from(&client_cert);

        // Build server that requires client auth.
        let server_provider = aws_lc_provider();
        let client_verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(client_roots),
            server_provider.clone(),
        )
        .build()
        .expect("client verifier");

        let server_cfg = rustls::ServerConfig::builder_with_provider(server_provider)
            .with_safe_default_protocol_versions()
            .expect("server versions")
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(vec![server_cert], server_key)
            .expect("server cert");

        let client_cfg = aws_lc_mtls_client_config(server_roots, vec![client_cert], client_key)
            .expect("mtls client config");

        do_loopback(server_cfg, client_cfg, b"mtls hello").await;
    }

    // ── Test 4: cipher suite restriction ─────────────────────────────────────

    #[tokio::test]
    async fn cipher_suite_restriction_negotiates_allowed() {
        let (cert_der, key_der) = make_cert();
        let roots = root_store_from(&cert_der);

        // Restrict to TLS_AES_256_GCM_SHA384 only.
        let target_suite = rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384;
        let restricted_provider = aws_lc_provider_with_cipher_suites(&[target_suite]);

        let server_cfg = rustls::ServerConfig::builder_with_provider(restricted_provider.clone())
            .with_safe_default_protocol_versions()
            .expect("server versions")
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .expect("server cert");

        let client_cfg = rustls::ClientConfig::builder_with_provider(restricted_provider)
            .with_safe_default_protocol_versions()
            .expect("client versions")
            .with_root_certificates(roots)
            .with_no_client_auth();

        // Just verifying the handshake completes (both ends restricted to same suite).
        do_loopback(server_cfg, client_cfg, b"restricted suite").await;
    }

    // ── Test 5: multi-CA chain validation ────────────────────────────────────

    #[tokio::test]
    async fn multi_ca_chain_validates() {
        // Use a 2-cert chain: self-signed CA signs the leaf.
        use rcgen::{CertificateParams, IsCa, Issuer};

        let mut ca_params =
            CertificateParams::new(vec!["ca.example.com".to_string()]).expect("ca params");
        ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_key = rcgen::KeyPair::generate().expect("ca key");
        let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");

        // Build the Issuer from CA params + key (already self-signed above).
        let issuer = Issuer::from_params(&ca_params, &ca_key);

        let leaf_params =
            CertificateParams::new(vec!["localhost".to_string()]).expect("leaf params");
        let leaf_key = rcgen::KeyPair::generate().expect("leaf key");
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &issuer)
            .expect("leaf cert");

        let ca_der = ca_cert.der().clone();
        let leaf_der = leaf_cert.der().clone();
        let leaf_key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));

        // Root store trusts only the CA, not the leaf directly.
        let mut roots = RootCertStore::empty();
        roots.add(ca_der).expect("add CA");

        let server_cfg = rustls::ServerConfig::builder_with_provider(aws_lc_provider())
            .with_safe_default_protocol_versions()
            .expect("server versions")
            .with_no_client_auth()
            // Present leaf cert only — server sends its own chain.
            .with_single_cert(vec![leaf_der], leaf_key_der)
            .expect("server cert chain");

        let client_cfg = aws_lc_client_config(roots, vec![]).expect("client config");

        do_loopback(server_cfg, client_cfg, b"chain valid").await;
    }

    // ── Test 6: ALPN negotiation ──────────────────────────────────────────────

    #[tokio::test]
    async fn alpn_negotiation_succeeds() {
        let (cert_der, key_der) = make_cert();
        let roots = root_store_from(&cert_der);

        let server_cfg = aws_lc_server_config(
            vec![cert_der],
            key_der,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        )
        .expect("server config");

        let client_cfg = aws_lc_client_config(roots, vec![b"h2".to_vec()]).expect("client config");

        let (client_proto, server_proto) = do_loopback(server_cfg, client_cfg, b"alpn test").await;

        assert_eq!(client_proto.as_deref(), Some(b"h2".as_ref()));
        assert_eq!(server_proto.as_deref(), Some(b"h2".as_ref()));
    }

    // ── Test 7: FIPS mode returns bool ────────────────────────────────────────

    #[test]
    fn is_fips_mode_returns_bool() {
        // Just verify the return type — no assertion on the value since it
        // depends on how aws-lc-rs was compiled.
        let _fips: bool = is_fips_mode();
    }

    // ── Test 8: ticket rotator round-trip ────────────────────────────────────

    #[tokio::test]
    async fn aws_lc_ticket_rotator_roundtrip() {
        use rustls::server::ProducesTickets;

        let rotator = AwsLcTicketRotator::new(Duration::from_secs(3600)).expect("create rotator");

        let plain = b"session-ticket-payload-data";
        let encrypted = rotator.encrypt(plain).expect("encrypt");
        let decrypted = rotator.decrypt(&encrypted).expect("decrypt");

        assert_eq!(decrypted, plain);
    }

    // ── Test 9: rotator accepts previous key after rotation ───────────────────

    #[tokio::test]
    async fn aws_lc_ticket_rotator_accepts_previous_key_after_rotation() {
        use rustls::server::ProducesTickets;

        let interval = Duration::from_millis(60);
        let rotator = AwsLcTicketRotator::new(interval).expect("create rotator");

        let plain = b"pre-rotation-ticket";
        let encrypted = rotator.encrypt(plain).expect("encrypt before rotation");

        // Wait for one rotation (80ms > 60ms interval).
        tokio::time::sleep(Duration::from_millis(80)).await;

        // Ticket encrypted with old key should still decrypt via `previous_key`.
        let decrypted = rotator
            .decrypt(&encrypted)
            .expect("decrypt after one rotation");
        assert_eq!(decrypted, plain);
    }

    // ── Test 10: rotator rejects after two rotations ──────────────────────────

    // Uses tokio mock time so rotation is deterministic regardless of scheduler
    // latency.  `tokio::time::pause()` freezes the clock; `advance()` drives it
    // forward by exactly one interval per call, triggering the background
    // rotation task.
    #[tokio::test(start_paused = true)]
    async fn aws_lc_ticket_rotator_rejects_after_two_rotations() {
        use rustls::server::ProducesTickets;

        let interval = Duration::from_millis(200);
        let rotator = AwsLcTicketRotator::new(interval).expect("create rotator");

        // Yield once so the background task reaches its first `ticker.tick()`
        // (the skipped immediate tick) and parks waiting for the second tick.
        tokio::task::yield_now().await;

        let plain = b"stale-ticket";
        let encrypted = rotator.encrypt(plain).expect("encrypt");

        // First rotation: advance past the interval and yield so the task runs.
        tokio::time::advance(interval + Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        // Verify first rotation occurred.
        assert_eq!(
            rotator.generation(),
            1,
            "expected generation 1 after first rotation"
        );

        // Second rotation: advance again.
        tokio::time::advance(interval + Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(
            rotator.generation(),
            2,
            "expected generation 2 after second rotation"
        );

        // After two rotations the key that encrypted this ticket has been
        // discarded; decryption must fail.
        let result = rotator.decrypt(&encrypted);
        assert!(
            result.is_none(),
            "stale ticket should not decrypt after 2 rotations"
        );
    }

    // ── Test 11: error conversion round-trip ─────────────────────────────────

    #[test]
    fn error_conversion_round_trip() {
        use oxitls_adapter_aws_lc::error::unspecified_to_tls_error;
        use oxitls_core::TlsError;

        // aws_lc_rs::error::Unspecified → TlsError via conversion function.
        let unspec: TlsError = unspecified_to_tls_error(aws_lc_rs::error::Unspecified);
        match &unspec {
            TlsError::Other(msg) => assert!(msg.contains("aws-lc-rs error")),
            other => panic!("expected TlsError::Other, got {other:?}"),
        }
    }
}
