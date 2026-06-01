//! Integration test: TLS handshake with a rustcrypto client and an aws-lc-rs server.
//!
//! Marked `#[ignore]` because it requires the `aws-lc` feature to be enabled
//! (which triggers a C/aws-lc-sys build) and is therefore intentionally
//! excluded from the default `cargo test` run.  Enable with:
//!
//! ```bash
//! cargo nextest run -p oxitls-adapter-aws-lc --features aws-lc -E 'test(handshake)'
//! ```

#[cfg(feature = "aws-lc")]
mod aws_lc_handshake {
    use oxitls_adapter_aws_lc::aws_lc_provider;
    use oxitls_adapter_rustls_rustcrypto::pure_provider;
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use rustls::{ClientConfig, RootCertStore, ServerConfig};
    use rustls_pki_types::{PrivatePkcs8KeyDer, ServerName};
    use std::sync::Arc;
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    /// Full TLS handshake: rustcrypto client ↔ aws-lc-rs server.
    ///
    /// Ignored by default — requires the `aws-lc` feature (C build).
    #[tokio::test]
    #[ignore = "requires aws-lc feature (C build); run with --features aws-lc"]
    async fn rustcrypto_client_aws_lc_server() {
        // Generate a self-signed cert via rcgen (ring stays on dev-deps only).
        let subject = vec!["localhost".to_string()];
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(subject).expect("rcgen cert gen failed");

        let cert_der = cert.der().clone();
        let key_bytes = signing_key.serialize_der();
        let key_der = rustls_pki_types::PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_bytes));

        // Build server config with aws-lc-rs provider.
        let server_provider = aws_lc_provider();
        let srv_cfg = ServerConfig::builder_with_provider(server_provider)
            .with_safe_default_protocol_versions()
            .expect("server protocol versions")
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .expect("server cert/key");
        let acceptor = TlsAcceptor::from(Arc::new(srv_cfg));

        // Build client config with pure rustcrypto provider.
        let client_provider = pure_provider();
        let mut root_store = RootCertStore::empty();
        root_store.add(cert_der).expect("add cert");
        let cli_cfg = ClientConfig::builder_with_provider(client_provider)
            .with_safe_default_protocol_versions()
            .expect("client protocol versions")
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(cli_cfg));

        // Bind on an ephemeral port.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind failed");
        let port = listener.local_addr().expect("local_addr").port();

        // Server task: accept one connection, drain, then exit.
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept tcp");
            let mut tls = acceptor.accept(stream).await.expect("tls accept");
            tokio::io::copy(&mut tls, &mut tokio::io::sink()).await.ok();
        });

        // Client connects and completes the TLS handshake.
        let tcp = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("tcp connect");
        let server_name = ServerName::try_from("localhost")
            .expect("server name parse")
            .to_owned();
        let _tls_stream = connector
            .connect(server_name, tcp)
            .await
            .expect("tls connect");

        server.abort();
    }
}
