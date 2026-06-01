//! Wave 9 — End-to-end HTTPS integration test using the aws-lc-rs TLS provider.
//!
//! Verifies that an `oxihttp` server whose TLS is backed by `aws_lc_server_config`
//! can be reached by a raw `hyper` HTTP/1.1 client whose TLS is backed by
//! `aws_lc_client_config`.  Both sides use the aws-lc-rs `CryptoProvider`
//! exclusively — no ring, no rustcrypto — so this test closes TODO L39.
//!
//! Run with:
//! ```bash
//! cargo nextest run -p oxitls-adapter-aws-lc --features aws-lc wave9
//! ```

#![cfg(feature = "aws-lc")]

#[cfg(test)]
mod wave9 {
    use bytes::Bytes;
    use http_body_util::{BodyExt, Empty};
    use hyper::Request as HyperRequest;
    use hyper_util::rt::TokioIo;
    use oxihttp_server::{response, Router, Server, TlsConfig};
    use oxitls_adapter_aws_lc::{aws_lc_client_config, aws_lc_server_config};
    use oxitls_rcgen::generate_self_signed_ed25519;
    use rustls::RootCertStore;
    use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use std::sync::Arc;
    use tokio::net::TcpStream;
    use tokio_rustls::TlsConnector;

    // ── Test ──────────────────────────────────────────────────────────────────

    /// Prove end-to-end TLS using aws-lc-rs on both the oxihttp server and the
    /// raw hyper client.
    ///
    /// Flow:
    /// 1. Generate a self-signed Ed25519 certificate for `localhost`.
    /// 2. Build an `oxihttp` server whose `TlsConfig` is constructed from a
    ///    `rustls::ServerConfig` built with `aws_lc_server_config`.
    /// 3. Spin up the server in a background task via `serve_with_addr`.
    /// 4. Build a raw hyper HTTP/1.1 client whose TLS is backed by
    ///    `aws_lc_client_config`, trusting the self-signed cert.
    /// 5. Send a `GET /hello` request and assert the response is `200 OK` with
    ///    the expected body.
    #[tokio::test]
    async fn aws_lc_https_loopback_via_oxihttp() {
        // ── 1. Certificate generation ──────────────────────────────────────
        let ck =
            generate_self_signed_ed25519(&["localhost"]).expect("Ed25519 cert generation failed");

        let cert_der = CertificateDer::from(ck.cert_der.clone());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.pkcs8_der.clone()));

        // ── 2. Build the oxihttp server with aws-lc-rs ServerConfig ────────
        let server_rustls_cfg = aws_lc_server_config(vec![cert_der.clone()], key_der, vec![])
            .expect("aws_lc_server_config failed");

        // TlsConfig::new accepts any pre-built rustls::ServerConfig.
        let tls_cfg = TlsConfig::new(server_rustls_cfg);

        // ── 3. Bind and start server in background ─────────────────────────
        let router = Router::new().get("/hello", |_req| async {
            response::text_response("hello from aws-lc-rs")
        });

        let (addr, server_handle) = Server::bind("127.0.0.1:0")
            .with_tls(tls_cfg)
            .serve_with_addr(router)
            .await
            .expect("server bind/start failed");

        // Give the acceptor loop a moment to park on `accept()`.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        // ── 4. Build the aws-lc-rs backed client ──────────────────────────
        let mut roots = RootCertStore::empty();
        roots
            .add(cert_der)
            .expect("add self-signed cert to root store");

        let client_rustls_cfg =
            aws_lc_client_config(roots, vec![]).expect("aws_lc_client_config failed");

        let connector = TlsConnector::from(Arc::new(client_rustls_cfg));

        // ── 5. TLS connect ─────────────────────────────────────────────────
        let tcp = TcpStream::connect(addr)
            .await
            .expect("TCP connect to loopback server failed");

        let server_name = ServerName::try_from("localhost")
            .expect("'localhost' is a valid ServerName")
            .to_owned();

        let tls_stream = connector
            .connect(server_name, tcp)
            .await
            .expect("TLS handshake with aws-lc-rs server failed");

        // Verify the negotiated TLS version is TLS 1.3.
        let proto_ver = tls_stream
            .get_ref()
            .1
            .protocol_version()
            .expect("TLS version should be negotiated after handshake");
        assert_eq!(
            proto_ver,
            rustls::ProtocolVersion::TLSv1_3,
            "expected TLS 1.3, got {proto_ver:?}"
        );

        // ── 6. HTTP/1.1 GET request over TLS ──────────────────────────────
        let io = TokioIo::new(tls_stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .expect("HTTP/1.1 handshake failed");

        // Drive the connection in a background task.
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                // Ignore graceful-close errors that arise when the server
                // shuts down after we call `abort()` below.
                eprintln!("connection error (expected on test teardown): {e}");
            }
        });

        let req = HyperRequest::builder()
            .method("GET")
            .uri(format!("https://localhost:{}/hello", addr.port()))
            .header("Host", format!("localhost:{}", addr.port()))
            .body(Empty::<Bytes>::new())
            .expect("build GET request");

        let resp = sender.send_request(req).await.expect("GET /hello failed");

        // ── 7. Assertions ──────────────────────────────────────────────────
        assert_eq!(
            resp.status(),
            hyper::StatusCode::OK,
            "expected 200 OK from oxihttp+aws-lc-rs server"
        );

        let body_bytes = resp
            .into_body()
            .collect()
            .await
            .expect("collect body")
            .to_bytes();

        assert_eq!(
            body_bytes.as_ref(),
            b"hello from aws-lc-rs",
            "unexpected response body"
        );

        server_handle.abort();
    }
}
