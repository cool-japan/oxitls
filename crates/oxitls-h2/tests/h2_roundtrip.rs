//! Integration test: HTTP/2 client↔server round-trip over a TLS loopback socket.
//!
//! Setup:
//!  1. Generate a self-signed certificate (rcgen) with ALPN extension "h2".
//!  2. Start a server listener on a random loopback port.
//!  3. Server: `h2_server_handshake(tls)` → accept one request → send 200 response.
//!  4. Client: `h2_client_handshake(tls)` → send GET request → assert 200 status.

use std::sync::Arc;

use bytes::Bytes;
use rcgen::{CertificateParams, KeyPair};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use oxitls_h2::{h2_client_handshake, h2_server_handshake};

// ---------------------------------------------------------------------------
// Helper: generate self-signed cert + build TLS configs with ALPN "h2"
// ---------------------------------------------------------------------------

fn build_tls_configs() -> (Arc<ServerConfig>, Arc<ClientConfig>) {
    let kp = KeyPair::generate().expect("keygen");
    let cert = CertificateParams::new(vec!["localhost".into()])
        .expect("cert params")
        .self_signed(&kp)
        .expect("self-sign");

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(kp.serialize_der().into());

    let provider = oxitls_adapter_rustls_rustcrypto::pure_provider();

    // Server config: TLS 1.3, ALPN "h2".
    let mut server_cfg = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .expect("server cert");
    server_cfg.alpn_protocols = vec![b"h2".to_vec()];

    // Client config: TLS 1.3, ALPN "h2", trusts the self-signed cert.
    let mut root_store = RootCertStore::empty();
    root_store.add(cert_der).expect("root cert");
    let mut client_cfg = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .with_root_certificates(root_store)
        .with_no_client_auth();
    client_cfg.alpn_protocols = vec![b"h2".to_vec()];

    (Arc::new(server_cfg), Arc::new(client_cfg))
}

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn h2_roundtrip() {
    let (server_cfg, client_cfg) = build_tls_configs();

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local addr");

    let acceptor = TlsAcceptor::from(server_cfg);

    // Server task: accept one HTTP/2 request, respond 200 + "hello".
    // The server task drives the h2 connection to completion so the client
    // receives all data before the TLS stream is dropped.
    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("tcp accept");
        let tls = acceptor.accept(tcp).await.expect("tls accept");

        let mut h2_conn = h2_server_handshake(tls).await.expect("h2 server handshake");

        // Accept one request.
        let (req, mut respond) = h2_conn
            .accept()
            .await
            .expect("no request received")
            .expect("request error");

        // Drain the request body (empty for GET).
        drop(req);

        // Send 200 response with a body.
        let response = http::Response::builder()
            .status(200)
            .body(())
            .expect("response build");
        let mut send = respond
            .send_response(response, false)
            .expect("send response");
        send.send_data(Bytes::from_static(b"hello"), true)
            .expect("send data");
        // Release the send handle so the stream is fully flushed.
        drop(send);

        // Signal graceful shutdown and drive remaining frames until EOF.
        h2_conn.graceful_shutdown();
        loop {
            match h2_conn.accept().await {
                // No more streams — connection is done.
                None => break,
                // New streams on a gracefully-closing server — send REFUSED.
                Some(Ok((_req, mut respond))) => {
                    respond.send_reset(h2::Reason::REFUSED_STREAM);
                }
                // Connection-level error (e.g. client closed) — stop.
                Some(Err(_)) => break,
            }
        }
    });

    // Client task: connect, send GET /, expect 200 + "hello".
    let connector = TlsConnector::from(client_cfg);
    let tcp = TcpStream::connect(addr).await.expect("tcp connect");
    let server_name = ServerName::try_from("localhost").expect("server name");
    let tls = connector
        .connect(server_name, tcp)
        .await
        .expect("tls connect");

    let (mut send_req, conn) = h2_client_handshake(tls).await.expect("h2 client handshake");

    // Drive the connection in the background.
    // h2 over TLS: the server may close the TCP connection without a TLS
    // close_notify once all streams are done.  That manifests as an `Io(UnexpectedEof)`
    // error on the client connection driver, which is acceptable at end-of-streams.
    let conn_task = tokio::spawn(async move {
        let _ = conn.await; // ignore graceful-close EOF
    });

    // Send a GET request.
    let request = http::Request::builder()
        .method(http::Method::GET)
        .uri("https://localhost/")
        .body(())
        .expect("request build");

    let (response_fut, _) = send_req.send_request(request, true).expect("send request");
    let response = response_fut.await.expect("response error");

    assert_eq!(response.status(), http::StatusCode::OK);

    // Receive the body.
    let mut body = response.into_body();
    let mut received = Bytes::new();
    while let Some(chunk) = body.data().await {
        received = chunk.expect("body chunk error");
    }
    assert_eq!(received.as_ref(), b"hello");

    server_task.await.expect("server task panicked");
    conn_task.await.expect("conn task panicked");
}
