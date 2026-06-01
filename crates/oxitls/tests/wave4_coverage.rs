//! Wave 4 coverage tests for Slice E features:
//!   - export_keying_material (both sides match, different labels differ, Ok return)
//!   - StaticOcspResolver propagation (handshake completes)
//!   - with_quic_preview ALPN injection

use std::sync::Arc;

use oxitls::tls13::{ClientBuilder, ServerBuilder};
use oxitls::{OxiTlsStream, StaticOcspResolver};
use oxitls_rcgen::generate_self_signed_ed25519;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

// ── Shared helper ─────────────────────────────────────────────────────────────

/// Build a full handshake pair and return both streams for in-process testing.
async fn handshake_pair() -> (
    OxiTlsStream<tokio::net::TcpStream>,
    OxiTlsStream<tokio::net::TcpStream>,
) {
    let ck = generate_self_signed_ed25519(&["localhost"]).expect("cert gen");

    let server_cfg = ServerBuilder::new()
        .with_der_cert_and_key(
            vec![CertificateDer::from(ck.cert_der.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.pkcs8_der.clone())),
        )
        .build()
        .expect("server config");
    let acceptor = TlsAcceptor::from(Arc::new(server_cfg));

    let client_cfg = ClientBuilder::new()
        .with_trusted_cert_der(ck.cert_der.clone())
        .expect("trusted cert")
        .build()
        .expect("client config");
    let connector = TlsConnector::from(Arc::new(client_cfg));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept");
        acceptor.accept(tcp).await.expect("server accept")
    });

    let client_tcp = TcpStream::connect(addr).await.expect("tcp connect");
    let domain = ServerName::try_from("localhost").expect("name").to_owned();
    let client_stream = connector
        .connect(domain, client_tcp)
        .await
        .expect("tls connect");

    let server_stream = server_task.await.expect("server task");

    (
        OxiTlsStream::from(client_stream),
        OxiTlsStream::from(server_stream),
    )
}

// ── Test 1: both sides export the same 32-byte material ──────────────────────

#[tokio::test]
async fn export_keying_material_both_sides_match() {
    let (client, server) = handshake_pair().await;

    let label = b"EXPORTER-Test";
    let ctx = Some(b"ctx".as_slice());

    let mut client_out = [0u8; 32];
    let mut server_out = [0u8; 32];

    client
        .export_keying_material(&mut client_out, label, ctx)
        .expect("client export");
    server
        .export_keying_material(&mut server_out, label, ctx)
        .expect("server export");

    assert_eq!(
        client_out, server_out,
        "keying material must be identical on both sides"
    );
}

// ── Test 2: different labels produce different material ───────────────────────

#[tokio::test]
async fn export_keying_material_different_labels_differ() {
    let (client, _server) = handshake_pair().await;

    let mut out_a = [0u8; 32];
    let mut out_b = [0u8; 32];

    client
        .export_keying_material(&mut out_a, b"EXPORTER-A", None)
        .expect("export A");
    client
        .export_keying_material(&mut out_b, b"EXPORTER-B", None)
        .expect("export B");

    assert_ne!(
        out_a, out_b,
        "different labels must produce different keying material"
    );
}

// ── Test 3: StaticOcspResolver — handshake completes ─────────────────────────

#[tokio::test]
async fn static_ocsp_resolver_propagates_bytes() {
    let ck = generate_self_signed_ed25519(&["localhost"]).expect("cert gen");

    let ocsp_bytes = vec![1u8, 2, 3, 4, 5];
    let server_cfg = ServerBuilder::new()
        .with_der_cert_and_key(
            vec![CertificateDer::from(ck.cert_der.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.pkcs8_der.clone())),
        )
        .with_ocsp_response_resolver(Arc::new(StaticOcspResolver(ocsp_bytes)))
        .build()
        .expect("server config with OCSP resolver");

    let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept");
        let mut tls = acceptor.accept(tcp).await.expect("server accept");
        // Echo one byte so the client knows the handshake is done.
        let mut buf = [0u8; 1];
        tls.read_exact(&mut buf).await.expect("server read");
        tls.write_all(&buf).await.expect("server write");
    });

    let client_cfg = ClientBuilder::new()
        .with_trusted_cert_der(ck.cert_der.clone())
        .expect("trusted cert")
        .build()
        .expect("client config");
    let connector = TlsConnector::from(Arc::new(client_cfg));

    let tcp = TcpStream::connect(addr).await.expect("connect");
    let domain = ServerName::try_from("localhost").expect("name").to_owned();
    let mut tls = connector.connect(domain, tcp).await.expect("tls connect");

    tls.write_all(&[0xAB]).await.expect("client write");
    let mut buf = [0u8; 1];
    tls.read_exact(&mut buf).await.expect("client read");
    assert_eq!(buf[0], 0xAB, "echo byte mismatch");

    server_task.await.expect("server task");
}

// ── Test 4: with_quic_preview adds h3 to ALPN ─────────────────────────────────

#[test]
#[cfg(feature = "quic-preview")]
fn quic_preview_advertises_h3_alpn() {
    let ck = generate_self_signed_ed25519(&["localhost"]).expect("cert gen");

    let config = ClientBuilder::new()
        .with_trusted_cert_der(ck.cert_der)
        .expect("trusted cert")
        .with_quic_preview(true)
        .build()
        .expect("client config");

    assert!(
        config.alpn_protocols.contains(&b"h3".to_vec()),
        "h3 must be in alpn_protocols when quic_preview=true"
    );
}

// ── Test 5: without with_quic_preview, h3 is absent ──────────────────────────

#[test]
fn quic_preview_disabled_no_h3_alpn() {
    let ck = generate_self_signed_ed25519(&["localhost"]).expect("cert gen");

    let config = ClientBuilder::new()
        .with_trusted_cert_der(ck.cert_der)
        .expect("trusted cert")
        // NOT calling with_quic_preview
        .build()
        .expect("client config");

    assert!(
        !config.alpn_protocols.contains(&b"h3".to_vec()),
        "h3 must NOT be in alpn_protocols when quic_preview is not set"
    );
}

// ── Test 6: export_keying_material returns Ok ─────────────────────────────────

#[tokio::test]
async fn export_keying_material_returns_ok() {
    let (client, _server) = handshake_pair().await;

    let mut out = [0u8; 16];
    let result = client.export_keying_material(&mut out, b"EXPORTER-Minimal", None);
    assert!(
        result.is_ok(),
        "export_keying_material must return Ok after handshake"
    );
}
