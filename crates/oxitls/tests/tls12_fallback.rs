//! Integration test: TLS 1.2 fallback via `ServerBuilder::with_protocol_versions` and
//! `ClientBuilder::with_tls12_fallback` / `with_protocol_versions`.
//!
//! The test restricts the client to TLS 1.2 only and verifies the negotiated
//! protocol version and that the cipher suite is an AEAD suite.

use std::sync::Arc;

use rcgen::{CertificateParams, KeyPair};
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

use oxitls::tls13::ServerBuilder;

// ---------------------------------------------------------------------------
// Helper: shared cert generation
// ---------------------------------------------------------------------------

fn gen_cert() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let kp = KeyPair::generate().expect("keygen");
    let cert = CertificateParams::new(vec!["localhost".into()])
        .expect("cert params")
        .self_signed(&kp)
        .expect("self-sign");
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(kp.serialize_der().into());
    (cert_der, key_der)
}

fn root_store_for(cert: &CertificateDer<'static>) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.add(cert.clone()).expect("add root");
    roots
}

// ---------------------------------------------------------------------------
// Test 1: Client forced to TLS 1.2 only — server supports both 1.3 and 1.2
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tls12_fallback_negotiation() {
    let (cert_der, key_der) = gen_cert();

    // Server: accept TLS 1.3 and 1.2.
    let server_cfg = ServerBuilder::new()
        .with_der_cert_and_key(vec![cert_der.clone()], key_der)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .build()
        .expect("server config");
    let acceptor = oxitls::tls13::server::tokio_acceptor(server_cfg);

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("tcp accept");
        let mut tls = acceptor.accept(tcp).await.expect("server tls accept");

        // Assert TLS 1.2 was negotiated from the server side.
        let (_, session) = tls.get_ref();
        let version = session.protocol_version().expect("protocol version");
        assert_eq!(
            version,
            rustls::ProtocolVersion::TLSv1_2,
            "server should have negotiated TLS 1.2"
        );

        // Echo one byte.
        let mut buf = [0u8; 1];
        tls.read_exact(&mut buf).await.expect("server read");
        tls.write_all(&buf).await.expect("server write");
        tls.flush().await.expect("server flush");
    });

    // Client: TLS 1.2 only.
    let provider = oxitls_adapter_rustls_rustcrypto::pure_provider();
    let client_cfg = Arc::new(
        ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS12])
            .expect("TLS 1.2")
            .with_root_certificates(root_store_for(&cert_der))
            .with_no_client_auth(),
    );

    let connector = TlsConnector::from(client_cfg);
    let tcp = TcpStream::connect(addr).await.expect("tcp connect");
    let server_name = ServerName::try_from("localhost").expect("server name");
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .expect("client tls connect");

    // Verify TLS 1.2 from the client side.
    let (_, session) = tls.get_ref();
    let version = session.protocol_version().expect("protocol version");
    assert_eq!(
        version,
        rustls::ProtocolVersion::TLSv1_2,
        "client should have negotiated TLS 1.2"
    );

    // Verify the cipher suite is an AEAD suite (has "GCM" or "CHACHA20" in the name).
    let suite_name = format!(
        "{:?}",
        session.negotiated_cipher_suite().expect("cipher suite")
    );
    let is_aead =
        suite_name.contains("GCM") || suite_name.contains("CHACHA20") || suite_name.contains("CCM");
    assert!(is_aead, "expected AEAD cipher suite, got: {suite_name}");

    // Echo test.
    tls.write_all(&[0xAA]).await.expect("client write");
    tls.flush().await.expect("client flush");
    let mut reply = [0u8; 1];
    tls.read_exact(&mut reply).await.expect("client read");
    assert_eq!(reply[0], 0xAA);

    server_task.await.expect("server task");
}

// ---------------------------------------------------------------------------
// Test 2: `ClientBuilder::with_tls12_fallback()` — client offers both 1.3
//         and 1.2; server accepts both; TLS 1.3 should win.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn client_builder_tls12_fallback() {
    let (cert_der, key_der) = gen_cert();

    // Server: TLS 1.3 + 1.2.
    let server_cfg = ServerBuilder::new()
        .with_der_cert_and_key(vec![cert_der.clone()], key_der)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .build()
        .expect("server config");
    let acceptor = oxitls::tls13::server::tokio_acceptor(server_cfg);

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("tcp accept");
        let mut tls = acceptor.accept(tcp).await.expect("server tls accept");

        // With both sides supporting TLS 1.3, the server should pick TLS 1.3.
        let (_, session) = tls.get_ref();
        let version = session.protocol_version().expect("protocol version");
        assert_eq!(
            version,
            rustls::ProtocolVersion::TLSv1_3,
            "TLS 1.3 should be preferred over 1.2"
        );

        let mut buf = [0u8; 1];
        tls.read_exact(&mut buf).await.expect("server read");
        tls.write_all(&buf).await.expect("server write");
        tls.flush().await.expect("server flush");
    });

    // Client: use ClientBuilder::with_tls12_fallback (offers 1.3 + 1.2).
    let client_cfg = Arc::new(
        oxitls::tls13::ClientBuilder::new()
            .with_tls12_fallback()
            .with_trusted_cert_der(cert_der.as_ref().to_vec())
            .expect("trusted cert")
            .build()
            .expect("client config"),
    );

    let connector = TlsConnector::from(client_cfg);
    let tcp = TcpStream::connect(addr).await.expect("tcp connect");
    let server_name = ServerName::try_from("localhost").expect("server name");
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .expect("client connect");

    // TLS 1.3 should be negotiated when both sides support it.
    let (_, session) = tls.get_ref();
    let version = session.protocol_version().expect("protocol version");
    assert_eq!(version, rustls::ProtocolVersion::TLSv1_3);

    tls.write_all(&[0xBB]).await.expect("write");
    tls.flush().await.expect("flush");
    let mut reply = [0u8; 1];
    tls.read_exact(&mut reply).await.expect("read");
    assert_eq!(reply[0], 0xBB);

    server_task.await.expect("server task");
}
