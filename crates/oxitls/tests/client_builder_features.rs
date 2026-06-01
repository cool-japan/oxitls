//! Integration tests for ClientBuilder new features:
//! - with_alpn_protocols
//! - with_danger_accept_invalid_certs
//! - with_client_cert

use std::sync::Arc;

use oxitls::tls13::{ClientBuilder, ServerBuilder};
use oxitls_rcgen::generate_self_signed_ed25519;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

#[tokio::test]
async fn client_builder_alpn_negotiation() {
    let ck = generate_self_signed_ed25519(&["localhost"]).expect("cert gen");

    // Server with h2 + http/1.1 ALPN.
    let server_config = ServerBuilder::new()
        .with_der_cert_and_key(
            vec![CertificateDer::from(ck.cert_der.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.pkcs8_der.clone())),
        )
        .with_alpn_protocols(["h2", "http/1.1"])
        .build()
        .expect("server config");

    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept");
        let tls = acceptor.accept(tcp).await.expect("tls accept");
        let (_, session) = tls.get_ref();
        // Verify the negotiated ALPN is h2 (client's first preference).
        assert_eq!(session.alpn_protocol(), Some(b"h2".as_slice()));

        use tokio::io::AsyncWriteExt;
        let (_, mut w) = tokio::io::split(tls);
        w.write_all(b"OK").await.expect("write");
    });

    // Client prefers h2 via the new with_alpn_protocols method.
    let client_config = ClientBuilder::new()
        .with_trusted_cert_der(ck.cert_der.clone())
        .expect("trusted cert")
        .with_alpn_protocols(["h2"])
        .build()
        .expect("client config");

    let connector = TlsConnector::from(Arc::new(client_config));
    let tcp = TcpStream::connect(addr).await.expect("connect");
    let domain = ServerName::try_from("localhost").expect("name").to_owned();
    let mut tls = connector.connect(domain, tcp).await.expect("tls connect");

    let (_, session) = tls.get_ref();
    assert_eq!(session.alpn_protocol(), Some(b"h2".as_slice()));

    let mut buf = [0u8; 2];
    {
        use tokio::io::AsyncReadExt;
        tls.read_exact(&mut buf).await.expect("read");
    }
    assert_eq!(&buf, b"OK");

    server.await.expect("server task");
}

#[tokio::test]
async fn client_builder_danger_accept_invalid_certs() {
    let ck = generate_self_signed_ed25519(&["localhost"]).expect("cert gen");

    let server_config = ServerBuilder::new()
        .with_der_cert_and_key(
            vec![CertificateDer::from(ck.cert_der.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.pkcs8_der.clone())),
        )
        .build()
        .expect("server config");

    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept");
        let tls = acceptor.accept(tcp).await.expect("tls accept");
        use tokio::io::AsyncWriteExt;
        let (_, mut w) = tokio::io::split(tls);
        w.write_all(b"OK").await.expect("write");
    });

    // Client does NOT trust the self-signed cert in its root store, but uses
    // danger_accept_invalid_certs, so the handshake should succeed.
    let client_config = ClientBuilder::new()
        .with_danger_accept_invalid_certs()
        .build()
        .expect("client config");

    let connector = TlsConnector::from(Arc::new(client_config));
    let tcp = TcpStream::connect(addr).await.expect("connect");
    let domain = ServerName::try_from("localhost").expect("name").to_owned();
    let mut tls = connector.connect(domain, tcp).await.expect("tls connect");

    let mut buf = [0u8; 2];
    {
        use tokio::io::AsyncReadExt;
        tls.read_exact(&mut buf).await.expect("read");
    }
    assert_eq!(&buf, b"OK");

    server.await.expect("server task");
}
