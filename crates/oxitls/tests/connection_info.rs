//! Integration tests for TlsConnectionExt and connection info extraction.

use std::sync::Arc;

use oxitls::TlsConnectionExt;
use oxitls_rcgen::generate_self_signed_ed25519;
use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

fn build_configs(
    cert_der: Vec<u8>,
    pkcs8_der: Vec<u8>,
) -> (Arc<ServerConfig>, Arc<rustls::ClientConfig>) {
    let cert_chain = vec![CertificateDer::from(cert_der.clone())];
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8_der));

    let provider = oxitls_adapter_rustls_rustcrypto::pure_provider();

    let mut server_cfg = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("version config")
        .with_no_client_auth()
        .with_single_cert(cert_chain, key_der)
        .expect("server cert");
    server_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let mut root_store = rustls::RootCertStore::empty();
    root_store
        .add(CertificateDer::from(cert_der))
        .expect("root cert");

    let mut client_cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("version config")
        .with_root_certificates(root_store)
        .with_no_client_auth();
    client_cfg.alpn_protocols = vec![b"h2".to_vec()];

    (Arc::new(server_cfg), Arc::new(client_cfg))
}

#[tokio::test]
async fn connection_info_extracts_version_suite_alpn() {
    let ck = generate_self_signed_ed25519(&["localhost"]).expect("cert gen");
    let (server_cfg, client_cfg) = build_configs(ck.cert_der, ck.pkcs8_der);

    let acceptor = TlsAcceptor::from(server_cfg);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept");
        let tls = acceptor.accept(tcp).await.expect("tls accept");

        // Extract server-side connection info.
        let info = tls.tls_connection_info();
        assert_eq!(info.version, Some(oxitls::TlsVersion::Tls13));
        assert!(info.cipher_suite.is_some());
        assert_eq!(info.alpn_protocol_str(), Some("h2"));
        assert_eq!(info.sni.as_deref(), Some("localhost"));

        // Write so client can finish.
        use tokio::io::AsyncWriteExt;
        let (_, mut w) = tokio::io::split(tls);
        w.write_all(b"OK").await.expect("write");
    });

    let connector = TlsConnector::from(client_cfg);
    let tcp = TcpStream::connect(addr).await.expect("connect");
    let domain = ServerName::try_from("localhost").expect("name").to_owned();
    let mut tls = connector.connect(domain, tcp).await.expect("tls connect");

    // Extract client-side connection info.
    let info = tls.tls_connection_info();
    assert_eq!(info.version, Some(oxitls::TlsVersion::Tls13));
    assert!(info.cipher_suite.is_some());
    assert_eq!(info.alpn_protocol_str(), Some("h2"));
    // Client doesn't set SNI on the connection info.
    assert!(info.sni.is_none());
    // Peer certificates should contain the server's cert.
    assert!(!info.peer_certificates.is_empty());

    let mut buf = [0u8; 2];
    {
        use tokio::io::AsyncReadExt;
        tls.read_exact(&mut buf).await.expect("read");
    }
    assert_eq!(&buf, b"OK");

    server.await.expect("server task");
}
