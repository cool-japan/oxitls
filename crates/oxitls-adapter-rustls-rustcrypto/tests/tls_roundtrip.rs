//! Integration test: localhost TLS handshake with an rcgen-issued self-signed cert.

use oxitls_adapter_rustls_rustcrypto::{
    client_config, server_config, RustcryptoAcceptor, RustcryptoConnector,
};
use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::RootCertStore;
use rustls_pki_types::{PrivatePkcs8KeyDer, ServerName};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};

#[tokio::test]
async fn localhost_tls_roundtrip() {
    // Generate a self-signed certificate using rcgen (default features include ring,
    // but ring stays out of normal dependency edges — it is only in dev-deps).
    let subject = vec!["localhost".to_string()];
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(subject).expect("rcgen cert gen failed");

    // Extract certificate DER — cert.der() returns &CertificateDer<'static>
    let cert_der = cert.der().clone();

    // Extract private key DER — KeyPair::serialize_der() returns Vec<u8> (PKCS#8)
    let key_bytes = signing_key.serialize_der();
    let key_der = rustls_pki_types::PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_bytes));

    // Build server config
    let srv_cfg = server_config(vec![cert_der.clone()], key_der).expect("server_config failed");

    // Build client config trusting only our self-signed cert
    let mut root_store = RootCertStore::empty();
    root_store.add(cert_der).expect("add cert failed");
    let cli_cfg = client_config(root_store).expect("client_config failed");

    // Bind on an ephemeral port
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind failed");
    let port = listener.local_addr().expect("local_addr").port();
    let acceptor = RustcryptoAcceptor::new(srv_cfg);

    // Spawn server task
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept tcp failed");
        let mut tls = acceptor.accept(stream).await.expect("tls accept failed");
        tokio::io::copy(&mut tls, &mut tokio::io::sink()).await.ok();
    });

    // Client connects and completes the TLS handshake
    let tcp = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("tcp connect failed");
    let connector = RustcryptoConnector::new(Arc::clone(&cli_cfg));
    let server_name = ServerName::try_from("localhost")
        .expect("server name parse")
        .to_owned();
    let _tls_stream = connector
        .connect(server_name, tcp)
        .await
        .expect("tls connect failed");

    server.abort();
}
