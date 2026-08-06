//! Mutual TLS (mTLS) example.
//!
//! Demonstrates certificate-based client authentication: a single
//! development CA issues both a server certificate and a client certificate,
//! the server is configured to *require and verify* a client certificate
//! signed by that CA (`with_client_cert_verifier`), and the client presents
//! its certificate (`with_client_cert`). The handshake only succeeds because
//! both sides trust the same CA and both sides authenticate.
//!
//! ```text
//! cargo run --example mtls
//! ```

use std::sync::Arc;

use rustls::RootCertStore;
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

use oxitls::tls13::{ClientBuilder, ServerBuilder};
use oxitls_rcgen::{
    generate_ca, generate_ca_signed_client_cert, generate_ca_signed_leaf, SigningAlgorithm,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ── 1. Stand up a development CA that will sign both certificates ───────
    let ca = generate_ca("oxitls mTLS Example Root CA", SigningAlgorithm::EcdsaP256)?;

    // Server certificate, signed by the CA.
    let server_leaf = generate_ca_signed_leaf(&["localhost"], SigningAlgorithm::EcdsaP256, &ca)?;
    let server_cert_der = server_leaf.cert_der.clone();
    let server_key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_leaf.pkcs8_der));

    // Client certificate, also signed by the CA (a different leaf: the CN
    // conventionally identifies the client, not a DNS/SNI name, but rcgen's
    // `subject_alt_names` param is reused here for simplicity).
    let client_leaf =
        generate_ca_signed_client_cert(&["example-client"], SigningAlgorithm::EcdsaP256, &ca)?;
    let client_cert_der = client_leaf.cert_der.clone();
    let client_key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(client_leaf.pkcs8_der));

    // Both sides trust the same CA (not the leaf certs directly).
    let ca_cert_der = ca.certified_key.cert_der.clone();
    let mut server_trust_roots = RootCertStore::empty();
    server_trust_roots.add(ca_cert_der.clone().into())?;

    // ── 2. Server: require and verify a client certificate ──────────────────
    let server_cfg = ServerBuilder::new()
        .with_der_cert_and_key(vec![server_cert_der.into()], server_key_der)
        .with_client_cert_verifier(server_trust_roots)
        .build()?;
    let acceptor = oxitls::tls13::server::tokio_acceptor(server_cfg);

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept");
        let mut tls = acceptor
            .accept(tcp)
            .await
            .expect("server-side mTLS handshake (client cert required)");
        let mut buf = vec![0u8; 1024];
        let n = tls.read(&mut buf).await.expect("read request");
        let reply = format!(
            "server: hello, authenticated client! you said: {}",
            String::from_utf8_lossy(&buf[..n])
        );
        tls.write_all(reply.as_bytes()).await.expect("write reply");
        tls.flush().await.expect("flush");
        tls.shutdown().await.expect("shutdown");
    });

    // ── 3. Client: trust the CA and present its own certificate ─────────────
    let client_cfg = ClientBuilder::new()
        .with_trusted_cert_der(ca_cert_der)?
        .with_client_cert(vec![client_cert_der.into()], client_key_der)
        .build()?;

    let connector = TlsConnector::from(Arc::new(client_cfg));
    let tcp = TcpStream::connect(addr).await?;
    let server_name = ServerName::try_from("localhost")?;
    let mut tls = connector.connect(server_name, tcp).await?;

    println!("mTLS handshake complete: both server and client authenticated each other.");

    tls.write_all(b"hi from the authenticated client").await?;
    tls.flush().await?;

    let mut response = vec![0u8; 1024];
    let n = tls.read(&mut response).await?;
    println!("{}", String::from_utf8_lossy(&response[..n]));

    Ok(())
}
