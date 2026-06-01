//! Integration tests for `oxitls-rcgen`: self-signed certificate generation
//! and a live TLS handshake validation.
//!
//! These tests prove:
//!  1. Ed25519 self-signed cert round-trips through rcgen without ring.
//!  2. ECDSA-P256 self-signed cert round-trips through rcgen without ring.
//!  3. The DER output is accepted by rustls + oxitls-adapter-rustls-rustcrypto
//!     in a full TLS 1.3 handshake (server + client on loopback).

use std::sync::Arc;

use oxitls_rcgen::{generate_self_signed_ed25519, generate_self_signed_p256};
use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

// ── Helper: build a rustls ServerConfig from a CertifiedKey ──────────────────

fn server_config_from_certified(
    cert_der: Vec<u8>,
    pkcs8_der: Vec<u8>,
) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    let cert_chain = vec![CertificateDer::from(cert_der)];
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8_der));

    let provider = oxitls_adapter_rustls_rustcrypto::pure_provider();
    let server_cfg = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("version config")
        .with_no_client_auth()
        .with_single_cert(cert_chain, key_der)?;
    Ok(server_cfg)
}

// ── Helper: TLS loopback handshake ────────────────────────────────────────────

/// Spawn a TLS server on an ephemeral loopback port, connect a client that
/// trusts *only* the supplied `cert_der`, perform a handshake, assert the
/// negotiated protocol is TLS 1.3, and return.
async fn loopback_handshake(
    cert_der: Vec<u8>,
    pkcs8_der: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    let server_cfg = server_config_from_certified(cert_der.clone(), pkcs8_der)?;
    let acceptor = TlsAcceptor::from(Arc::new(server_cfg));

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    // Server task: accept one connection then drop.
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let tls = acceptor.accept(stream).await.expect("tls accept");
        // Write a small response so the client read completes.
        use tokio::io::AsyncWriteExt;
        let (_, mut write) = tokio::io::split(tls);
        write.write_all(b"OK").await.expect("write");
    });

    // Client: trust only the self-signed cert we just generated.
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(CertificateDer::from(cert_der))?;

    let provider = oxitls_adapter_rustls_rustcrypto::pure_provider();
    let client_cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("version config")
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(client_cfg));
    let domain = rustls_pki_types::ServerName::try_from("localhost")
        .map_err(|e| format!("invalid server name: {e}"))?
        .to_owned();

    let stream = TcpStream::connect(addr).await?;
    let mut tls = connector.connect(domain, stream).await?;

    // Read the "OK" the server sends so the connection closes gracefully.
    let mut buf = [0u8; 2];
    {
        use tokio::io::AsyncReadExt;
        tls.read_exact(&mut buf).await?;
    }
    assert_eq!(&buf, b"OK");

    // Assert TLS 1.3 was negotiated.
    let (_, conn) = tls.into_inner();
    assert_eq!(
        conn.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );

    server.await?;
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[test]
fn test_ed25519_cert_der_is_non_empty() {
    let ck = generate_self_signed_ed25519(&["localhost"]).expect("ed25519 cert gen");
    assert!(!ck.cert_der.is_empty(), "cert DER must be non-empty");
    assert!(!ck.pkcs8_der.is_empty(), "pkcs8 DER must be non-empty");
    // Minimal sanity: DER certs start with SEQUENCE (0x30)
    assert_eq!(ck.cert_der[0], 0x30);
}

#[test]
fn test_p256_cert_der_is_non_empty() {
    let ck = generate_self_signed_p256(&["localhost"]).expect("p256 cert gen");
    assert!(!ck.cert_der.is_empty(), "cert DER must be non-empty");
    assert!(!ck.pkcs8_der.is_empty(), "pkcs8 DER must be non-empty");
    assert_eq!(ck.cert_der[0], 0x30);
}

#[test]
fn test_ed25519_cert_multiple_sans() {
    let ck = generate_self_signed_ed25519(&["localhost", "example.com"])
        .expect("ed25519 multi-san cert gen");
    assert!(!ck.cert_der.is_empty());
}

#[test]
fn test_p256_cert_multiple_sans() {
    let ck =
        generate_self_signed_p256(&["localhost", "127.0.0.1"]).expect("p256 multi-san cert gen");
    assert!(!ck.cert_der.is_empty());
}

#[test]
fn test_empty_sans_returns_error() {
    let result = generate_self_signed_ed25519(&[]);
    assert!(result.is_err(), "empty SANs must return an error");
}

#[tokio::test]
async fn test_ed25519_loopback_handshake() {
    let ck = generate_self_signed_ed25519(&["localhost"]).expect("ed25519 cert gen");
    loopback_handshake(ck.cert_der, ck.pkcs8_der)
        .await
        .expect("ed25519 loopback handshake");
}

#[tokio::test]
async fn test_p256_loopback_handshake() {
    let ck = generate_self_signed_p256(&["localhost"]).expect("p256 cert gen");
    loopback_handshake(ck.cert_der, ck.pkcs8_der)
        .await
        .expect("p256 loopback handshake");
}
