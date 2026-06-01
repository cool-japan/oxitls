//! Wave 6 facade tests: post-quantum provider wiring and RFC 7250 raw public key support.
//!
//! ## Compile-time gating
//!
//! - `pq_handshake_via_facade`: gated behind `#[cfg(feature = "post-quantum")]` — requires
//!   `oxitls_adapter_rustls_rustcrypto::pure_provider_with_pq()` from the PQ slice.
//!
//! - `facade_server_raw_public_key_pinned`, `facade_server_rpk_wrong_spki_rejected`,
//!   `facade_mtls_rpk_server_plus_x509_client`: gated behind `#[cfg(feature = "pure")]`
//!   but also require `oxitls_adapter_rustls_rustcrypto::verifier::raw_public_key::*`
//!   from the RPK slice.  These tests compile once the RPK slice lands.
//!   NOTE: until the RPK slice lands, compilation of this file under `pure` feature will
//!   fail on the missing `raw_public_key` module — that is expected and tracked by
//!   verification pass #30.
//!
//! All tests run over a loopback TCP socket on a random free port.
//! Certificates are generated inline via rcgen (no files on disk).

#![allow(unused_imports)]

use std::sync::Arc;

use rcgen::{CertificateParams, KeyPair, PublicKeyData as _};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

use oxitls::tls13::{ClientBuilder, ServerBuilder};

// ── Shared helper ─────────────────────────────────────────────────────────────

/// Generate a self-signed certificate (using rcgen defaults) with SAN `localhost`.
/// Returns `(cert_der, key_der)`.
#[cfg(feature = "post-quantum")]
fn make_self_signed() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let kp = KeyPair::generate().expect("keygen failed");
    let cert = CertificateParams::new(vec!["localhost".to_string()])
        .expect("cert params")
        .self_signed(&kp)
        .expect("self-sign failed");
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(kp.serialize_der().into());
    (cert_der, key_der)
}

// ── Post-quantum handshake via facade ─────────────────────────────────────────

/// When `post-quantum` feature is active, `ClientBuilder::build()` and
/// `ServerBuilder::build()` automatically wire `pure_provider_with_pq()` as
/// the crypto provider.  The TLS 1.3 handshake must complete without error.
///
/// Compilation requires: `oxitls_adapter_rustls_rustcrypto::pure_provider_with_pq()`
/// (supplied by the PQ slice).
#[cfg(feature = "post-quantum")]
#[tokio::test]
async fn pq_handshake_via_facade() {
    let (cert_der, key_der) = make_self_signed();
    let root_cert = cert_der.clone();

    let server_cfg = ServerBuilder::new()
        .with_der_cert_and_key(vec![cert_der], key_der)
        .build()
        .expect("server config build failed");

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));

    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept");
        let mut tls = acceptor.accept(tcp).await.expect("tls accept");
        let mut buf = [0u8; 1];
        tls.read_exact(&mut buf).await.expect("read");
        tls.write_all(&buf).await.expect("write");
        tls.flush().await.expect("flush");
    });

    // ClientBuilder will use pure_provider_with_pq() automatically.
    let client_cfg = ClientBuilder::new()
        .with_trusted_cert_der(root_cert.to_vec())
        .expect("trusted cert")
        .build()
        .expect("client config build failed");

    let connector = TlsConnector::from(Arc::new(client_cfg));
    let tcp = TcpStream::connect(addr).await.expect("tcp connect");
    let sni = ServerName::try_from("localhost").expect("sni");
    let mut tls = connector.connect(sni, tcp).await.expect("tls connect");

    tls.write_all(&[0xAB]).await.expect("client write");
    let mut echo = [0u8; 1];
    tls.read_exact(&mut echo).await.expect("client read");
    assert_eq!(echo[0], 0xAB, "echo mismatch — PQ handshake echo failed");

    server_task.await.expect("server task");
}

// ── RPK: server presents raw public key, client pins expected SPKI ─────────────

/// Server presents a raw public key (RFC 7250); client pins the correct SPKI.
/// The handshake must succeed.
///
/// Compilation requires: `oxitls_adapter_rustls_rustcrypto::verifier::raw_public_key`
/// (supplied by the RPK slice — expected to compile once Slice RPK lands).
#[cfg(feature = "pure")]
#[tokio::test]
async fn facade_server_raw_public_key_pinned() {
    use oxitls_adapter_rustls_rustcrypto::verifier::raw_public_key::server_raw_public_key_resolver;
    use oxitls_adapter_rustls_rustcrypto::verifier::raw_public_key::RawPublicKeyServerVerifier;

    let provider = oxitls_adapter_rustls_rustcrypto::pure_provider();

    // Build a CertifiedKey for the server (RPK mode: cert chain = [SPKI DER]).
    let kp = KeyPair::generate().expect("server keygen");
    // Extract the SPKI DER from rcgen before consuming the key.
    // In rustls RPK mode CertifiedKey.cert must contain the SPKI DER as its single entry.
    let spki_bytes: Vec<u8> = kp.subject_public_key_info();
    let spki_cert = rustls::pki_types::CertificateDer::from(spki_bytes.clone());
    let server_spki = rustls::pki_types::SubjectPublicKeyInfoDer::from(spki_bytes);

    let key_der = PrivateKeyDer::Pkcs8(kp.serialize_der().into());
    let signing_key = provider
        .key_provider
        .load_private_key(key_der)
        .expect("load server key");
    let certified_key = Arc::new(rustls::sign::CertifiedKey::new(
        vec![spki_cert],
        signing_key,
    ));

    // Server: present RPK.
    let server_cfg = ServerBuilder::new()
        .with_server_raw_public_key(Arc::clone(&certified_key))
        .build()
        .expect("server config build (RPK)");

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));

    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept");
        let mut tls = acceptor.accept(tcp).await.expect("tls accept RPK");
        let mut buf = [0u8; 1];
        tls.read_exact(&mut buf).await.expect("read");
        tls.write_all(&buf).await.expect("write");
        tls.flush().await.expect("flush");
    });

    // Client: pin the server's SPKI.
    let client_cfg = ClientBuilder::new()
        .with_server_raw_public_keys(vec![server_spki])
        .build()
        .expect("client config build (RPK)");

    let connector = TlsConnector::from(Arc::new(client_cfg));
    let tcp = TcpStream::connect(addr).await.expect("tcp connect");
    let sni = ServerName::try_from("localhost").expect("sni");
    let mut tls = connector.connect(sni, tcp).await.expect("RPK handshake");

    tls.write_all(&[0xCC]).await.expect("write");
    let mut echo = [0u8; 1];
    tls.read_exact(&mut echo).await.expect("read");
    assert_eq!(echo[0], 0xCC, "echo mismatch — RPK handshake failed");

    server_task.await.expect("server task");
}

/// Server presents RPK; client pins a **wrong** SPKI — the handshake must be rejected.
///
/// Compilation requires: `oxitls_adapter_rustls_rustcrypto::verifier::raw_public_key`
/// (supplied by the RPK slice — expected to compile once Slice RPK lands).
#[cfg(feature = "pure")]
#[tokio::test]
async fn facade_server_rpk_wrong_spki_rejected() {
    use oxitls_adapter_rustls_rustcrypto::verifier::raw_public_key::server_raw_public_key_resolver;

    let provider = oxitls_adapter_rustls_rustcrypto::pure_provider();

    // Server key.
    let kp = KeyPair::generate().expect("server keygen");
    // RPK mode: cert chain must contain the SPKI DER as its single entry.
    // Extract SPKI from rcgen before consuming the key.
    let server_spki_bytes: Vec<u8> = kp.subject_public_key_info();
    let spki_cert = rustls::pki_types::CertificateDer::from(server_spki_bytes);
    let key_der = PrivateKeyDer::Pkcs8(kp.serialize_der().into());
    let signing_key = provider
        .key_provider
        .load_private_key(key_der)
        .expect("load server key");
    let certified_key = Arc::new(rustls::sign::CertifiedKey::new(
        vec![spki_cert],
        signing_key,
    ));

    // A different key — its SPKI will not match the server.
    let wrong_kp = KeyPair::generate().expect("wrong keygen");
    let wrong_spki =
        rustls::pki_types::SubjectPublicKeyInfoDer::from(wrong_kp.subject_public_key_info());

    let server_cfg = ServerBuilder::new()
        .with_server_raw_public_key(certified_key)
        .build()
        .expect("server config (wrong SPKI test)");

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));

    let _server = tokio::spawn(async move {
        if let Ok((tcp, _)) = listener.accept().await {
            let _ = acceptor.accept(tcp).await;
        }
    });

    let client_cfg = ClientBuilder::new()
        .with_server_raw_public_keys(vec![wrong_spki])
        .build()
        .expect("client config (wrong SPKI)");

    let connector = TlsConnector::from(Arc::new(client_cfg));
    let tcp = TcpStream::connect(addr).await.expect("tcp connect");
    let sni = ServerName::try_from("localhost").expect("sni");
    let result = connector.connect(sni, tcp).await;
    assert!(result.is_err(), "wrong SPKI should cause handshake failure");
}

// ── RPK server + standard X.509 client auth (server-side RPK, client X.509 mTLS) ─

/// Server presents RPK; server also requires standard X.509 client certificate auth.
/// Client presents an X.509 cert and pins the server's raw public key.
///
/// Compilation requires: `oxitls_adapter_rustls_rustcrypto::verifier::raw_public_key`
/// (supplied by the RPK slice — expected to compile once Slice RPK lands).
#[cfg(feature = "pure")]
#[tokio::test]
async fn facade_mtls_rpk_server_plus_x509_client() {
    use oxitls_adapter_rustls_rustcrypto::verifier::raw_public_key::server_raw_public_key_resolver;

    let provider = oxitls_adapter_rustls_rustcrypto::pure_provider();

    // Server raw public key.
    let server_kp = KeyPair::generate().expect("server keygen");
    // RPK mode: cert chain must contain the SPKI DER as its single entry.
    // Extract SPKI from rcgen before consuming the key.
    let server_spki_bytes: Vec<u8> = server_kp.subject_public_key_info();
    let server_spki_cert = rustls::pki_types::CertificateDer::from(server_spki_bytes.clone());
    let server_spki = rustls::pki_types::SubjectPublicKeyInfoDer::from(server_spki_bytes);
    let server_key_der = PrivateKeyDer::Pkcs8(server_kp.serialize_der().into());
    let server_signing = provider
        .key_provider
        .load_private_key(server_key_der)
        .expect("load server key");
    let server_ck = Arc::new(rustls::sign::CertifiedKey::new(
        vec![server_spki_cert],
        server_signing,
    ));

    // Client X.509 cert (self-signed, used as both CA root and leaf for mTLS).
    let client_kp = KeyPair::generate().expect("client keygen");
    let client_cert_params =
        CertificateParams::new(vec!["client.local".to_string()]).expect("client cert params");
    let client_cert = client_cert_params
        .self_signed(&client_kp)
        .expect("client self-sign");
    let client_cert_der = CertificateDer::from(client_cert.der().to_vec());
    let client_key_der = PrivateKeyDer::Pkcs8(client_kp.serialize_der().into());

    // Server: present RPK + require X.509 client cert verified against a root store
    // containing the client's self-signed cert.
    let mut client_roots = rustls::RootCertStore::empty();
    client_roots
        .add(client_cert_der.clone())
        .expect("add client root");

    let server_cfg = ServerBuilder::new()
        .with_server_raw_public_key(server_ck)
        .with_client_cert_verifier(client_roots)
        .build()
        .expect("server config (RPK + mTLS)");

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));

    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept");
        let mut tls = acceptor.accept(tcp).await.expect("tls accept (RPK+mTLS)");
        let mut buf = [0u8; 1];
        tls.read_exact(&mut buf).await.expect("read");
        tls.write_all(&buf).await.expect("write");
        tls.flush().await.expect("flush");
    });

    // Client: pin server SPKI + present X.509 client cert.
    let client_cfg = ClientBuilder::new()
        .with_server_raw_public_keys(vec![server_spki])
        .with_client_cert(vec![client_cert_der], client_key_der)
        .build()
        .expect("client config (RPK + X.509 mTLS)");

    let connector = TlsConnector::from(Arc::new(client_cfg));
    let tcp = TcpStream::connect(addr).await.expect("tcp connect");
    let sni = ServerName::try_from("localhost").expect("sni");
    let mut tls = connector
        .connect(sni, tcp)
        .await
        .expect("RPK+mTLS handshake");

    tls.write_all(&[0xDD]).await.expect("write");
    let mut echo = [0u8; 1];
    tls.read_exact(&mut echo).await.expect("read");
    assert_eq!(echo[0], 0xDD, "echo mismatch — RPK+mTLS handshake failed");

    server_task.await.expect("server task");
}
