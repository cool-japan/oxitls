//! Integration tests for oxitls M2: TLS 1.3 server + mTLS + ALPN + SNI.
//!
//! All TLS certificates are generated inline via rcgen (no files on disk).
//! All tests run over a loopback TCP socket on a random free port.

use std::sync::Arc;

use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

use oxitls::tls13::ServerBuilder;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a `RootCertStore` trusting the single given DER cert.
fn root_store_for(cert_der: &CertificateDer<'static>) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots
        .add(cert_der.clone())
        .expect("failed to add root cert");
    roots
}

/// Build a pure-Rust TLS 1.3 `ClientConfig` trusting the given root store.
fn client_cfg(roots: RootCertStore) -> Arc<ClientConfig> {
    let provider = oxitls_adapter_rustls_rustcrypto::pure_provider();
    Arc::new(
        ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3 not supported by provider")
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// Build a pure-Rust TLS 1.3 `ClientConfig` that also presents a client cert.
fn client_cfg_with_cert(
    roots: RootCertStore,
    client_certs: Vec<CertificateDer<'static>>,
    client_key: PrivateKeyDer<'static>,
) -> Arc<ClientConfig> {
    let provider = oxitls_adapter_rustls_rustcrypto::pure_provider();
    Arc::new(
        ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3 not supported by provider")
            .with_root_certificates(roots)
            .with_client_auth_cert(client_certs, client_key)
            .expect("client auth cert invalid"),
    )
}

// ---------------------------------------------------------------------------
// Test 1: basic server-client TLS 1.3 handshake + echo
// ---------------------------------------------------------------------------

#[tokio::test]
async fn server_client_handshake() {
    let server_kp = KeyPair::generate().unwrap();
    let server_cert = CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&server_kp)
        .unwrap();
    let cert_der = CertificateDer::from(server_cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(server_kp.serialize_der().into());
    let root_cert = cert_der.clone();

    let server_cfg = ServerBuilder::new()
        .with_der_cert_and_key(vec![cert_der], key_der)
        .build()
        .expect("server config build failed");
    let acceptor = oxitls::tls13::server::tokio_acceptor(server_cfg);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(tcp).await.expect("server accept failed");
        let mut buf = [0u8; 1];
        tls.read_exact(&mut buf).await.unwrap();
        tls.write_all(&buf).await.unwrap();
        tls.flush().await.unwrap();
    });

    let connector = TlsConnector::from(client_cfg(root_store_for(&root_cert)));
    let tcp = TcpStream::connect(addr).await.unwrap();
    let server_name = ServerName::try_from("localhost").unwrap();
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .expect("client connect failed");

    tls.write_all(&[0x42]).await.unwrap();
    tls.flush().await.unwrap();
    let mut reply = [0u8; 1];
    tls.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[0], 0x42);

    server_task.await.unwrap();
}

// ---------------------------------------------------------------------------
// Test 2: mTLS — client must present a cert signed by the server-trusted CA
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mtls_handshake() {
    // CA: self-signed CA certificate.
    let ca_kp = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(vec!["ca.test".into()]).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_kp).unwrap();
    let ca_cert_der = CertificateDer::from(ca_cert.der().to_vec());

    // CA issuer handle for signing the client cert.
    let ca_issuer = rcgen::Issuer::from_params(&ca_params, &ca_kp);

    // Server cert: self-signed (independent of CA).
    let server_kp = KeyPair::generate().unwrap();
    let server_cert = CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&server_kp)
        .unwrap();
    let server_cert_der = CertificateDer::from(server_cert.der().to_vec());
    let server_key_der = PrivateKeyDer::Pkcs8(server_kp.serialize_der().into());

    // Client leaf cert signed by the CA.
    let client_kp = KeyPair::generate().unwrap();
    let client_params = CertificateParams::new(vec!["client.test".into()]).unwrap();
    let client_cert = client_params.signed_by(&client_kp, &ca_issuer).unwrap();
    let client_cert_der = CertificateDer::from(client_cert.der().to_vec());
    let client_key_der = PrivateKeyDer::Pkcs8(client_kp.serialize_der().into());

    // Server requires client certs verified against CA roots.
    let mut ca_roots = RootCertStore::empty();
    ca_roots.add(ca_cert_der).expect("add CA root");

    let server_cfg = ServerBuilder::new()
        .with_der_cert_and_key(vec![server_cert_der.clone()], server_key_der)
        .with_client_cert_verifier(ca_roots)
        .build()
        .expect("mTLS server config failed");
    let acceptor = oxitls::tls13::server::tokio_acceptor(server_cfg);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = acceptor
            .accept(tcp)
            .await
            .expect("mTLS server accept failed");
        let mut buf = [0u8; 1];
        tls.read_exact(&mut buf).await.unwrap();
        tls.write_all(&buf).await.unwrap();
        tls.flush().await.unwrap();
    });

    let connector = TlsConnector::from(client_cfg_with_cert(
        root_store_for(&server_cert_der),
        vec![client_cert_der],
        client_key_der,
    ));
    let tcp = TcpStream::connect(addr).await.unwrap();
    let server_name = ServerName::try_from("localhost").unwrap();
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .expect("mTLS client connect failed");

    tls.write_all(&[0xAB]).await.unwrap();
    tls.flush().await.unwrap();
    let mut reply = [0u8; 1];
    tls.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[0], 0xAB);

    server_task.await.unwrap();
}

// ---------------------------------------------------------------------------
// Test 3: ALPN negotiation — server announces h2 + http/1.1; client picks h2
// ---------------------------------------------------------------------------

#[tokio::test]
async fn alpn_negotiation() {
    let server_kp = KeyPair::generate().unwrap();
    let server_cert = CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&server_kp)
        .unwrap();
    let cert_der = CertificateDer::from(server_cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(server_kp.serialize_der().into());
    let root_cert = cert_der.clone();

    let server_cfg = ServerBuilder::new()
        .with_der_cert_and_key(vec![cert_der], key_der)
        .with_alpn_protocols(["h2", "http/1.1"])
        .build()
        .expect("ALPN server config failed");
    let acceptor = oxitls::tls13::server::tokio_acceptor(server_cfg);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let tls = acceptor
            .accept(tcp)
            .await
            .expect("ALPN server accept failed");
        let negotiated = tls.get_ref().1.alpn_protocol().map(|p| p.to_vec());
        assert_eq!(negotiated, Some(b"h2".to_vec()));
    });

    // Build client config with ALPN preference for h2.
    let provider = oxitls_adapter_rustls_rustcrypto::pure_provider();
    let mut client_cfg = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 not supported by provider")
        .with_root_certificates(root_store_for(&root_cert))
        .with_no_client_auth();
    client_cfg.alpn_protocols = vec![b"h2".to_vec()];

    let connector = TlsConnector::from(Arc::new(client_cfg));
    let tcp = TcpStream::connect(addr).await.unwrap();
    let server_name = ServerName::try_from("localhost").unwrap();
    let tls = connector
        .connect(server_name, tcp)
        .await
        .expect("ALPN client connect failed");

    let negotiated = tls.get_ref().1.alpn_protocol().map(|p| p.to_vec());
    assert_eq!(negotiated, Some(b"h2".to_vec()));

    server_task.await.unwrap();
}

// ---------------------------------------------------------------------------
// Test 4: SNI dispatch — server has two certs (a.test, b.test); verify by
//   comparing DER bytes of the received cert against the expected one.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sni_dispatch() {
    use rustls::sign::CertifiedKey as RustlsCertifiedKey;

    let provider = oxitls_adapter_rustls_rustcrypto::pure_provider();

    // Generate two self-signed certs, each SANed to their own name.
    let kp_a = KeyPair::generate().unwrap();
    let cert_a = CertificateParams::new(vec!["a.test".into()])
        .unwrap()
        .self_signed(&kp_a)
        .unwrap();
    let cert_a_der = CertificateDer::from(cert_a.der().to_vec());
    let key_a_der = PrivateKeyDer::Pkcs8(kp_a.serialize_der().into());
    let expected_a_der = cert_a_der.clone();

    let kp_b = KeyPair::generate().unwrap();
    let cert_b = CertificateParams::new(vec!["b.test".into()])
        .unwrap()
        .self_signed(&kp_b)
        .unwrap();
    let cert_b_der = CertificateDer::from(cert_b.der().to_vec());
    let key_b_der = PrivateKeyDer::Pkcs8(kp_b.serialize_der().into());

    // Build rustls CertifiedKeys for the SNI resolver.
    let rustls_ck_a = RustlsCertifiedKey::from_der(vec![cert_a_der.clone()], key_a_der, &provider)
        .expect("CertifiedKey a failed");
    let rustls_ck_b = RustlsCertifiedKey::from_der(vec![cert_b_der], key_b_der, &provider)
        .expect("CertifiedKey b failed");

    let server_cfg = ServerBuilder::new()
        .with_sni_cert("a.test", rustls_ck_a)
        .with_sni_cert("b.test", rustls_ck_b)
        .build()
        .expect("SNI server config failed");
    let acceptor = oxitls::tls13::server::tokio_acceptor(server_cfg);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Server just accepts and drops the connection.
    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let _tls = acceptor
            .accept(tcp)
            .await
            .expect("SNI server accept failed");
    });

    // Client connects with SNI = "a.test", trusting expected_a_der.
    let connector = TlsConnector::from(client_cfg(root_store_for(&expected_a_der)));
    let tcp = TcpStream::connect(addr).await.unwrap();
    let server_name = ServerName::try_from("a.test").unwrap();
    let tls = connector
        .connect(server_name, tcp)
        .await
        .expect("SNI client connect failed");

    // The server must have sent the cert for a.test.
    let peer_certs = tls
        .get_ref()
        .1
        .peer_certificates()
        .expect("no peer certificates");
    assert_eq!(
        peer_certs[0].as_ref(),
        expected_a_der.as_ref(),
        "SNI dispatch: expected a.test cert but got different DER"
    );
    drop(tls);

    server_task.await.unwrap();
}
