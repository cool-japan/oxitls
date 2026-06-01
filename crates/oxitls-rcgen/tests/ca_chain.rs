//! Integration tests for CA certificate generation, intermediate CA signing,
//! CA-signed leaf certificates, certificate chain building, and auxiliary APIs
//! (fingerprint_sha256, key_pem, to_rustls_certified_key).

use std::sync::Arc;

use oxitls_rcgen::{
    generate_ca, generate_ca_signed_leaf, generate_intermediate_ca, generate_self_signed_ed25519,
    CertChainBuilder, CertificateParamsBuilder, SigningAlgorithm,
};
use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

// ── Helper: loopback handshake with a custom root store ──────────────────────

async fn loopback_handshake_with_chain(
    chain: Vec<Vec<u8>>,
    key_pkcs8: Vec<u8>,
    root_der: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    let cert_chain: Vec<CertificateDer<'static>> =
        chain.into_iter().map(CertificateDer::from).collect();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pkcs8));

    let provider = oxitls_adapter_rustls_rustcrypto::pure_provider();
    let server_cfg = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("version config")
        .with_no_client_auth()
        .with_single_cert(cert_chain, key_der)?;

    let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let tls = acceptor.accept(stream).await.expect("tls accept");
        use tokio::io::AsyncWriteExt;
        let (_, mut write) = tokio::io::split(tls);
        write.write_all(b"OK").await.expect("write");
    });

    // Client trusts only the root CA.
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(CertificateDer::from(root_der))?;

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

    let mut buf = [0u8; 2];
    {
        use tokio::io::AsyncReadExt;
        tls.read_exact(&mut buf).await?;
    }
    assert_eq!(&buf, b"OK");

    server.await?;
    Ok(())
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[test]
fn test_generate_ca_ed25519() {
    let ca = generate_ca("Test Root CA", SigningAlgorithm::Ed25519).expect("CA generation");
    let ck = ca.as_certified_key();
    assert!(!ck.cert_der.is_empty());
    assert!(!ck.pkcs8_der.is_empty());
    assert!(ck.cert_pem.contains("BEGIN CERTIFICATE"));
    assert_eq!(ck.cert_der[0], 0x30); // DER SEQUENCE
}

#[test]
fn test_generate_ca_p256() {
    let ca = generate_ca("Test Root CA", SigningAlgorithm::EcdsaP256).expect("CA generation");
    let ck = ca.as_certified_key();
    assert!(!ck.cert_der.is_empty());
}

#[test]
fn test_generate_intermediate_ca() {
    let root = generate_ca("Root CA", SigningAlgorithm::Ed25519).expect("root CA");
    let intermediate =
        generate_intermediate_ca("Intermediate CA", SigningAlgorithm::Ed25519, &root)
            .expect("intermediate CA");

    let ck = intermediate.as_certified_key();
    assert!(!ck.cert_der.is_empty());
    // Intermediate cert should be different from root.
    assert_ne!(
        ck.cert_der,
        root.as_certified_key().cert_der,
        "intermediate must be a different cert from root"
    );
}

#[test]
fn test_generate_ca_signed_leaf() {
    let root = generate_ca("Root CA", SigningAlgorithm::Ed25519).expect("root CA");
    let leaf = generate_ca_signed_leaf(&["localhost"], SigningAlgorithm::Ed25519, &root)
        .expect("CA-signed leaf");

    assert!(!leaf.cert_der.is_empty());
    assert!(!leaf.pkcs8_der.is_empty());
}

#[test]
fn test_three_level_chain() {
    // Root -> Intermediate -> Leaf
    let root = generate_ca("Root CA", SigningAlgorithm::Ed25519).expect("root CA");
    let intermediate =
        generate_intermediate_ca("Intermediate CA", SigningAlgorithm::Ed25519, &root)
            .expect("intermediate CA");
    let leaf = generate_ca_signed_leaf(&["localhost"], SigningAlgorithm::Ed25519, &intermediate)
        .expect("leaf cert");

    // Build chain.
    let chain = CertChainBuilder::new()
        .with_leaf(leaf.cert_der.clone())
        .with_intermediate(intermediate.as_certified_key().cert_der.clone())
        .with_root(root.as_certified_key().cert_der.clone())
        .build();

    assert_eq!(chain.len(), 3);
    assert_eq!(chain[0], leaf.cert_der);
    assert_eq!(chain[1], intermediate.as_certified_key().cert_der);
    assert_eq!(chain[2], root.as_certified_key().cert_der);
}

#[tokio::test]
async fn test_ca_signed_leaf_loopback_handshake() {
    let root = generate_ca("Test Root CA", SigningAlgorithm::Ed25519).expect("root CA");
    let leaf = generate_ca_signed_leaf(&["localhost"], SigningAlgorithm::Ed25519, &root)
        .expect("CA-signed leaf");

    // Server presents leaf + root chain; client trusts only root.
    let chain = vec![
        leaf.cert_der.clone(),
        root.as_certified_key().cert_der.clone(),
    ];

    loopback_handshake_with_chain(
        chain,
        leaf.pkcs8_der.clone(),
        root.as_certified_key().cert_der.clone(),
    )
    .await
    .expect("CA-signed leaf loopback handshake");
}

#[tokio::test]
async fn test_three_level_chain_loopback_handshake() {
    let root = generate_ca("Root CA", SigningAlgorithm::Ed25519).expect("root CA");
    let intermediate =
        generate_intermediate_ca("Intermediate CA", SigningAlgorithm::Ed25519, &root)
            .expect("intermediate CA");
    let leaf = generate_ca_signed_leaf(&["localhost"], SigningAlgorithm::Ed25519, &intermediate)
        .expect("leaf cert");

    // Chain: leaf + intermediate (root is the trust anchor in the client).
    let chain = vec![
        leaf.cert_der.clone(),
        intermediate.as_certified_key().cert_der.clone(),
    ];

    loopback_handshake_with_chain(
        chain,
        leaf.pkcs8_der.clone(),
        root.as_certified_key().cert_der.clone(),
    )
    .await
    .expect("three-level chain loopback handshake");
}

#[test]
fn test_fingerprint_sha256() {
    let ck = generate_self_signed_ed25519(&["localhost"]).expect("cert gen");
    let fp = ck.fingerprint_sha256();
    // Fingerprint is not all zeros.
    assert_ne!(fp, [0u8; 32]);
    // Same cert produces same fingerprint.
    let fp2 = ck.fingerprint_sha256();
    assert_eq!(fp, fp2);
}

#[test]
fn test_key_pem() {
    let ck = generate_self_signed_ed25519(&["localhost"]).expect("cert gen");
    let pem = ck.key_pem();
    assert!(pem.contains("-----BEGIN PRIVATE KEY-----"));
    assert!(pem.contains("-----END PRIVATE KEY-----"));
}

#[test]
fn test_to_rustls_certified_key() {
    let ck = generate_self_signed_ed25519(&["localhost"]).expect("cert gen");
    let rustls_ck = ck.to_rustls_certified_key().expect("rustls conversion");
    assert!(!rustls_ck.cert.is_empty());
}

#[test]
fn test_cert_chain_builder_empty() {
    let chain = CertChainBuilder::new().build();
    assert!(chain.is_empty());
}

#[test]
fn test_cert_chain_builder_rustls() {
    let ck = generate_self_signed_ed25519(&["localhost"]).expect("cert gen");
    let builder = CertChainBuilder::new().with_leaf(ck.cert_der.clone());
    let rustls_chain = builder.build_rustls();
    assert_eq!(rustls_chain.len(), 1);
}

#[test]
fn test_certificate_params_builder() {
    let params = CertificateParamsBuilder::new()
        .with_common_name("My Server")
        .with_dns_names(&["example.com", "*.example.com"])
        .with_server_auth()
        .with_digital_signature()
        .build()
        .expect("valid params");

    // Verify SANs were set.
    assert_eq!(params.subject_alt_names.len(), 2);
}

#[test]
fn test_certificate_params_builder_ca() {
    let params = CertificateParamsBuilder::new()
        .with_common_name("My CA")
        .with_ca()
        .with_key_cert_sign()
        .with_crl_sign()
        .with_serial_number(42)
        .build()
        .expect("valid CA params");

    assert!(matches!(params.is_ca, rcgen::IsCa::Ca(_)));
}

#[test]
fn test_cross_algorithm_chain() {
    // Root uses P-256, leaf uses Ed25519.
    let root = generate_ca("Root CA", SigningAlgorithm::EcdsaP256).expect("root CA");
    let leaf = generate_ca_signed_leaf(&["localhost"], SigningAlgorithm::Ed25519, &root)
        .expect("cross-alg leaf");

    assert!(!leaf.cert_der.is_empty());
}
