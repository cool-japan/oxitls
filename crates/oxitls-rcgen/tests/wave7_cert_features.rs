//! Wave 7 integration tests: CRL Distribution Points, Authority Information
//! Access (OCSP URL), extended EKU variants (CodeSigning, EmailProtection,
//! OcspSigning), plus loopback handshake smoke-tests for RSA-2048, P-384, and
//! the three-level CA chain.
//!
//! All extension content is verified via `x509-parser` round-trips so that we
//! confirm the DER is not merely *present* but also correctly *parsed*.
//!
//! RSA-2048 loopback tests use a pre-generated key fixture to avoid the cost
//! of pure-Rust RSA key generation, which can take minutes without hardware
//! acceleration.

mod test_fixtures;

use std::sync::Arc;

use oxitls_rcgen::{
    generate_ca, generate_ca_signed_leaf, generate_intermediate_ca, generate_self_signed,
    generate_self_signed_p384, self_signed_from_rsa2048_key, CertChainBuilder,
    CertificateParamsBuilder, OxiEd25519Key, OxiRsa2048Key, SigningAlgorithm,
};
use rcgen::PublicKeyData;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use x509_parser::prelude::*;

// ── Shared loopback helper ───────────────────────────────────────────────────

async fn loopback_handshake(
    cert_chain: Vec<Vec<u8>>,
    pkcs8_der: Vec<u8>,
    trust_anchor_der: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    let chain: Vec<CertificateDer<'static>> =
        cert_chain.into_iter().map(CertificateDer::from).collect();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8_der));

    let provider = oxitls_adapter_rustls_rustcrypto::pure_provider();
    let server_cfg = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(chain, key_der)?;

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

    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(CertificateDer::from(trust_anchor_der))?;

    let client_cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
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
    let (_, conn) = tls.into_inner();
    assert_eq!(
        conn.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3),
        "TLS 1.3 must be negotiated"
    );

    server.await?;
    Ok(())
}

// ── 1. RSA-2048 self-signed TLS 1.3 loopback ─────────────────────────────────

#[tokio::test]
async fn rsa2048_self_signed_tls13_loopback() {
    // Use a pre-generated key fixture to avoid slow pure-Rust RSA-2048 keygen.
    let key = OxiRsa2048Key::from_pkcs8_der(test_fixtures::RSA2048_PKCS8_DER)
        .expect("RSA-2048 fixture parse");
    let ck =
        self_signed_from_rsa2048_key(&["localhost"], key).expect("RSA-2048 cert gen from fixture");
    assert!(!ck.cert_der.is_empty());
    loopback_handshake(
        vec![ck.cert_der.clone()],
        ck.pkcs8_der.clone(),
        ck.cert_der.clone(),
    )
    .await
    .expect("RSA-2048 loopback handshake");
}

// ── 2. ECDSA P-384 self-signed TLS 1.3 loopback ──────────────────────────────

#[tokio::test]
async fn ecdsa_p384_self_signed_loopback() {
    let ck = generate_self_signed_p384(&["localhost"]).expect("P-384 cert gen");
    assert!(!ck.cert_der.is_empty());
    loopback_handshake(
        vec![ck.cert_der.clone()],
        ck.pkcs8_der.clone(),
        ck.cert_der.clone(),
    )
    .await
    .expect("P-384 loopback handshake");
}

// ── 3. 3-level CA chain loopback ──────────────────────────────────────────────

#[tokio::test]
async fn ca_chain_root_intermediate_leaf_validates() {
    let root = generate_ca("Wave7 Root CA", SigningAlgorithm::Ed25519).expect("root CA");
    let inter =
        generate_intermediate_ca("Wave7 Intermediate CA", SigningAlgorithm::EcdsaP256, &root)
            .expect("intermediate CA");
    let leaf = generate_ca_signed_leaf(&["localhost"], SigningAlgorithm::EcdsaP256, &inter)
        .expect("leaf cert");

    let chain = CertChainBuilder::new()
        .with_leaf(leaf.cert_der.clone())
        .with_intermediate(inter.as_certified_key().cert_der.clone())
        .build();

    loopback_handshake(
        chain,
        leaf.pkcs8_der.clone(),
        root.as_certified_key().cert_der.clone(),
    )
    .await
    .expect("3-level CA chain loopback");
}

// ── 4. CSR generate → sign → valid cert ──────────────────────────────────────

#[test]
fn csr_generate_then_sign_produces_valid_cert() {
    use oxitls_rcgen::{generate_csr, sign_csr};

    let ca = generate_ca("CSR Wave7 CA", SigningAlgorithm::EcdsaP256).expect("CA");
    let (csr, _priv_pkcs8) =
        generate_csr("csr-test.wave7.example", SigningAlgorithm::Ed25519).expect("CSR");

    assert!(!csr.der.is_empty(), "CSR DER must be non-empty");
    assert!(
        csr.pem.contains("BEGIN CERTIFICATE REQUEST"),
        "CSR PEM must contain BEGIN CERTIFICATE REQUEST"
    );

    let signed = sign_csr(&csr.der, &ca, 365).expect("sign CSR");
    assert!(!signed.cert_der.is_empty(), "signed cert must be non-empty");
    assert!(
        signed.cert_pem.contains("BEGIN CERTIFICATE"),
        "signed cert PEM must contain BEGIN CERTIFICATE"
    );

    // Verify via x509-parser.
    let (_, leaf) =
        x509_parser::parse_x509_certificate(&signed.cert_der).expect("parse signed cert");
    let (_, ca_cert) = x509_parser::parse_x509_certificate(&ca.as_certified_key().cert_der)
        .expect("parse CA cert");
    assert_eq!(
        leaf.issuer().to_string(),
        ca_cert.subject().to_string(),
        "leaf issuer must match CA subject"
    );
    assert!(
        leaf.subject()
            .to_string()
            .contains("csr-test.wave7.example"),
        "leaf subject must carry CSR CN, got {}",
        leaf.subject()
    );
}

// ── 5. PKCS#12 export is non-trivial ─────────────────────────────────────────

#[test]
fn pkcs12_export_nonempty() {
    let ck = generate_self_signed(&["localhost"], SigningAlgorithm::EcdsaP256).expect("cert");
    let pfx = ck
        .to_pkcs12("wave7pass", "wave7cert")
        .expect("PKCS#12 export");
    assert!(
        pfx.len() > 100,
        "PKCS#12 blob must be > 100 bytes, got {} bytes",
        pfx.len()
    );
    // Structural sanity: PFX starts with DER SEQUENCE (0x30).
    assert_eq!(pfx[0], 0x30, "PFX DER must start with SEQUENCE tag 0x30");
}

// ── 6. fingerprint_sha256 is deterministic and 32 bytes ──────────────────────

#[test]
fn fingerprint_sha256_consistent() {
    let ck = generate_self_signed(&["localhost"], SigningAlgorithm::Ed25519).expect("cert");
    let fp1 = ck.fingerprint_sha256();
    let fp2 = ck.fingerprint_sha256();
    assert_eq!(fp1, fp2, "fingerprint_sha256 must be deterministic");
    assert_eq!(fp1.len(), 32, "SHA-256 fingerprint must be 32 bytes");
    assert_ne!(fp1, [0u8; 32], "fingerprint must not be all-zeros");
}

// ── 7. CRL Distribution Point OID present in parsed cert ─────────────────────

#[test]
fn crl_distribution_point_in_parsed_cert() {
    let crl_uri = "http://example.com/wave7-test.crl";

    let key = OxiEd25519Key::generate().expect("keygen");
    let spki = PublicKeyData::subject_public_key_info(&key);

    let params = CertificateParamsBuilder::new()
        .with_common_name("CRL DP Test")
        .with_ca()
        .with_crl_distribution_point(crl_uri)
        .build_with_spki(&spki)
        .expect("build params");

    let cert = params.self_signed(&key).expect("self-sign");
    let cert_der = cert.der().to_vec();

    let (_, parsed) = X509Certificate::from_der(&cert_der).expect("parse cert DER");

    // OID 2.5.29.31 must appear in the extensions.
    let crl_dp_oid = oid_registry::OID_X509_EXT_CRL_DISTRIBUTION_POINTS;
    let crl_ext = parsed
        .extensions()
        .iter()
        .find(|e| e.oid == crl_dp_oid)
        .expect("CRL Distribution Points extension must be present");

    // Verify the URI string appears in the raw extension value bytes.
    let ext_value_str = std::str::from_utf8(crl_ext.value).unwrap_or("");
    assert!(
        ext_value_str.contains(crl_uri)
            || crl_ext
                .value
                .windows(crl_uri.len())
                .any(|w| w == crl_uri.as_bytes()),
        "CRL DP extension value must contain the URI '{crl_uri}'"
    );
}

// ── 8. AIA OCSP URL round-trips through x509-parser ──────────────────────────

#[test]
fn aia_ocsp_url_in_parsed_cert() {
    let ocsp_url = "http://ocsp.wave7.example.com";

    let key = OxiEd25519Key::generate().expect("keygen");
    let spki = PublicKeyData::subject_public_key_info(&key);

    let params = CertificateParamsBuilder::new()
        .with_common_name("AIA OCSP Test")
        .with_ca()
        .with_ocsp_responder_url(ocsp_url)
        .build_with_spki(&spki)
        .expect("build params");

    let cert = params.self_signed(&key).expect("self-sign");
    let cert_der = cert.der().to_vec();

    let (_, parsed) = X509Certificate::from_der(&cert_der).expect("parse cert DER");

    // Find the AIA extension via ParsedExtension.
    let aia = parsed
        .extensions()
        .iter()
        .find_map(|ext| {
            if let ParsedExtension::AuthorityInfoAccess(aia) = ext.parsed_extension() {
                Some(aia)
            } else {
                None
            }
        })
        .expect("AuthorityInfoAccess extension must be present");

    // Find the OCSP access description and verify the URI.
    let found_url = aia
        .accessdescs
        .iter()
        .find_map(|desc| {
            // access_method OID 1.3.6.1.5.5.7.48.1 is id-ad-ocsp.
            if desc.access_method.to_id_string() == "1.3.6.1.5.5.7.48.1" {
                if let GeneralName::URI(uri) = &desc.access_location {
                    return Some(*uri);
                }
            }
            None
        })
        .expect("id-ad-ocsp entry with URI must be present in AIA");

    assert_eq!(
        found_url, ocsp_url,
        "AIA OCSP URL must round-trip correctly"
    );
}

// ── 9. CodeSigning EKU round-trips through x509-parser ───────────────────────

#[test]
fn code_signing_eku_in_parsed_cert() {
    let key = OxiEd25519Key::generate().expect("keygen");
    let spki = PublicKeyData::subject_public_key_info(&key);

    let params = CertificateParamsBuilder::new()
        .with_common_name("CodeSigning Test")
        .with_ca()
        .with_code_signing()
        .build_with_spki(&spki)
        .expect("build params");

    let cert = params.self_signed(&key).expect("self-sign");
    let cert_der = cert.der().to_vec();

    let (_, parsed) = X509Certificate::from_der(&cert_der).expect("parse cert DER");

    let eku = parsed
        .extended_key_usage()
        .expect("EKU parse ok")
        .expect("EKU extension must be present");

    assert!(
        eku.value.code_signing,
        "code_signing flag must be set in the parsed EKU extension"
    );
}

// ── 10. EmailProtection EKU round-trips through x509-parser ──────────────────

#[test]
fn email_protection_eku_in_parsed_cert() {
    let key = OxiEd25519Key::generate().expect("keygen");
    let spki = PublicKeyData::subject_public_key_info(&key);

    let params = CertificateParamsBuilder::new()
        .with_common_name("EmailProtection Test")
        .with_ca()
        .with_email_protection()
        .build_with_spki(&spki)
        .expect("build params");

    let cert = params.self_signed(&key).expect("self-sign");
    let cert_der = cert.der().to_vec();

    let (_, parsed) = X509Certificate::from_der(&cert_der).expect("parse cert DER");

    let eku = parsed
        .extended_key_usage()
        .expect("EKU parse ok")
        .expect("EKU extension must be present");

    assert!(
        eku.value.email_protection,
        "email_protection flag must be set in the parsed EKU extension"
    );
}

// ── 11. OcspSigning EKU round-trips through x509-parser ──────────────────────

#[test]
fn ocsp_signing_eku_in_parsed_cert() {
    let key = OxiEd25519Key::generate().expect("keygen");
    let spki = PublicKeyData::subject_public_key_info(&key);

    let params = CertificateParamsBuilder::new()
        .with_common_name("OcspSigning Test")
        .with_ca()
        .with_ocsp_signing()
        .build_with_spki(&spki)
        .expect("build params");

    let cert = params.self_signed(&key).expect("self-sign");
    let cert_der = cert.der().to_vec();

    let (_, parsed) = X509Certificate::from_der(&cert_der).expect("parse cert DER");

    let eku = parsed
        .extended_key_usage()
        .expect("EKU parse ok")
        .expect("EKU extension must be present");

    assert!(
        eku.value.ocsp_signing,
        "ocsp_signing flag must be set in the parsed EKU extension"
    );
}
