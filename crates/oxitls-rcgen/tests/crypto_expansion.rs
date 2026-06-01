//! Integration tests for the Slice B crypto expansion:
//!
//! * RSA-2048 / RSA-4096 / P-384 self-signed loopback handshakes.
//! * CA-signed leaf + intermediate chain validation (additional crypto coverage
//!   to complement the Ed25519/P-256 tests in `ca_chain.rs`).
//! * CSR generation + signing round-trip.
//! * PKCS#12 (PFX) export + decode round-trip.
//! * PEM export format sanity.
//! * Custom validity period round-trips via `not_after()` accessor.
//! * Multi-SAN parsing through x509-parser.
//! * SHA-256 cert fingerprint matches a hand-computed digest.
//!
//! Loopback handshakes use the Pure-Rust `rustls-rustcrypto` provider via
//! `oxitls-adapter-rustls-rustcrypto`. No ring, no aws-lc-rs.
//!
//! RSA-2048 and RSA-4096 tests use pre-generated key fixtures from
//! `test_fixtures.rs` to avoid the cost of pure-Rust RSA key generation.
//! The PKCS#8 DER parse path, cert generation, and TLS handshake are still
//! fully exercised by these tests.

mod test_fixtures;
mod test_fixtures_rsa4096;

use std::sync::Arc;

use oxitls_rcgen::{
    cert::CertifiedKey, csr::CsrBytes, generate_ca, generate_ca_signed_leaf, generate_csr,
    generate_self_signed, generate_self_signed_p384, self_signed_from_rsa2048_key,
    self_signed_from_rsa4096_key, sign_csr, CertChainBuilder, CertificateParamsBuilder,
    OxiRsa2048Key, OxiRsa4096Key, SigningAlgorithm,
};
use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

// ── Shared loopback helper ───────────────────────────────────────────────────

/// Spawn a TLS 1.3 server on an ephemeral loopback port, connect a client
/// that trusts only `trust_anchor_der`, exchange a small "OK" payload, and
/// return.
async fn loopback_handshake(
    cert_chain: Vec<Vec<u8>>,
    pkcs8_der: Vec<u8>,
    trust_anchor_der: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    let chain: Vec<CertificateDer<'static>> =
        cert_chain.into_iter().map(CertificateDer::from).collect();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8_der));

    let provider = oxitls_adapter_rustls_rustcrypto::pure_provider();
    let server_cfg = ServerConfig::builder_with_provider(provider.clone())
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

// ── 1. RSA-2048 self-signed loopback ──────────────────────────────────────────

#[tokio::test]
async fn rsa2048_self_signed_loopback() {
    // Use a pre-generated key to skip pure-Rust RSA-2048 keygen, which can
    // take over a minute without hardware-accelerated arithmetic.  The PKCS#8
    // parse path, cert generation, and TLS handshake are still fully exercised.
    let key = OxiRsa2048Key::from_pkcs8_der(test_fixtures::RSA2048_PKCS8_DER)
        .expect("RSA-2048 key fixture parse");
    let ck =
        self_signed_from_rsa2048_key(&["localhost"], key).expect("RSA-2048 cert gen from fixture");
    assert!(!ck.cert_der.is_empty());
    assert_eq!(ck.cert_der[0], 0x30, "DER must start with SEQUENCE tag");

    loopback_handshake(
        vec![ck.cert_der.clone()],
        ck.pkcs8_der.clone(),
        ck.cert_der.clone(),
    )
    .await
    .expect("RSA-2048 loopback handshake");
}

// ── 2. RSA-4096 self-signed loopback ──────────────────────────────────────────

#[tokio::test]
async fn rsa4096_self_signed_loopback() {
    // Use a pre-generated key to skip pure-Rust RSA-4096 keygen, which can
    // take 10+ minutes without hardware-accelerated arithmetic.  The PKCS#8
    // parse path, cert generation, and TLS handshake are still fully exercised.
    let key = OxiRsa4096Key::from_pkcs8_der(test_fixtures_rsa4096::RSA4096_PKCS8_DER)
        .expect("RSA-4096 key fixture parse");
    let ck =
        self_signed_from_rsa4096_key(&["localhost"], key).expect("RSA-4096 cert gen from fixture");
    assert!(!ck.cert_der.is_empty());

    loopback_handshake(
        vec![ck.cert_der.clone()],
        ck.pkcs8_der.clone(),
        ck.cert_der.clone(),
    )
    .await
    .expect("RSA-4096 loopback handshake");
}

// ── 3. P-384 self-signed loopback ─────────────────────────────────────────────

#[tokio::test]
async fn p384_self_signed_loopback() {
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

// ── 4. CA-signed leaf chain (P-384 issuer, P-384 leaf) ────────────────────────

#[tokio::test]
async fn ca_signed_leaf_validates() {
    let root = generate_ca("P-384 Root CA", SigningAlgorithm::EcdsaP384).expect("root CA");
    let leaf =
        generate_ca_signed_leaf(&["localhost"], SigningAlgorithm::EcdsaP384, &root).expect("leaf");

    let chain = vec![
        leaf.cert_der.clone(),
        root.as_certified_key().cert_der.clone(),
    ];
    loopback_handshake(
        chain,
        leaf.pkcs8_der.clone(),
        root.as_certified_key().cert_der.clone(),
    )
    .await
    .expect("P-384 CA-signed leaf loopback");
}

// ── 5. Intermediate chain (root P-256 → intermediate P-384 → leaf Ed25519) ────
//
// This test uses three different signing algorithms to prove cross-algorithm
// signing works at each level of the chain.  Historically the leaf used RSA-2048,
// but pure-Rust RSA keygen takes >2 minutes on this machine, so the leaf now
// uses Ed25519 (which is fast) while still exercising P-256 and P-384 at the
// CA levels.  RSA-2048 signing at the leaf level is tested separately in
// `rsa2048_self_signed_loopback` using a pre-generated key fixture.

#[tokio::test]
async fn intermediate_chain_validates() {
    // Mix algorithms across levels to prove cross-algorithm signing works.
    let root = oxitls_rcgen::generate_ca("Root CA", SigningAlgorithm::EcdsaP256).expect("root");
    let inter = oxitls_rcgen::generate_intermediate_ca(
        "Intermediate CA",
        SigningAlgorithm::EcdsaP384,
        &root,
    )
    .expect("intermediate");
    // Use Ed25519 at the leaf to keep this test fast; RSA leaf loopback is
    // covered by rsa2048_self_signed_loopback using a pre-generated key fixture.
    let leaf =
        generate_ca_signed_leaf(&["localhost"], SigningAlgorithm::Ed25519, &inter).expect("leaf");

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
    .expect("3-level chain loopback");
}

// ── 6. CSR round-trip (Ed25519 CSR, P-256 CA) ─────────────────────────────────

#[test]
fn csr_roundtrip() {
    let ca = generate_ca("CSR Test CA", SigningAlgorithm::EcdsaP256).expect("CA");
    let (csr, _priv_pkcs8): (CsrBytes, Vec<u8>) =
        generate_csr("test.example.com", SigningAlgorithm::Ed25519).expect("CSR gen");

    assert!(!csr.der.is_empty());
    assert!(csr.pem.contains("BEGIN CERTIFICATE REQUEST"));

    let signed = sign_csr(&csr.der, &ca, 365).expect("CSR sign");
    assert!(!signed.cert_der.is_empty());
    assert!(signed.cert_pem.contains("BEGIN CERTIFICATE"));

    // Parse the signed cert and check it chains to the CA (issuer DN matches
    // CA subject DN).
    let (_, leaf) = x509_parser::parse_x509_certificate(&signed.cert_der).expect("parse leaf");
    let (_, ca_cert) =
        x509_parser::parse_x509_certificate(&ca.as_certified_key().cert_der).expect("parse CA");
    assert_eq!(
        leaf.issuer().to_string(),
        ca_cert.subject().to_string(),
        "leaf.issuer must match CA.subject"
    );
    assert!(
        leaf.subject().to_string().contains("test.example.com"),
        "leaf.subject must carry CSR CN, got {}",
        leaf.subject()
    );
}

// ── 7. PKCS#12 round-trip ─────────────────────────────────────────────────────

#[test]
fn pkcs12_roundtrip() {
    let ck = generate_self_signed(&["localhost"], SigningAlgorithm::EcdsaP256).expect("cert");
    let pfx_bytes = ck.to_pkcs12("test123", "my-cert").expect("PKCS#12 export");

    assert!(!pfx_bytes.is_empty(), "PFX must be non-empty");
    // Re-parse via `p12` and ensure the cert/key bags can be reconstructed.
    let pfx = p12::PFX::parse(&pfx_bytes).expect("PFX parse");
    assert_eq!(pfx.version, 3);
    let cert_bags = pfx.cert_bags("test123").expect("decrypt cert bags");
    assert!(
        !cert_bags.is_empty(),
        "expected at least one cert bag in PFX"
    );
    let key_bags = pfx.key_bags("test123").expect("decrypt key bags");
    assert!(!key_bags.is_empty(), "expected at least one key bag in PFX");
    // The cert bag should contain the same DER we exported.
    assert_eq!(
        cert_bags[0], ck.cert_der,
        "decoded cert bag must match the exported cert DER"
    );
}

// ── 8. PEM export format sanity ───────────────────────────────────────────────

#[test]
fn pem_export_format() {
    let ck = generate_self_signed(&["localhost"], SigningAlgorithm::Ed25519).expect("cert");
    assert!(
        ck.cert_pem.starts_with("-----BEGIN CERTIFICATE-----"),
        "cert_pem must start with BEGIN CERTIFICATE; got: {:.80}",
        ck.cert_pem
    );
    let key_pem = ck.key_pem();
    assert!(
        key_pem.starts_with("-----BEGIN PRIVATE KEY-----"),
        "key_pem must start with BEGIN PRIVATE KEY; got: {:.80}",
        key_pem
    );
}

// ── 9. Custom validity period round-trips ─────────────────────────────────────

#[test]
fn custom_validity_period() {
    // We can't call CertificateParamsBuilder::build_with_spki without going
    // through a key — so we directly build params and feed them via the
    // low-level rcgen path. This test verifies that the accessor reads from
    // the actual cert DER, not a stored builder value.
    use oxitls_rcgen::OxiEd25519Key;
    use rcgen::PublicKeyData;

    let key = OxiEd25519Key::generate().expect("keygen");
    let spki = PublicKeyData::subject_public_key_info(&key);

    for days in [1i64, 365, 365 * 10] {
        let not_before = time::OffsetDateTime::now_utc();
        let not_after = not_before + time::Duration::days(days);

        let params = CertificateParamsBuilder::new()
            .with_dns_names(&["localhost"])
            .with_server_auth()
            .with_digital_signature()
            .with_validity(not_before, not_after)
            .build_with_spki(&spki)
            .expect("params");

        let cert = params.self_signed(&key).expect("self-sign cert");

        let ck = CertifiedKey {
            cert_der: cert.der().to_vec(),
            pkcs8_der: key.pkcs8_der().to_vec(),
            cert_pem: cert.pem(),
        };

        let decoded_not_after = ck.not_after().expect("not_after accessor");
        // X.509 timestamps are second-granularity; allow ≤1 s drift.
        let diff = (decoded_not_after - not_after).whole_seconds().abs();
        assert!(
            diff <= 1,
            "not_after drift {diff} s for {days}-day window (decoded {decoded_not_after}, expected {not_after})"
        );
    }
}

// ── 10. Multi-SAN: DNS + IP all present after x509-parser round-trip ──────────

#[test]
fn multi_san_cert() {
    use oxitls_rcgen::OxiEcdsaP256Key;
    use rcgen::PublicKeyData;

    let key = OxiEcdsaP256Key::generate().expect("keygen");
    let spki = PublicKeyData::subject_public_key_info(&key);

    let params = CertificateParamsBuilder::new()
        .with_common_name("multi-san.example")
        .with_dns_names(&["multi-san.example", "*.multi-san.example"])
        .with_ip_addresses(&["192.0.2.1", "::1"])
        .with_server_auth()
        .with_digital_signature()
        .build_with_spki(&spki)
        .expect("params");

    let cert = params.self_signed(&key).expect("self-sign cert");
    let cert_der = cert.der().to_vec();

    let (_, parsed) = x509_parser::parse_x509_certificate(&cert_der).expect("parse");
    let san_ext = parsed
        .subject_alternative_name()
        .expect("SAN parse")
        .expect("SAN present");
    let names: Vec<String> = san_ext
        .value
        .general_names
        .iter()
        .map(|gn| format!("{gn:?}"))
        .collect();
    assert!(
        names.iter().any(|n| n.contains("multi-san.example")),
        "DNS SAN must be present, got {names:?}"
    );
    assert!(
        names.iter().any(|n| n.contains("*.multi-san.example")),
        "wildcard DNS SAN must be present, got {names:?}"
    );
    assert!(
        names.iter().any(|n| n.contains("192.0.2.1")
            || n.contains("c0 00 02 01")
            || n.contains("\u{c0}\u{0}\u{2}\u{1}")
            || n.contains("[192, 0, 2, 1]")),
        "IPv4 SAN must be present, got {names:?}"
    );
    assert!(
        names
            .iter()
            .any(|n| n.contains("::1")
                || n.contains("[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]")),
        "IPv6 SAN must be present, got {names:?}"
    );
}

// ── 11. fingerprint_sha256() matches explicit SHA-256(cert_der) ───────────────

#[test]
fn fingerprint_matches_explicit_sha256() {
    let ck = generate_self_signed(&["localhost"], SigningAlgorithm::Ed25519).expect("cert");
    let mut hasher = Sha256::new();
    hasher.update(&ck.cert_der);
    let manual = hasher.finalize();

    let computed = ck.fingerprint_sha256();
    assert_eq!(
        &manual[..],
        &computed[..],
        "fingerprint_sha256() must equal SHA-256 over cert_der"
    );
}

// ── Bonus sanity: Display impl prints the four expected sections ──────────────

#[test]
fn display_impl_includes_all_sections() {
    let ck = generate_self_signed(&["localhost"], SigningAlgorithm::EcdsaP256).expect("cert");
    let out = format!("{ck}");
    for section in ["Subject:", "Algorithm:", "SHA-256:", "Not after:"] {
        assert!(
            out.contains(section),
            "Display output is missing {section}: {out}"
        );
    }
}

// ── 13. name_constraints_enforced ─────────────────────────────────────────────

/// Verify that a CA certificate can carry the NameConstraints extension and
/// that the extension is preserved faithfully in the serialised DER.
///
/// rcgen encodes NameConstraints (OID 2.5.29.30) when the builder is used
/// with `with_name_constraints`. This test:
///   1. Builds a CA cert with `permittedSubtrees = ["example.com"]`.
///   2. Parses the resulting DER with x509-parser.
///   3. Asserts the NameConstraints extension (OID 2.5.29.30) is present.
///
/// Whether rustls enforces the constraint at handshake time is outside scope:
/// rustls 0.23 delegates path building to webpki, which does enforce name
/// constraints. The test focusses on correct DER encoding.
#[test]
fn name_constraints_enforced() {
    use oxitls_rcgen::{CertificateParamsBuilder, OxiEd25519Key};
    use rcgen::{GeneralSubtree, PublicKeyData};
    use x509_parser::prelude::*;

    // Generate a fresh Ed25519 key and derive its SPKI for the KID.
    let key = OxiEd25519Key::generate().expect("Ed25519 keygen");
    let spki = PublicKeyData::subject_public_key_info(&key);

    // Build a CA cert that constrains issuance to the "example.com" DNS subtree.
    let params = CertificateParamsBuilder::new()
        .with_common_name("Name-Constrained CA")
        .with_ca()
        .with_key_cert_sign()
        .with_crl_sign()
        .with_name_constraints(
            vec![GeneralSubtree::DnsName("example.com".to_string())],
            vec![],
        )
        .build_with_spki(&spki)
        .expect("build CA params with name constraints");

    let cert = params.self_signed(&key).expect("self-sign CA cert");
    let cert_der = cert.der().to_vec();

    // Parse the DER and verify the NameConstraints extension is present.
    let (_, parsed) = X509Certificate::from_der(&cert_der).expect("x509-parser: parse CA cert DER");

    // OID 2.5.29.30 = NameConstraints
    const NAME_CONSTRAINTS_OID: &str = "2.5.29.30";
    let has_name_constraints = parsed
        .extensions()
        .iter()
        .any(|ext| ext.oid.to_id_string() == NAME_CONSTRAINTS_OID);

    assert!(
        has_name_constraints,
        "Expected NameConstraints extension (OID {NAME_CONSTRAINTS_OID}) in CA cert DER; \
         extensions present: {:?}",
        parsed
            .extensions()
            .iter()
            .map(|e| e.oid.to_id_string())
            .collect::<Vec<_>>()
    );
}

// ── 14. expired_cert_rejected_by_rustls ───────────────────────────────────────

/// Verify that rustls rejects a certificate whose `notAfter` is in the past.
///
/// Strategy: generate a cert that expired 1 day ago, wire it into an in-memory
/// rustls handshake (no tokio — uses `rustls::ConnectionCommon::process_new_packets`
/// in a synchronous byte-pump loop), and assert that at least one side raises
/// an error that mentions expiry or invalidity.
#[test]
fn expired_cert_rejected_by_rustls() {
    use oxitls_rcgen::{CertificateParamsBuilder, OxiEd25519Key};
    use rcgen::PublicKeyData;
    use rustls::{ClientConnection, ServerConnection};
    use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use std::sync::Arc;

    // Cert expired one day ago.
    let key = OxiEd25519Key::generate().expect("Ed25519 keygen");
    let spki = PublicKeyData::subject_public_key_info(&key);

    let now = time::OffsetDateTime::now_utc();
    let not_before = now - time::Duration::days(2); // 2 days ago
    let not_after = now - time::Duration::days(1); // 1 day ago (already expired)

    let params = CertificateParamsBuilder::new()
        .with_dns_names(&["expired.example.com"])
        .with_server_auth()
        .with_digital_signature()
        .with_validity(not_before, not_after)
        .build_with_spki(&spki)
        .expect("build expired cert params");

    let cert = params.self_signed(&key).expect("self-sign expired cert");
    let cert_der = cert.der().to_vec();
    let pkcs8_der = key.pkcs8_der().to_vec();

    // Build rustls server + client configs.
    // pure_provider() already returns Arc<CryptoProvider>.
    let provider: Arc<rustls::crypto::CryptoProvider> =
        oxitls_adapter_rustls_rustcrypto::pure_provider();

    let cert_chain = vec![CertificateDer::from(cert_der.clone())];
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8_der));

    let server_cfg = Arc::new(
        rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3 versions")
            .with_no_client_auth()
            .with_single_cert(cert_chain, key_der)
            .expect("server single cert"),
    );

    // Client trusts the expired cert as the root (so the chain validates
    // structurally — rustls must still reject based on time).
    let mut root_store = rustls::RootCertStore::empty();
    root_store
        .add(CertificateDer::from(cert_der))
        .expect("add expired cert to root store");

    let client_cfg = Arc::new(
        rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3 versions")
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    );

    let server_name =
        ServerName::try_from("expired.example.com".to_string()).expect("valid server name");
    let mut client = ClientConnection::new(client_cfg, server_name).expect("client conn");
    let mut server = ServerConnection::new(server_cfg).expect("server conn");

    // Byte-pump: drive both sides until an error surfaces or the pump exhausts.
    let mut error_found = false;
    let mut buf = Vec::with_capacity(16384);

    'outer: for _ in 0..40 {
        // Client → server
        buf.clear();
        if client.wants_write() {
            client.write_tls(&mut buf).ok();
            if !buf.is_empty() {
                let mut cursor = &buf[..];
                server.read_tls(&mut cursor).ok();
                if let Err(_e) = server.process_new_packets() {
                    error_found = true;
                    break 'outer;
                }
            }
        }

        // Server → client
        buf.clear();
        if server.wants_write() {
            server.write_tls(&mut buf).ok();
            if !buf.is_empty() {
                let mut cursor = &buf[..];
                client.read_tls(&mut cursor).ok();
                if let Err(e) = client.process_new_packets() {
                    let msg = e.to_string().to_lowercase();
                    // rustls/webpki emits "expired" or "invalid peer certificate"
                    // or similar when the notAfter constraint is violated.
                    assert!(
                        msg.contains("expired")
                            || msg.contains("invalid peer certificate")
                            || msg.contains("certificate is not valid")
                            || msg.contains("not yet valid")
                            || msg.contains("invalid"),
                        "Expected a certificate-expiry error from rustls, got: {e}"
                    );
                    error_found = true;
                    break 'outer;
                }
            }
        }

        // Both sides idle — handshake stalled without error.
        if !client.wants_write() && !server.wants_write() {
            break;
        }
    }

    assert!(
        error_found,
        "rustls accepted an expired certificate without raising an error — \
         the time-validity check appears to be absent from the path"
    );
}
