//! Integration tests for RFC 7250 raw public key support.
//!
//! Tests verify that:
//! 1. A server presenting a pinned RPK and a matching client verifier
//!    successfully complete a TLS 1.3 handshake.
//! 2. A mismatched pin causes the handshake to fail.
//! 3. Mutual RPK (mTLS equivalent) succeeds when both sides use raw keys.

use std::sync::Arc;

use oxitls_adapter_rustls_rustcrypto::pure_provider;
use oxitls_adapter_rustls_rustcrypto::verifier::{
    client_raw_public_key_resolver, server_raw_public_key_resolver, RawPublicKeyClientVerifier,
    RawPublicKeyServerVerifier,
};
use oxitls_rcgen::generate_self_signed_ed25519;
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, SubjectPublicKeyInfoDer,
};
use rustls::version::TLS13;

/// Extract the SubjectPublicKeyInfo DER from a full X.509 DER certificate.
///
/// Uses `rustls`'s internal webpki parser (exposed as
/// `rustls::server::ParsedCertificate`) which is guaranteed to be consistent
/// with how rustls itself reads keys during verification.
fn spki_from_cert_der(cert_der: &[u8]) -> SubjectPublicKeyInfoDer<'static> {
    let cert = CertificateDer::from(cert_der.to_vec());
    let parsed =
        rustls::server::ParsedCertificate::try_from(&cert).expect("parse cert for SPKI extraction");
    parsed.subject_public_key_info()
}

/// Build a `rustls::sign::CertifiedKey` suitable for RPK mode.
///
/// The `cert` slot holds the raw SPKI DER bytes (one entry).  The signing
/// key is loaded from the PKCS#8 DER via the provider's key loader.
fn rpk_certified_key(cert_der: &[u8], pkcs8_der: &[u8]) -> Arc<rustls::sign::CertifiedKey> {
    let provider = pure_provider();
    let spki = spki_from_cert_der(cert_der);
    let spki_cert = CertificateDer::from(spki.as_ref().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8_der.to_vec()));
    let signing_key = provider
        .key_provider
        .load_private_key(key_der)
        .expect("load signing key");
    Arc::new(rustls::sign::CertifiedKey::new(
        vec![spki_cert],
        signing_key,
    ))
}

/// Build a server `rustls::ServerConfig` with RPK resolver.
///
/// `verifier` is the client-cert verifier — pass `Arc::new(rustls::verify::NoClientAuth)`
/// for no mTLS, or an `RawPublicKeyClientVerifier` for mTLS.
fn server_config_rpk(
    cert_der: &[u8],
    pkcs8_der: &[u8],
    verifier: Arc<dyn rustls::server::danger::ClientCertVerifier>,
) -> Arc<rustls::ServerConfig> {
    let provider = pure_provider();
    let ck = rpk_certified_key(cert_der, pkcs8_der);
    let resolver = server_raw_public_key_resolver(ck);
    let cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])
        .expect("TLS 1.3 version config")
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(resolver);
    Arc::new(cfg)
}

/// Build a client `rustls::ClientConfig` with RPK verifier and optional
/// client cert resolver for mutual auth.
fn client_config_rpk(
    trusted_spki: SubjectPublicKeyInfoDer<'static>,
    client_cert: Option<(Vec<u8>, Vec<u8>)>, // (cert_der, pkcs8_der)
) -> Arc<rustls::ClientConfig> {
    let provider = pure_provider();
    let verifier = Arc::new(RawPublicKeyServerVerifier::new(
        vec![trusted_spki],
        Arc::clone(&provider),
    ));
    let builder = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&TLS13])
        .expect("TLS 1.3 version config")
        .dangerous()
        .with_custom_certificate_verifier(verifier);

    let cfg = match client_cert {
        Some((cert_der, pkcs8_der)) => {
            let ck = rpk_certified_key(&cert_der, &pkcs8_der);
            let resolver = client_raw_public_key_resolver(ck);
            builder.with_client_cert_resolver(resolver)
        }
        None => builder.with_no_client_auth(),
    };
    Arc::new(cfg)
}

/// Run a complete TLS 1.3 handshake over an in-memory duplex pipe and return
/// whether it succeeded.
async fn try_handshake(
    client_cfg: Arc<rustls::ClientConfig>,
    server_cfg: Arc<rustls::ServerConfig>,
) -> (bool, bool) {
    let (client_io, server_io) = tokio::io::duplex(65_536);
    let connector = tokio_rustls::TlsConnector::from(client_cfg);
    let acceptor = tokio_rustls::TlsAcceptor::from(server_cfg);
    let sn = ServerName::try_from("localhost")
        .expect("valid server name")
        .to_owned();

    let (client_res, server_res) =
        tokio::join!(connector.connect(sn, client_io), acceptor.accept(server_io),);
    (client_res.is_ok(), server_res.is_ok())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Test 1: Server presents a raw public key; client pins the matching SPKI.
/// The handshake must succeed.
#[tokio::test]
async fn rpk_server_pinned_match_succeeds() {
    let ck = generate_self_signed_ed25519(&["localhost"]).expect("cert gen");
    let server_spki = spki_from_cert_der(&ck.cert_der);

    let srv_cfg = server_config_rpk(
        &ck.cert_der,
        &ck.pkcs8_der,
        Arc::new(rustls::server::NoClientAuth),
    );
    let cli_cfg = client_config_rpk(server_spki, None);

    let (client_ok, server_ok) = try_handshake(cli_cfg, srv_cfg).await;
    assert!(
        client_ok,
        "client handshake should succeed with matching pin"
    );
    assert!(
        server_ok,
        "server handshake should succeed with matching pin"
    );
}

/// Test 2: Client pins the wrong SPKI.  The handshake must fail on the
/// client side (certificate verification failure).
#[tokio::test]
async fn rpk_server_wrong_pin_fails() {
    let server_ck = generate_self_signed_ed25519(&["localhost"]).expect("cert gen");
    let other_ck = generate_self_signed_ed25519(&["other.example"]).expect("cert gen");
    // Pin the *other* key, not the server's.
    let wrong_spki = spki_from_cert_der(&other_ck.cert_der);

    let srv_cfg = server_config_rpk(
        &server_ck.cert_der,
        &server_ck.pkcs8_der,
        Arc::new(rustls::server::NoClientAuth),
    );
    let cli_cfg = client_config_rpk(wrong_spki, None);

    let (client_ok, _) = try_handshake(cli_cfg, srv_cfg).await;
    assert!(
        !client_ok,
        "client handshake should fail with mismatched pin"
    );
}

/// Test 3: Mutual raw-public-key authentication.
/// Both server and client use raw public keys; both handshakes must succeed.
#[tokio::test]
async fn rpk_mutual_both_raw_keys_succeed() {
    let server_ck = generate_self_signed_ed25519(&["localhost"]).expect("server cert gen");
    let client_ck = generate_self_signed_ed25519(&["client.example"]).expect("client cert gen");

    let server_spki = spki_from_cert_der(&server_ck.cert_der);
    let client_spki = spki_from_cert_der(&client_ck.cert_der);

    let provider = pure_provider();
    let client_verifier = Arc::new(RawPublicKeyClientVerifier::new(
        vec![client_spki],
        Arc::clone(&provider),
    ));

    let srv_cfg = server_config_rpk(&server_ck.cert_der, &server_ck.pkcs8_der, client_verifier);
    let cli_cfg = client_config_rpk(
        server_spki,
        Some((client_ck.cert_der.clone(), client_ck.pkcs8_der.clone())),
    );

    let (client_ok, server_ok) = try_handshake(cli_cfg, srv_cfg).await;
    assert!(
        client_ok,
        "client handshake should succeed in mutual RPK mode"
    );
    assert!(
        server_ok,
        "server handshake should succeed in mutual RPK mode"
    );
}
