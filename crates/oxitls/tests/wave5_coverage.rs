//! Wave 5 Slice F — coverage test backfill.
//!
//! Covers:
//!  1. CRL: revoked cert rejected by client
//!  2. CRL: valid cert (not listed) accepted by client
//!  3. `with_danger_accept_invalid_certs` accepts self-signed server cert
//!  4. mTLS: client cert + server `with_client_cert_verifier` — handshake completes
//!  5. OCSP staple: server sets static OCSP response; client SoftFail policy; handshake completes
//!
//! All TLS sessions run over loopback TCP (random port).

use std::sync::Arc;

use rcgen::{
    date_time_ymd, BasicConstraints, CertificateParams, CertificateRevocationListParams, IsCa,
    KeyIdMethod, KeyPair, KeyUsagePurpose, RevocationReason, RevokedCertParams, SerialNumber,
};
use rustls::RootCertStore;
use rustls_pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

use oxitls::tls13::{ClientBuilder, ServerBuilder};

// ── Helpers ───────────────────────────────────────────────────────────────────

/// A CA-signed leaf pair usable in CRL tests.
struct CaLeafPair {
    ca_cert_der: CertificateDer<'static>,
    ca_kp: KeyPair,
    ca_params: CertificateParams,
    leaf_cert_der: CertificateDer<'static>,
    leaf_key_der: PrivateKeyDer<'static>,
    leaf_serial: SerialNumber,
}

/// Mint a CA + leaf certificate pair.
///
/// The leaf has SAN `localhost` and is signed by the CA.  Returns both
/// DER blobs and the signing context needed for CRL generation.
fn make_ca_and_leaf() -> CaLeafPair {
    // CA key + cert.
    let ca_kp = KeyPair::generate().expect("ca keygen");
    let mut ca_params =
        CertificateParams::new(vec!["ca.wave5.test".to_string()]).expect("ca params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::CrlSign,
    ];
    ca_params.serial_number = Some(SerialNumber::from(1u64));
    let ca_cert = ca_params.self_signed(&ca_kp).expect("ca self-sign");
    let ca_cert_der = CertificateDer::from(ca_cert.der().to_vec());

    // Leaf key + cert signed by CA.
    let leaf_kp = KeyPair::generate().expect("leaf keygen");
    let leaf_serial = SerialNumber::from(42u64);
    let mut leaf_params =
        CertificateParams::new(vec!["localhost".to_string()]).expect("leaf params");
    leaf_params.serial_number = Some(leaf_serial.clone());
    let ca_issuer = rcgen::Issuer::from_params(&ca_params, &ca_kp);
    let leaf_cert = leaf_params
        .signed_by(&leaf_kp, &ca_issuer)
        .expect("leaf sign");
    let leaf_cert_der = CertificateDer::from(leaf_cert.der().to_vec());
    let leaf_key_der = PrivateKeyDer::Pkcs8(leaf_kp.serialize_der().into());

    CaLeafPair {
        ca_cert_der,
        ca_kp,
        ca_params,
        leaf_cert_der,
        leaf_key_der,
        leaf_serial,
    }
}

/// Build a CRL signed by the given CA, optionally revoking the leaf serial.
fn build_crl(pair: &CaLeafPair, revoke_leaf: bool) -> CertificateRevocationListDer<'static> {
    let revoked = if revoke_leaf {
        vec![RevokedCertParams {
            serial_number: pair.leaf_serial.clone(),
            revocation_time: date_time_ymd(2026, 1, 1),
            reason_code: Some(RevocationReason::KeyCompromise),
            invalidity_date: None,
        }]
    } else {
        vec![]
    };

    let ca_issuer = rcgen::Issuer::from_params(&pair.ca_params, &pair.ca_kp);
    let crl = CertificateRevocationListParams {
        this_update: date_time_ymd(2026, 1, 1),
        next_update: date_time_ymd(2030, 1, 1),
        crl_number: SerialNumber::from(1u64),
        issuing_distribution_point: None,
        revoked_certs: revoked,
        key_identifier_method: KeyIdMethod::Sha256,
    }
    .signed_by(&ca_issuer)
    .expect("crl sign");

    CertificateRevocationListDer::from(crl.der().to_vec())
}

/// Spawn a simple TLS echo-server accepting one connection (echo 1 byte).
/// Returns the listening address + join handle.
async fn spawn_echo_server_cfg(
    cfg: rustls::ServerConfig,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener bind");
    let addr = listener.local_addr().expect("local addr");
    let handle = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept");
        // Ignore accept errors — test may close before the handshake.
        if let Ok(mut tls) = acceptor.accept(tcp).await {
            let mut buf = [0u8; 1];
            let _ = tls.read_exact(&mut buf).await;
            let _ = tls.write_all(&buf).await;
            let _ = tls.flush().await;
        }
    });
    (addr, handle)
}

// ── Test 1: CRL — revoked cert is rejected ────────────────────────────────────

#[tokio::test]
async fn crl_revoked_cert_rejected() {
    let pair = make_ca_and_leaf();
    let crl_der = build_crl(&pair, true); // leaf is revoked

    // Build server config presenting the CA-signed leaf cert.
    let server_cfg = ServerBuilder::new()
        .with_der_cert_and_key(
            vec![pair.leaf_cert_der.clone()],
            pair.leaf_key_der.clone_key(),
        )
        .build()
        .expect("server config");

    let (addr, _server_handle) = spawn_echo_server_cfg(server_cfg).await;

    // Build client config with CRL via ClientBuilder (delegates to adapter's
    // RustcryptoClientConfigBuilder CRL path).
    let client_cfg = ClientBuilder::new()
        .with_trusted_cert_der(pair.ca_cert_der.to_vec())
        .expect("trusted cert")
        .with_crl(vec![crl_der])
        .build()
        .expect("client config with CRL");

    let connector = TlsConnector::from(Arc::new(client_cfg));
    let tcp = TcpStream::connect(addr).await.expect("tcp connect");
    let sn = ServerName::try_from("localhost").expect("server name");
    let result = connector.connect(sn, tcp).await;

    assert!(
        result.is_err(),
        "expected TLS handshake to fail for revoked cert; got Ok"
    );
}

// ── Test 2: CRL — valid cert (not listed) is accepted ────────────────────────

#[tokio::test]
async fn crl_valid_cert_accepted() {
    let pair = make_ca_and_leaf();
    let crl_der = build_crl(&pair, false); // leaf is NOT revoked

    let server_cfg = ServerBuilder::new()
        .with_der_cert_and_key(
            vec![pair.leaf_cert_der.clone()],
            pair.leaf_key_der.clone_key(),
        )
        .build()
        .expect("server config");

    let (addr, server_handle) = spawn_echo_server_cfg(server_cfg).await;

    let client_cfg = ClientBuilder::new()
        .with_trusted_cert_der(pair.ca_cert_der.to_vec())
        .expect("trusted cert")
        .with_crl(vec![crl_der])
        .build()
        .expect("client config with CRL");

    let connector = TlsConnector::from(Arc::new(client_cfg));
    let tcp = TcpStream::connect(addr).await.expect("tcp connect");
    let sn = ServerName::try_from("localhost").expect("server name");
    let mut tls = connector
        .connect(sn, tcp)
        .await
        .expect("handshake should succeed for valid cert with CRL");

    tls.write_all(&[0x5A]).await.expect("write");
    tls.flush().await.expect("flush");
    let mut reply = [0u8; 1];
    tls.read_exact(&mut reply).await.expect("read");
    assert_eq!(reply[0], 0x5A, "echo mismatch");

    server_handle.await.expect("server task");
}

// ── Test 3: with_danger_accept_invalid_certs accepts self-signed ──────────────

#[tokio::test]
async fn with_danger_accept_invalid_certs_accepts_self_signed() {
    // Server uses a raw self-signed cert with no CA chain.
    let kp = KeyPair::generate().expect("keygen");
    let cert = CertificateParams::new(vec!["localhost".to_string()])
        .expect("cert params")
        .self_signed(&kp)
        .expect("self-sign");
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(kp.serialize_der().into());

    let server_cfg = ServerBuilder::new()
        .with_der_cert_and_key(vec![cert_der], key_der)
        .build()
        .expect("server config");

    let (addr, server_handle) = spawn_echo_server_cfg(server_cfg).await;

    // Client skips all cert verification (danger flag).
    let client_cfg = ClientBuilder::new()
        .with_danger_accept_invalid_certs()
        .build()
        .expect("danger client config");

    let connector = TlsConnector::from(Arc::new(client_cfg));
    let tcp = TcpStream::connect(addr).await.expect("tcp connect");
    let sn = ServerName::try_from("localhost").expect("server name");
    let mut tls = connector
        .connect(sn, tcp)
        .await
        .expect("handshake should succeed with danger_accept_invalid_certs");

    tls.write_all(&[0x77]).await.expect("write");
    tls.flush().await.expect("flush");
    let mut reply = [0u8; 1];
    tls.read_exact(&mut reply).await.expect("read");
    assert_eq!(reply[0], 0x77, "echo mismatch");

    server_handle.await.expect("server task");
}

// ── Test 4: mTLS — client presents cert; server sees peer_certificates ────────

#[tokio::test]
async fn with_client_cert_mtls_handshake_completes() {
    // CA + client leaf.
    let ca_kp = KeyPair::generate().expect("ca keygen");
    let mut ca_params =
        CertificateParams::new(vec!["ca.mtls.test".to_string()]).expect("ca params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.serial_number = Some(SerialNumber::from(1u64));
    let ca_cert = ca_params.self_signed(&ca_kp).expect("ca self-sign");
    let ca_cert_der = CertificateDer::from(ca_cert.der().to_vec());

    let ca_issuer = rcgen::Issuer::from_params(&ca_params, &ca_kp);
    let client_kp = KeyPair::generate().expect("client keygen");
    let client_params =
        CertificateParams::new(vec!["client.mtls.test".to_string()]).expect("client params");
    let client_cert = client_params
        .signed_by(&client_kp, &ca_issuer)
        .expect("sign");
    let client_cert_der = CertificateDer::from(client_cert.der().to_vec());
    let client_key_der = PrivateKeyDer::Pkcs8(client_kp.serialize_der().into());

    // Server: self-signed cert (client does not verify it via CA, just trusts
    // it directly) + requires client cert signed by our CA.
    let server_kp = KeyPair::generate().expect("server keygen");
    let server_cert = CertificateParams::new(vec!["localhost".to_string()])
        .expect("server params")
        .self_signed(&server_kp)
        .expect("server self-sign");
    let server_cert_der = CertificateDer::from(server_cert.der().to_vec());
    let server_key_der = PrivateKeyDer::Pkcs8(server_kp.serialize_der().into());

    let mut ca_roots = RootCertStore::empty();
    ca_roots.add(ca_cert_der).expect("add ca root");

    let server_cfg = ServerBuilder::new()
        .with_der_cert_and_key(vec![server_cert_der.clone()], server_key_der)
        .with_client_cert_verifier(ca_roots)
        .build()
        .expect("mTLS server config");

    // The server task captures the peer certs from the accepted stream.
    use std::sync::atomic::{AtomicBool, Ordering};
    let saw_client_cert = Arc::new(AtomicBool::new(false));
    let saw_flag = Arc::clone(&saw_client_cert);

    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener bind");
    let addr = listener.local_addr().expect("addr");
    let server_handle = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept");
        let mut tls = acceptor.accept(tcp).await.expect("server accept");
        let (_, session) = tls.get_ref();
        if session.peer_certificates().is_some() {
            saw_flag.store(true, Ordering::SeqCst);
        }
        let mut buf = [0u8; 1];
        tls.read_exact(&mut buf).await.expect("server read");
        tls.write_all(&buf).await.expect("server write");
        tls.flush().await.expect("flush");
    });

    // Client presents its cert.
    let client_cfg = ClientBuilder::new()
        .with_trusted_cert_der(server_cert_der.to_vec())
        .expect("trusted server cert")
        .with_client_cert(vec![client_cert_der], client_key_der)
        .build()
        .expect("client config with client cert");

    let connector = TlsConnector::from(Arc::new(client_cfg));
    let tcp = TcpStream::connect(addr).await.expect("tcp connect");
    let sn = ServerName::try_from("localhost").expect("server name");
    let mut tls = connector
        .connect(sn, tcp)
        .await
        .expect("mTLS handshake should complete");

    tls.write_all(&[0xCC]).await.expect("write");
    tls.flush().await.expect("flush");
    let mut reply = [0u8; 1];
    tls.read_exact(&mut reply).await.expect("read");
    assert_eq!(reply[0], 0xCC, "echo mismatch");

    server_handle.await.expect("server task");
    assert!(
        saw_client_cert.load(std::sync::atomic::Ordering::SeqCst),
        "server should have seen peer_certificates after mTLS handshake"
    );
}

// ── Test 5: OCSP staple — server provides response; client SoftFail ───────────
//
// NOTE: This test verifies the OCSP bytes reach the client-side verifier but
// does NOT perform cryptographic validation of the OCSP signature (that is
// Wave 5 Slice A work). The SoftFail policy means a malformed/unverified OCSP
// staple will not block the handshake.

#[tokio::test]
#[ignore = "requires Wave 5 Slice A OCSP crypto to be complete"]
async fn ocsp_staple_with_response() {
    use oxitls::StaticOcspResolver;
    use oxitls_adapter_rustls_rustcrypto::{
        verifier::ocsp_client::OcspClientPolicy, RustcryptoClientConfigBuilder,
    };

    let kp = KeyPair::generate().expect("keygen");
    let cert = CertificateParams::new(vec!["localhost".to_string()])
        .expect("cert params")
        .self_signed(&kp)
        .expect("self-sign");
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(kp.serialize_der().into());

    // A minimal valid-looking OCSP response DER (not cryptographically valid,
    // but sufficient to exercise the SoftFail path — the verifier logs an
    // error and continues).
    let ocsp_bytes: Vec<u8> = vec![
        0x30, 0x03, 0x0a, 0x01, 0x00, // OCSP Response: successful status byte
    ];

    let server_cfg = ServerBuilder::new()
        .with_der_cert_and_key(vec![cert_der.clone()], key_der)
        .with_ocsp_response_resolver(Arc::new(StaticOcspResolver(ocsp_bytes)))
        .build()
        .expect("server config with OCSP staple");

    let (addr, server_handle) = spawn_echo_server_cfg(server_cfg).await;

    // Build a client config with OcspClientPolicy::SoftFail via the adapter
    // builder — this is the path that exercises the OCSP verifier.
    let mut root_store = RootCertStore::empty();
    root_store.add(cert_der).expect("add root");
    let client_cfg = Arc::new(
        RustcryptoClientConfigBuilder::new()
            .with_roots(root_store)
            .with_ocsp_policy(OcspClientPolicy::SoftFail)
            .build()
            .expect("client config with OCSP policy"),
    );

    let connector = TlsConnector::from(client_cfg);
    let tcp = TcpStream::connect(addr).await.expect("tcp connect");
    let sn = ServerName::try_from("localhost").expect("server name");
    let mut tls = connector
        .connect(sn, tcp)
        .await
        .expect("OCSP SoftFail handshake should complete even with unverified staple");

    tls.write_all(&[0xF1]).await.expect("write");
    tls.flush().await.expect("flush");
    let mut reply = [0u8; 1];
    tls.read_exact(&mut reply).await.expect("read");
    assert_eq!(reply[0], 0xF1, "echo mismatch");

    server_handle.await.expect("server task");
}
