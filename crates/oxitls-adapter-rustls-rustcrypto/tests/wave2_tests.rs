//! Wave 2 integration tests: builders, verifiers, keylog, ConnectionInfo.

use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use oxitls_adapter_rustls_rustcrypto::{
    accept_with_timeout, connect_with_alpn, from_config_with_sni, server_config,
    RustcryptoAcceptor, RustcryptoClientConfigBuilder, RustcryptoConnector,
    RustcryptoServerConfigBuilder,
};
use oxitls_core::keylog::{KeyLog, KeyLogPolicy};
use oxitls_core::TlsStreamInfo;
use oxitls_webpki_roots::IntermediateCertCache;
use rcgen::{
    date_time_ymd, generate_simple_self_signed, BasicConstraints, CertificateParams,
    CertificateRevocationListParams, CertifiedIssuer, CertifiedKey, IsCa, KeyPair, KeyUsagePurpose,
    RevocationReason, RevokedCertParams, SerialNumber,
};
use rustls::RootCertStore;
use rustls_pki_types::PrivatePkcs8KeyDer;
use sha2::{Digest, Sha256};
use tokio::net::{TcpListener, TcpStream};

// ── Helper ───────────────────────────────────────────────────────────────────

/// Build a minimal server + client config from a self-signed cert and a root
/// store containing that cert. Returns (server_cfg, root_store, cert_der).
fn make_self_signed(
    san: &str,
) -> (
    Arc<rustls::ServerConfig>,
    RootCertStore,
    rustls_pki_types::CertificateDer<'static>,
) {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec![san.to_string()]).expect("rcgen failed");
    let cert_der = cert.der().clone();
    let key_bytes = signing_key.serialize_der();
    let key_der = rustls_pki_types::PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_bytes));
    let srv_cfg = server_config(vec![cert_der.clone()], key_der).expect("server_config failed");
    let mut roots = RootCertStore::empty();
    roots.add(cert_der.clone()).expect("add root failed");
    (srv_cfg, roots, cert_der)
}

/// Compute the SHA-256 fingerprint of a DER blob.
fn sha256_fingerprint(der: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(der);
    let mut fp = [0u8; 32];
    fp.copy_from_slice(&digest);
    fp
}

/// Spawn a server that echoes nothing (just accepts and holds), return port.
async fn spawn_echo_server(acceptor: RustcryptoAcceptor) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind failed");
    let port = listener.local_addr().expect("addr").port();
    tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            let _tls = acceptor.accept_tcp(stream).await;
        }
    });
    port
}

// ── Test 1a: cert pin match accepts ─────────────────────────────────────────

#[tokio::test]
async fn cert_pin_match_accepts() {
    let (srv_cfg, roots, cert_der) = make_self_signed("localhost");
    let fingerprint = sha256_fingerprint(&cert_der);

    let cli_cfg = RustcryptoClientConfigBuilder::new()
        .with_roots(roots)
        .with_pinned_certs(vec![fingerprint])
        .build()
        .expect("client config");

    let acceptor = RustcryptoAcceptor::new(srv_cfg);
    let port = spawn_echo_server(acceptor).await;

    let tcp = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("tcp connect");
    let _tls = RustcryptoConnector::new(Arc::new(cli_cfg))
        .connect_tcp("localhost", tcp)
        .await
        .expect("pinned connect should succeed");
}

// ── Test 1b: cert pin mismatch rejects ──────────────────────────────────────

#[tokio::test]
async fn cert_pin_mismatch_rejects() {
    let (srv_cfg, roots, _cert_der) = make_self_signed("localhost");
    // Use a random wrong fingerprint.
    let wrong_fp = [0u8; 32];

    let cli_cfg = RustcryptoClientConfigBuilder::new()
        .with_roots(roots)
        .with_pinned_certs(vec![wrong_fp])
        .build()
        .expect("client config");

    let acceptor = RustcryptoAcceptor::new(srv_cfg);
    let port = spawn_echo_server(acceptor).await;

    let tcp = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("tcp connect");
    let result = RustcryptoConnector::new(Arc::new(cli_cfg))
        .connect_tcp("localhost", tcp)
        .await;
    assert!(result.is_err(), "mismatched pin should reject");
}

// ── Test 2: CRL revoked cert rejected ────────────────────────────────────────

#[tokio::test]
async fn crl_revoked_cert_rejected() {
    // Build a self-signed CA using CertifiedIssuer.
    let ca_key = KeyPair::generate().expect("ca key");
    let mut ca_params = CertificateParams::new(vec!["ca.test".to_string()]).expect("ca params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    ca_params.serial_number = Some(SerialNumber::from(1u64));
    let ca = CertifiedIssuer::self_signed(ca_params, ca_key).expect("CA self_signed");
    let ca_cert_der = ca.der().clone();

    // Build a leaf cert signed by the CA.
    let leaf_serial = SerialNumber::from(42u64);
    let mut leaf_params =
        CertificateParams::new(vec!["localhost".to_string()]).expect("leaf params");
    leaf_params.serial_number = Some(leaf_serial.clone());
    let leaf_key = KeyPair::generate().expect("leaf key");
    let leaf_cert = leaf_params.signed_by(&leaf_key, &ca).expect("signed_by");

    // Build server config from the leaf cert.
    let leaf_key_bytes = leaf_key.serialize_der();
    let leaf_key_der =
        rustls_pki_types::PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key_bytes));
    let leaf_cert_der = leaf_cert.der().clone();

    let srv_cfg = server_config(vec![leaf_cert_der], leaf_key_der).expect("server_config");

    // Build a CRL revoking the leaf.
    let crl_params = CertificateRevocationListParams {
        this_update: date_time_ymd(2023, 1, 1),
        next_update: date_time_ymd(2099, 1, 1),
        crl_number: SerialNumber::from(1u64),
        issuing_distribution_point: None,
        revoked_certs: vec![RevokedCertParams {
            serial_number: leaf_serial,
            revocation_time: date_time_ymd(2023, 6, 1),
            reason_code: Some(RevocationReason::KeyCompromise),
            invalidity_date: None,
        }],
        key_identifier_method: rcgen::KeyIdMethod::Sha256,
    };
    let crl = crl_params.signed_by(&ca).expect("crl signed_by");
    let crl_der = crl.der().clone();

    // Add the CA as trust anchor.
    let mut roots = RootCertStore::empty();
    roots.add(ca_cert_der).expect("add CA root");

    let cli_cfg = RustcryptoClientConfigBuilder::new()
        .with_roots(roots)
        .with_crl(vec![crl_der])
        .build()
        .expect("client config with CRL");

    let acceptor = RustcryptoAcceptor::new(srv_cfg);
    let port = spawn_echo_server(acceptor).await;

    let tcp = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("tcp connect");
    let result = RustcryptoConnector::new(Arc::new(cli_cfg))
        .connect_tcp("localhost", tcp)
        .await;
    assert!(result.is_err(), "revoked cert should be rejected");
}

// ── Test 3: keylog file writes secrets ───────────────────────────────────────

#[tokio::test]
async fn keylog_file_writes_secrets() {
    let (srv_cfg, roots, _cert_der) = make_self_signed("localhost");

    let tmp = std::env::temp_dir().join(format!("oxitls_keys_{}.log", std::process::id()));
    let keylog_path = tmp.clone();

    let cli_cfg = RustcryptoClientConfigBuilder::new()
        .with_roots(roots)
        .with_keylog(KeyLogPolicy::File(keylog_path.clone()))
        .build()
        .expect("client config");

    let acceptor = RustcryptoAcceptor::new(srv_cfg);
    let port = spawn_echo_server(acceptor).await;

    let tcp = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("tcp connect");
    let _tls = RustcryptoConnector::new(Arc::new(cli_cfg))
        .connect_tcp("localhost", tcp)
        .await
        .expect("tls connect");

    // Verify the key log file exists and contains a known label.
    let contents = std::fs::read_to_string(&keylog_path).expect("keylog file should exist");
    let has_secret = contents.contains("CLIENT_HANDSHAKE_TRAFFIC_SECRET")
        || contents.contains("CLIENT_RANDOM")
        || contents.contains("TRAFFIC_SECRET");
    assert!(
        has_secret,
        "keylog should contain TLS secret labels: {contents}"
    );

    let _ = std::fs::remove_file(&keylog_path);
}

// ── Test 4: keylog custom receives secrets ───────────────────────────────────

#[derive(Debug)]
struct InMemoryLog {
    entries: Arc<Mutex<Vec<String>>>,
}

impl KeyLog for InMemoryLog {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        let entry = format!("{label} {} {}", hex_bytes(client_random), hex_bytes(secret),);
        self.entries.lock().expect("mutex ok").push(entry);
    }
}

fn hex_bytes(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, x| {
        use std::fmt::Write as _;
        let _ = write!(s, "{x:02x}");
        s
    })
}

#[tokio::test]
async fn keylog_custom_receives_secrets() {
    let (srv_cfg, roots, _cert_der) = make_self_signed("localhost");

    let log_entries: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let logger = InMemoryLog {
        entries: Arc::clone(&log_entries),
    };

    let cli_cfg = RustcryptoClientConfigBuilder::new()
        .with_roots(roots)
        .with_keylog(KeyLogPolicy::Custom(Arc::new(logger)))
        .build()
        .expect("client config");

    let acceptor = RustcryptoAcceptor::new(srv_cfg);
    let port = spawn_echo_server(acceptor).await;

    let tcp = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("tcp connect");
    let _tls = RustcryptoConnector::new(Arc::new(cli_cfg))
        .connect_tcp("localhost", tcp)
        .await
        .expect("tls connect");

    let entries = log_entries.lock().expect("mutex ok");
    assert!(
        entries.len() >= 2,
        "expected at least 2 key log entries, got {}",
        entries.len()
    );
}

// ── Test 5: connection_info populated post-handshake ─────────────────────────

#[tokio::test]
async fn connection_info_populated_post_handshake() {
    let (srv_cfg, roots, _cert_der) = make_self_signed("localhost");
    let cli_cfg = RustcryptoClientConfigBuilder::new()
        .with_roots(roots)
        .build()
        .expect("client config");

    let acceptor = RustcryptoAcceptor::new(srv_cfg);
    let port = spawn_echo_server(acceptor).await;

    let tcp = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("tcp connect");
    let tls = RustcryptoConnector::new(Arc::new(cli_cfg))
        .connect_tcp("localhost", tcp)
        .await
        .expect("tls connect");

    let info = tls
        .connection_info()
        .expect("connection_info should be Some");
    assert!(info.version.is_some(), "TLS version should be set");
    assert!(info.cipher_suite.is_some(), "cipher suite should be set");
}

// ── Test 6: connect_with_alpn negotiates ─────────────────────────────────────

#[tokio::test]
async fn connect_with_alpn_negotiates() {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".to_string()]).expect("rcgen");
    let cert_der = cert.der().clone();
    let key_bytes = signing_key.serialize_der();
    let key_der = rustls_pki_types::PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_bytes));

    let srv_cfg = RustcryptoServerConfigBuilder::new()
        .with_cert_and_key(vec![cert_der.clone()], key_der)
        .with_alpn(vec![b"h2".to_vec()])
        .build()
        .expect("server config");

    let mut roots = RootCertStore::empty();
    roots.add(cert_der.clone()).expect("add root");

    let acceptor = RustcryptoAcceptor::new(Arc::new(srv_cfg));
    let port = spawn_echo_server(acceptor).await;

    let tcp = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("tcp connect");
    let tls = connect_with_alpn(tcp, "localhost", vec![b"h2".to_vec()], roots)
        .await
        .expect("connect_with_alpn");

    let info = tls.connection_info().expect("connection_info");
    assert_eq!(
        info.alpn_protocol.as_deref(),
        Some(b"h2".as_ref()),
        "ALPN should be h2"
    );
}

// ── Test 7: accept_with_timeout elapses ──────────────────────────────────────

#[tokio::test]
async fn accept_with_timeout_elapses() {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".to_string()]).expect("rcgen");
    let cert_der = cert.der().clone();
    let key_bytes = signing_key.serialize_der();
    let key_der = rustls_pki_types::PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_bytes));
    let srv_cfg = server_config(vec![cert_der], key_der).expect("server_config");

    let acceptor = RustcryptoAcceptor::new(srv_cfg);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();

    // Connect at TCP level but never start TLS handshake from the other end.
    let _tcp_client = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("tcp connect");
    let (server_side, _) = listener.accept().await.expect("accept tcp");

    let result = accept_with_timeout(&acceptor, server_side, Duration::from_millis(50)).await;
    assert!(result.is_err(), "should time out");
    let err_str = result.err().map(|e| e.to_string()).unwrap_or_default();
    assert!(
        err_str.contains("timed out") || err_str.contains("timeout"),
        "error should mention timeout: {err_str}"
    );
}

// ── Test 8: client builder fluent compiles ───────────────────────────────────

#[tokio::test]
async fn client_builder_fluent_compiles() {
    // Need at least one root cert to satisfy WebPkiServerVerifier (NoRootAnchors error otherwise).
    let (_, roots, _) = make_self_signed("localhost");
    let cfg = RustcryptoClientConfigBuilder::new()
        .with_roots(roots)
        .with_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()])
        .with_resumption_disabled()
        .build();
    assert!(cfg.is_ok(), "client builder should produce a valid config");
}

// ── Test 9: server builder fluent compiles ───────────────────────────────────

#[tokio::test]
async fn server_builder_fluent_compiles() {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".to_string()]).expect("rcgen");
    let cert_der = cert.der().clone();
    let key_bytes = signing_key.serialize_der();
    let key_der = rustls_pki_types::PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_bytes));

    let cfg = RustcryptoServerConfigBuilder::new()
        .with_cert_and_key(vec![cert_der], key_der)
        .with_alpn(vec![b"h2".to_vec()])
        .build();
    assert!(cfg.is_ok(), "server builder should produce a valid config");
}

// ── Test 10: intermediate cache records chain ─────────────────────────────────

#[tokio::test]
async fn intermediate_cache_records_chain() {
    // Build CA -> intermediate -> leaf chain using CertifiedIssuer.
    let root_key = KeyPair::generate().expect("root key");
    let mut root_params = CertificateParams::new(vec!["root.ca".to_string()]).expect("root params");
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    root_params.serial_number = Some(SerialNumber::from(1u64));
    let root_ca = CertifiedIssuer::self_signed(root_params, root_key).expect("root CA");

    let int_key = KeyPair::generate().expect("int key");
    let mut int_params = CertificateParams::new(vec!["int.ca".to_string()]).expect("int params");
    int_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    int_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    int_params.serial_number = Some(SerialNumber::from(2u64));
    let int_ca =
        CertifiedIssuer::signed_by(int_params, int_key, &root_ca).expect("int CA signed_by");

    let leaf_key = KeyPair::generate().expect("leaf key");
    let mut leaf_params =
        CertificateParams::new(vec!["localhost".to_string()]).expect("leaf params");
    leaf_params.serial_number = Some(SerialNumber::from(3u64));
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &int_ca)
        .expect("leaf signed_by");

    // Intermediate DER — fingerprint for later assertion.
    let int_cert_der = int_ca.der().clone();
    let int_fp = sha256_fingerprint(&int_cert_der);

    // Server config: send leaf + intermediate.
    let leaf_key_bytes = leaf_key.serialize_der();
    let leaf_key_der =
        rustls_pki_types::PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key_bytes));
    let leaf_cert_der = leaf_cert.der().clone();
    let srv_cfg = server_config(
        vec![leaf_cert_der.clone(), int_cert_der.clone()],
        leaf_key_der,
    )
    .expect("server_config");

    // Client trusts the root.
    let root_cert_der = root_ca.der().clone();
    let mut roots = RootCertStore::empty();
    roots.add(root_cert_der).expect("add root");

    let cache = Arc::new(IntermediateCertCache::new(
        NonZeroUsize::new(32).expect("non-zero"),
    ));
    let cli_cfg = RustcryptoClientConfigBuilder::new()
        .with_roots(roots)
        .with_intermediate_cache(Arc::clone(&cache))
        .build()
        .expect("client config");

    let acceptor = RustcryptoAcceptor::new(srv_cfg);
    let port = spawn_echo_server(acceptor).await;

    let tcp = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("tcp connect");
    let _tls = RustcryptoConnector::new(Arc::new(cli_cfg))
        .connect_tcp("localhost", tcp)
        .await
        .expect("tls connect");

    assert!(
        cache.contains(&int_fp).expect("cache ok"),
        "intermediate fingerprint should be in cache after handshake"
    );
}

// ── Test 11: from_config_with_sni works ──────────────────────────────────────

#[tokio::test]
async fn from_config_with_sni_works() {
    let (srv_cfg, roots, _cert_der) = make_self_signed("localhost");
    let cli_cfg = Arc::new(
        RustcryptoClientConfigBuilder::new()
            .with_roots(roots)
            .build()
            .expect("client config"),
    );

    let acceptor = RustcryptoAcceptor::new(srv_cfg);
    let port = spawn_echo_server(acceptor).await;

    let tcp = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("tcp connect");
    let _tls = from_config_with_sni(tcp, cli_cfg, "localhost")
        .await
        .expect("from_config_with_sni");
}
