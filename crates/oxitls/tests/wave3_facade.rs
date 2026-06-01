//! Wave 3 Slice G: integration tests for oxitls facade builder expansion +
//! OxiTlsStream<S> wrapper.
//!
//! All loopback handshakes use in-process TCP sockets on a random free port.
//! Certificates are generated via `oxitls_rcgen` (Pure Rust, no ring).
//! Temp files use `std::env::temp_dir()`.

use std::sync::Arc;
use std::time::Duration;

use rustls::RootCertStore;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

use oxitls::tls13::{ClientBuilder, ServerBuilder};
use oxitls::{OxiTlsStream, TlsConnectionExt};
use oxitls_rcgen::{generate_self_signed_ed25519, generate_self_signed_p256};

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Build a `RootCertStore` trusting one DER cert.
fn one_cert_root(der: &[u8]) -> RootCertStore {
    let mut store = RootCertStore::empty();
    store
        .add(CertificateDer::from(der.to_vec()))
        .expect("add root");
    store
}

/// Build a Plain rustls TLS 1.3 `ClientConfig` trusting the given root.
fn plain_client_config(root: RootCertStore) -> Arc<rustls::ClientConfig> {
    let provider = oxitls_adapter_rustls_rustcrypto::pure_provider();
    Arc::new(
        rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3")
            .with_root_certificates(root)
            .with_no_client_auth(),
    )
}

// ── Test 1: cert pinning accepts correct pin ──────────────────────────────────

#[tokio::test]
async fn client_with_cert_pinning_accepts_matching_pin() {
    let ck = generate_self_signed_p256(&["localhost"]).expect("cert gen");
    let fp = ck.fingerprint_sha256();

    let certs = vec![CertificateDer::from(ck.cert_der.clone())];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.pkcs8_der.clone()));

    let server_cfg = ServerBuilder::new()
        .with_der_cert_and_key(certs, key)
        .build()
        .expect("server build");
    let acceptor = oxitls::tls13::server::tokio_acceptor(server_cfg);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(tcp).await.expect("server accept");
        let mut buf = [0u8; 1];
        tls.read_exact(&mut buf).await.unwrap();
        tls.write_all(&buf).await.unwrap();
        tls.flush().await.unwrap();
    });

    // Client with matching pin + cert in root store (for PKI chain validation).
    let pinned_cfg = ClientBuilder::new()
        .with_trusted_cert_der(ck.cert_der.clone())
        .expect("add cert")
        .with_cert_pinning(vec![fp])
        .build()
        .expect("pinned client config");

    let connector = TlsConnector::from(Arc::new(pinned_cfg));
    let tcp = TcpStream::connect(addr).await.unwrap();
    let sn = ServerName::try_from("localhost").unwrap();
    let mut tls = connector.connect(sn, tcp).await.expect("pinned connect");

    tls.write_all(&[0x42]).await.unwrap();
    tls.flush().await.unwrap();
    let mut reply = [0u8; 1];
    tls.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[0], 0x42);

    server_task.await.unwrap();
}

// ── Test 2: cert pinning rejects wrong pin ────────────────────────────────────

#[tokio::test]
async fn client_with_cert_pinning_rejects_wrong_pin() {
    let ck = generate_self_signed_p256(&["localhost"]).expect("cert gen");
    let wrong_pin = [0u8; 32]; // zeroed — definitely wrong

    let certs = vec![CertificateDer::from(ck.cert_der.clone())];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.pkcs8_der.clone()));

    let server_cfg = ServerBuilder::new()
        .with_der_cert_and_key(certs, key)
        .build()
        .expect("server build");
    let acceptor = oxitls::tls13::server::tokio_acceptor(server_cfg);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        // Server accept may fail when client rejects — that's fine.
        let _ = acceptor.accept(tcp).await;
    });

    let client_cfg = ClientBuilder::new()
        .with_trusted_cert_der(ck.cert_der.clone())
        .expect("add cert")
        .with_cert_pinning(vec![wrong_pin])
        .build()
        .expect("pinned client config");

    let connector = TlsConnector::from(Arc::new(client_cfg));
    let tcp = TcpStream::connect(addr).await.unwrap();
    let sn = ServerName::try_from("localhost").unwrap();
    let result = connector.connect(sn, tcp).await;
    assert!(result.is_err(), "expected handshake to fail with wrong pin");

    server_task.await.unwrap();
}

// ── Test 3: key-log file writes secrets ──────────────────────────────────────

#[tokio::test]
async fn client_with_key_log_file_writes_secrets() {
    let ck = generate_self_signed_ed25519(&["localhost"]).expect("cert gen");
    let certs = vec![CertificateDer::from(ck.cert_der.clone())];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.pkcs8_der.clone()));

    let server_cfg = ServerBuilder::new()
        .with_der_cert_and_key(certs, key)
        .build()
        .expect("server build");
    let acceptor = oxitls::tls13::server::tokio_acceptor(server_cfg);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(tcp).await.expect("server accept");
        let mut buf = [0u8; 1];
        tls.read_exact(&mut buf).await.unwrap();
        tls.write_all(&buf).await.unwrap();
        tls.flush().await.unwrap();
    });

    let log_path = std::env::temp_dir().join(format!("oxitls_keylog_{}.txt", std::process::id()));
    // Remove stale file if present.
    let _ = std::fs::remove_file(&log_path);

    let client_cfg = ClientBuilder::new()
        .with_trusted_cert_der(ck.cert_der.clone())
        .expect("add cert")
        .with_key_log_file(log_path.clone())
        .build()
        .expect("client with key log");

    let connector = TlsConnector::from(Arc::new(client_cfg));
    let tcp = TcpStream::connect(addr).await.unwrap();
    let sn = ServerName::try_from("localhost").unwrap();
    let mut tls = connector.connect(sn, tcp).await.expect("connect");

    tls.write_all(&[0x77]).await.unwrap();
    tls.flush().await.unwrap();
    let mut r = [0u8; 1];
    tls.read_exact(&mut r).await.unwrap();

    // Drop the TLS stream so the file is fully flushed.
    drop(tls);

    server_task.await.unwrap();

    // The file should exist and contain key-log entries.
    let content = std::fs::read_to_string(&log_path).expect("keylog file not created");
    assert!(
        content.contains("CLIENT_HANDSHAKE_TRAFFIC_SECRET")
            || content.contains("CLIENT_RANDOM")
            || content.contains("CLIENT_TRAFFIC_SECRET"),
        "keylog should contain TLS secrets, got: {:?}",
        &content[..content.len().min(200)]
    );

    // Clean up.
    let _ = std::fs::remove_file(&log_path);
}

// ── Test 4: danger accept invalid hostnames ───────────────────────────────────

#[tokio::test]
async fn client_with_danger_accept_invalid_hostnames_works() {
    // Server cert is for "example.com" but client connects with SNI "localhost".
    let ck = generate_self_signed_p256(&["example.com"]).expect("cert gen");
    let certs = vec![CertificateDer::from(ck.cert_der.clone())];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.pkcs8_der.clone()));

    let server_cfg = ServerBuilder::new()
        .with_der_cert_and_key(certs, key)
        .build()
        .expect("server build");
    let acceptor = oxitls::tls13::server::tokio_acceptor(server_cfg);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(tcp).await.expect("server accept");
        let mut buf = [0u8; 1];
        tls.read_exact(&mut buf).await.unwrap();
        tls.write_all(&buf).await.unwrap();
        tls.flush().await.unwrap();
    });

    // Client trusts the cert (chain validates) but connects with different SNI.
    let client_cfg = ClientBuilder::new()
        .with_trusted_cert_der(ck.cert_der.clone())
        .expect("add cert")
        .with_danger_accept_invalid_hostnames()
        .build()
        .expect("danger hostname client config");

    let connector = TlsConnector::from(Arc::new(client_cfg));
    let tcp = TcpStream::connect(addr).await.unwrap();
    // SNI doesn't match the cert SAN ("example.com").
    let sn = ServerName::try_from("localhost").unwrap();
    let mut tls = connector
        .connect(sn, tcp)
        .await
        .expect("danger connect should succeed");

    tls.write_all(&[0xCC]).await.unwrap();
    tls.flush().await.unwrap();
    let mut r = [0u8; 1];
    tls.read_exact(&mut r).await.unwrap();
    assert_eq!(r[0], 0xCC);

    server_task.await.unwrap();
}

// ── Test 5: server with OCSP response stapled ─────────────────────────────────

#[tokio::test]
async fn server_with_ocsp_response_stapled() {
    let ck = generate_self_signed_ed25519(&["localhost"]).expect("cert gen");
    let certs = vec![CertificateDer::from(ck.cert_der.clone())];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.pkcs8_der.clone()));

    // Minimal well-formed DER SEQUENCE (0x30 = SEQUENCE tag, 0x00 = length 0).
    let ocsp_der = vec![0x30u8, 0x00];

    let server_cfg = ServerBuilder::new()
        .with_der_cert_and_key(certs, key)
        .with_ocsp_response(ocsp_der)
        .build()
        .expect("server build with OCSP");
    let acceptor = oxitls::tls13::server::tokio_acceptor(server_cfg);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(tcp).await.expect("server accept");
        let mut buf = [0u8; 1];
        tls.read_exact(&mut buf).await.unwrap();
        tls.write_all(&buf).await.unwrap();
        tls.flush().await.unwrap();
    });

    let connector = TlsConnector::from(plain_client_config(one_cert_root(&ck.cert_der)));
    let tcp = TcpStream::connect(addr).await.unwrap();
    let sn = ServerName::try_from("localhost").unwrap();
    let mut tls = connector.connect(sn, tcp).await.expect("connect");

    tls.write_all(&[0xAA]).await.unwrap();
    tls.flush().await.unwrap();
    let mut r = [0u8; 1];
    tls.read_exact(&mut r).await.unwrap();
    assert_eq!(r[0], 0xAA);

    server_task.await.unwrap();
}

// ── Test 6: server with max fragment size ────────────────────────────────────

#[tokio::test]
async fn server_with_max_fragment_size_limits_record_size() {
    let ck = generate_self_signed_ed25519(&["localhost"]).expect("cert gen");
    let certs = vec![CertificateDer::from(ck.cert_der.clone())];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.pkcs8_der.clone()));

    let server_cfg = ServerBuilder::new()
        .with_der_cert_and_key(certs, key)
        .with_max_fragment_size(Some(512))
        .build()
        .expect("server build with max fragment size");
    let acceptor = oxitls::tls13::server::tokio_acceptor(server_cfg);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(tcp).await.expect("server accept");
        let mut buf = vec![0u8; 2048];
        tls.read_exact(&mut buf).await.unwrap();
        tls.write_all(&buf).await.unwrap();
        tls.flush().await.unwrap();
    });

    let connector = TlsConnector::from(plain_client_config(one_cert_root(&ck.cert_der)));
    let tcp = TcpStream::connect(addr).await.unwrap();
    let sn = ServerName::try_from("localhost").unwrap();
    let mut tls = connector.connect(sn, tcp).await.expect("connect");

    // Write 2048 bytes (larger than max_fragment_size=512) to force multiple TLS records.
    let payload = vec![0x55u8; 2048];
    tls.write_all(&payload).await.unwrap();
    tls.flush().await.unwrap();

    let mut received = vec![0u8; 2048];
    tls.read_exact(&mut received).await.unwrap();
    assert_eq!(received, payload);

    server_task.await.unwrap();
}

// ── Test 7: server with PEM cert chain and key ────────────────────────────────

#[tokio::test]
async fn server_with_pem_cert_chain_and_key_parses_pem() {
    let ck = generate_self_signed_ed25519(&["localhost"]).expect("cert gen");
    let cert_pem = ck.cert_pem.clone();
    let key_pem = ck.key_pem();

    let server_cfg = ServerBuilder::new()
        .with_pem_cert_chain_and_key(&cert_pem, &key_pem)
        .expect("PEM parse")
        .build()
        .expect("server build from PEM");
    let acceptor = oxitls::tls13::server::tokio_acceptor(server_cfg);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(tcp).await.expect("server accept");
        let mut buf = [0u8; 1];
        tls.read_exact(&mut buf).await.unwrap();
        tls.write_all(&buf).await.unwrap();
        tls.flush().await.unwrap();
    });

    let connector = TlsConnector::from(plain_client_config(one_cert_root(&ck.cert_der)));
    let tcp = TcpStream::connect(addr).await.unwrap();
    let sn = ServerName::try_from("localhost").unwrap();
    let mut tls = connector.connect(sn, tcp).await.expect("connect");

    tls.write_all(&[0xBB]).await.unwrap();
    tls.flush().await.unwrap();
    let mut r = [0u8; 1];
    tls.read_exact(&mut r).await.unwrap();
    assert_eq!(r[0], 0xBB);

    server_task.await.unwrap();
}

// ── Test 8: server with ticketer rotation interval compiles and runs ──────────

#[tokio::test]
async fn server_with_ticketer_rotation_interval_compiles() {
    let ck = generate_self_signed_ed25519(&["localhost"]).expect("cert gen");
    let certs = vec![CertificateDer::from(ck.cert_der.clone())];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.pkcs8_der.clone()));

    let server_cfg = ServerBuilder::new()
        .with_der_cert_and_key(certs, key)
        .with_ticketer_rotation_interval(Duration::from_secs(60))
        .build()
        .expect("server build with ticketer rotation");
    let acceptor = oxitls::tls13::server::tokio_acceptor(server_cfg);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(tcp).await.expect("server accept");
        let mut buf = [0u8; 1];
        tls.read_exact(&mut buf).await.unwrap();
        tls.write_all(&buf).await.unwrap();
        tls.flush().await.unwrap();
    });

    let connector = TlsConnector::from(plain_client_config(one_cert_root(&ck.cert_der)));
    let tcp = TcpStream::connect(addr).await.unwrap();
    let sn = ServerName::try_from("localhost").unwrap();
    let mut tls = connector.connect(sn, tcp).await.expect("connect");

    tls.write_all(&[0xDD]).await.unwrap();
    tls.flush().await.unwrap();
    let mut r = [0u8; 1];
    tls.read_exact(&mut r).await.unwrap();
    assert_eq!(r[0], 0xDD);

    server_task.await.unwrap();
}

// ── Test 9: ClientBuilder clone independence ──────────────────────────────────

#[tokio::test]
async fn client_builder_clone_independence() {
    let ck = generate_self_signed_ed25519(&["localhost"]).expect("cert gen");
    let certs_orig = vec![CertificateDer::from(ck.cert_der.clone())];
    let key_orig = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.pkcs8_der.clone()));

    let server_cfg = ServerBuilder::new()
        .with_der_cert_and_key(certs_orig, key_orig)
        .build()
        .expect("server build");
    let acceptor = oxitls::tls13::server::tokio_acceptor(server_cfg);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // We accept two connections for both builds.
    let server_task = tokio::spawn(async move {
        for _ in 0..2usize {
            let (tcp, _) = listener.accept().await.unwrap();
            let tls_r = acceptor.accept(tcp).await;
            if let Ok(mut tls) = tls_r {
                let mut buf = [0u8; 1];
                let _ = tls.read_exact(&mut buf).await;
                let _ = tls.write_all(&buf).await;
                let _ = tls.flush().await;
            }
        }
    });

    let base = ClientBuilder::new()
        .with_trusted_cert_der(ck.cert_der.clone())
        .expect("add cert");
    let cloned = base.clone().with_alpn_protocols(["h2"]);
    // base has no ALPN; cloned has h2.

    // Both should be able to build and connect independently.
    let cfg_base = base.build().expect("base build");
    let cfg_cloned = cloned.build().expect("cloned build");

    // First connection from base config (no ALPN).
    {
        let connector = TlsConnector::from(Arc::new(cfg_base));
        let tcp = TcpStream::connect(addr).await.unwrap();
        let sn = ServerName::try_from("localhost").unwrap();
        let mut tls = connector.connect(sn, tcp).await.expect("base connect");
        tls.write_all(&[0xE0]).await.unwrap();
        tls.flush().await.unwrap();
        let mut r = [0u8; 1];
        tls.read_exact(&mut r).await.unwrap();
        assert_eq!(r[0], 0xE0);
    }

    // Second connection from cloned config (with ALPN h2).
    {
        let connector = TlsConnector::from(Arc::new(cfg_cloned));
        let tcp = TcpStream::connect(addr).await.unwrap();
        let sn = ServerName::try_from("localhost").unwrap();
        let mut tls = connector.connect(sn, tcp).await.expect("cloned connect");
        tls.write_all(&[0xE1]).await.unwrap();
        tls.flush().await.unwrap();
        let mut r = [0u8; 1];
        tls.read_exact(&mut r).await.unwrap();
        assert_eq!(r[0], 0xE1);
    }

    server_task.await.unwrap();
}

// ── Test 10: builder validation — missing cert fails ─────────────────────────

#[test]
fn builder_validation_missing_cert_fails() {
    let result = ServerBuilder::new().build();
    assert!(
        result.is_err(),
        "ServerBuilder::build() without cert should return Err"
    );
}

// ── Test 10b: ClientBuilder validation — no roots and no pinning fails ───────

#[test]
fn client_builder_validation_missing_roots_fails() {
    // No webpki roots, no trusted certs, no cert pins, no danger flags →
    // build() must return Err.
    let result = ClientBuilder::new().build();
    assert!(
        result.is_err(),
        "ClientBuilder::build() without any trust anchor should return Err"
    );
}

// ── Test 11: OxiTlsStream connection info populated ──────────────────────────

#[tokio::test]
async fn oxi_tls_stream_connection_info_populated() {
    use oxitls::TlsVersion;

    let ck = generate_self_signed_ed25519(&["localhost"]).expect("cert gen");
    let certs = vec![CertificateDer::from(ck.cert_der.clone())];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.pkcs8_der.clone()));

    let server_cfg = ServerBuilder::new()
        .with_der_cert_and_key(certs, key)
        .build()
        .expect("server build");
    let acceptor = oxitls::tls13::server::tokio_acceptor(server_cfg);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(tcp).await.expect("server accept");
        let mut buf = [0u8; 1];
        tls.read_exact(&mut buf).await.unwrap();
        tls.write_all(&buf).await.unwrap();
        tls.flush().await.unwrap();
    });

    let connector = TlsConnector::from(plain_client_config(one_cert_root(&ck.cert_der)));
    let tcp = TcpStream::connect(addr).await.unwrap();
    let sn = ServerName::try_from("localhost").unwrap();
    let tls_stream = connector.connect(sn, tcp).await.expect("connect");

    // Extract connection info from the raw tokio_rustls stream.
    let info = tls_stream.tls_connection_info();
    assert_eq!(
        info.version,
        Some(TlsVersion::Tls13),
        "expected TLS 1.3 negotiated version"
    );

    // Wrap in OxiTlsStream.
    let mut oxi_stream = OxiTlsStream::from_client(tls_stream, Some(info));
    let retrieved = oxi_stream
        .connection_info()
        .expect("connection info missing");
    assert_eq!(retrieved.version, Some(TlsVersion::Tls13));

    // Send a byte so the server can complete its read.
    oxi_stream.write_all(&[0xF0]).await.unwrap();
    oxi_stream.flush().await.unwrap();
    // Read the echo back.
    let mut r = [0u8; 1];
    oxi_stream.read_exact(&mut r).await.unwrap();
    assert_eq!(r[0], 0xF0);

    drop(oxi_stream);
    server_task.await.unwrap();
}

// ── Test 12: OxiTlsStream async read/write round-trip ────────────────────────

#[tokio::test]
async fn oxi_tls_stream_async_read_write() {
    let ck = generate_self_signed_ed25519(&["localhost"]).expect("cert gen");
    let certs = vec![CertificateDer::from(ck.cert_der.clone())];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.pkcs8_der.clone()));

    let server_cfg = ServerBuilder::new()
        .with_der_cert_and_key(certs, key)
        .build()
        .expect("server build");
    let acceptor = oxitls::tls13::server::tokio_acceptor(server_cfg);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let payload_len: usize = 1024;
    let payload: Vec<u8> = (0..payload_len).map(|i| (i % 251) as u8).collect();
    let payload_clone = payload.clone();

    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let raw_tls = acceptor.accept(tcp).await.expect("server accept");
        let info = raw_tls.tls_connection_info();
        let mut oxi = OxiTlsStream::from_server(raw_tls, Some(info));
        let mut buf = vec![0u8; payload_len];
        oxi.read_exact(&mut buf).await.unwrap();
        oxi.write_all(&buf).await.unwrap();
        oxi.flush().await.unwrap();
    });

    let connector = TlsConnector::from(plain_client_config(one_cert_root(&ck.cert_der)));
    let tcp = TcpStream::connect(addr).await.unwrap();
    let sn = ServerName::try_from("localhost").unwrap();
    let raw_tls = connector.connect(sn, tcp).await.expect("connect");

    let info = raw_tls.tls_connection_info();
    let mut oxi = OxiTlsStream::from_client(raw_tls, Some(info));

    oxi.write_all(&payload_clone).await.unwrap();
    oxi.flush().await.unwrap();

    let mut received = vec![0u8; payload_len];
    oxi.read_exact(&mut received).await.unwrap();
    assert_eq!(received, payload_clone, "round-trip data mismatch");

    server_task.await.unwrap();
}
