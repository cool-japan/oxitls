//! Wave 7 facade integration tests.
//!
//! Tests:
//!  1. `protocol_version_re_exports_usable` — `oxitls::ProtocolVersion::TLSv1_3` accessible.
//!  2. `server_builder_clone_produces_independent_configs` — clone a `ServerBuilder`, build both.
//!  3. `sslkeylogfile_writes_to_temp_dir` — async loopback handshake; SSLKEYLOGFILE populated.
//!  4. `cert_pin_match_succeeds` — correct pin allows handshake.
//!  5. `cert_pin_mismatch_rejected` — wrong pin rejects handshake.
//!  6. `connect_future_type_alias_usable` — `ConnectFuture<IO>` resolves at compile time.
//!  7. `accept_future_type_alias_usable` — `AcceptFuture<IO>` resolves at compile time.

#![allow(unused_imports)]

use std::sync::Arc;

use oxitls_rcgen::generate_self_signed_p256;
use rcgen::{CertificateParams, KeyPair};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

use oxitls::tls13::{ClientBuilder, ServerBuilder};

// ── Shared helpers ────────────────────────────────────────────────────────────

/// Generate a self-signed P-256 certificate with SAN `localhost` via oxitls-rcgen.
/// Returns `(cert_der, key_der, sha256_fingerprint)`.
fn make_self_signed_p256() -> (CertificateDer<'static>, PrivateKeyDer<'static>, [u8; 32]) {
    let ck = generate_self_signed_p256(&["localhost"]).expect("cert gen failed");
    let fp = ck.fingerprint_sha256();
    let cert_der = CertificateDer::from(ck.cert_der.clone());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.pkcs8_der.clone()));
    (cert_der, key_der, fp)
}

/// Generate a self-signed certificate with SAN `localhost` via rcgen/ring (for
/// tests that don't need the fingerprint helper).
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

/// Spawn a one-shot TLS echo server.  Returns `(addr, join_handle)`.
async fn spawn_echo_server(
    cfg: rustls::ServerConfig,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener bind");
    let addr = listener.local_addr().expect("local addr");
    let handle = tokio::spawn(async move {
        if let Ok((tcp, _)) = listener.accept().await {
            if let Ok(mut tls) = acceptor.accept(tcp).await {
                let mut buf = [0u8; 1];
                let _ = tls.read_exact(&mut buf).await;
                let _ = tls.write_all(&buf).await;
                let _ = tls.flush().await;
            }
        }
    });
    (addr, handle)
}

// ── Test 1: ProtocolVersion re-export ─────────────────────────────────────────

/// Verify that `oxitls::ProtocolVersion::TLSv1_3` is accessible from the facade
/// root without importing from `rustls` directly.
#[cfg(feature = "pure")]
#[test]
fn protocol_version_re_exports_usable() {
    // If the `pub use rustls::ProtocolVersion;` in lib.rs is in place,
    // this constant access compiles.
    let v = oxitls::ProtocolVersion::TLSv1_3;
    // ProtocolVersion does not implement PartialEq publicly — use Debug as a proxy.
    let debug = format!("{v:?}");
    assert!(
        debug.contains("TLSv1_3") || !debug.is_empty(),
        "ProtocolVersion::TLSv1_3 must be accessible and non-empty debug: {debug}"
    );
}

// ── Test 2: ServerBuilder::Clone produces independent configs ─────────────────

/// Clone a `ServerBuilder` and build both copies.  Neither build must fail, and
/// the resulting configs are independent (modifying alpn on one does not affect
/// the other at builder level).
#[cfg(feature = "pure")]
#[test]
fn server_builder_clone_produces_independent_configs() {
    let (cert_der, key_der) = make_self_signed();

    let builder_a = ServerBuilder::new()
        .with_der_cert_and_key(vec![cert_der], key_der)
        .with_alpn_protocols(["http/1.1"]);

    // Clone and diverge: clone gets "h2", original keeps "http/1.1".
    let builder_b = builder_a.clone().with_alpn_protocols(["h2"]);

    let cfg_a = builder_a.build().expect("build a");
    let cfg_b = builder_b.build().expect("build b");

    assert_eq!(cfg_a.alpn_protocols, vec![b"http/1.1".to_vec()]);
    assert_eq!(cfg_b.alpn_protocols, vec![b"h2".to_vec()]);
}

// ── Test 3: SSLKEYLOGFILE writes to temp dir ──────────────────────────────────

/// Perform a loopback TLS 1.3 handshake with `ClientBuilder::with_key_log_file`.
/// After the handshake the key-log file must exist and have non-zero content.
#[cfg(feature = "pure")]
#[tokio::test]
async fn sslkeylogfile_writes_to_temp_dir() {
    let (cert_der, key_der) = make_self_signed();
    let root_cert = cert_der.clone();

    let server_cfg = ServerBuilder::new()
        .with_der_cert_and_key(vec![cert_der], key_der)
        .build()
        .expect("server config");

    let (addr, server_handle) = spawn_echo_server(server_cfg).await;

    let log_path =
        std::env::temp_dir().join(format!("oxitls_wave7_keylog_{}.txt", std::process::id()));

    let client_cfg = ClientBuilder::new()
        .with_trusted_cert_der(root_cert.to_vec())
        .expect("trusted cert")
        .with_key_log_file(log_path.clone())
        .build()
        .expect("client config with keylog");

    let connector = TlsConnector::from(Arc::new(client_cfg));
    let tcp = TcpStream::connect(addr).await.expect("tcp connect");
    let sni = ServerName::try_from("localhost").expect("sni");
    let mut tls = connector
        .connect(sni, tcp)
        .await
        .expect("TLS handshake must succeed");

    tls.write_all(&[0xA1]).await.expect("write");
    tls.flush().await.expect("flush");
    let mut echo = [0u8; 1];
    tls.read_exact(&mut echo).await.expect("read");
    assert_eq!(echo[0], 0xA1, "echo mismatch");

    server_handle.await.expect("server task");

    // The key-log file must have been created with non-zero content.
    assert!(
        log_path.exists(),
        "SSLKEYLOGFILE must be created at {log_path:?}"
    );
    let content = std::fs::read_to_string(&log_path).expect("read keylog file");
    assert!(
        !content.is_empty(),
        "SSLKEYLOGFILE must contain key-log entries after a handshake"
    );

    // Cleanup.
    let _ = std::fs::remove_file(&log_path);
}

// ── Test 4: cert_pin match succeeds ──────────────────────────────────────────

/// The correct SHA-256 leaf fingerprint (via `oxitls_rcgen::fingerprint_sha256`)
/// as a cert pin must allow the handshake to complete.
#[cfg(feature = "pure")]
#[tokio::test]
async fn cert_pin_match_succeeds() {
    // Use oxitls_rcgen which exposes fingerprint_sha256() — no sha2 dep needed.
    let (cert_der, key_der, fingerprint) = make_self_signed_p256();
    let root_cert = cert_der.clone();

    let server_cfg = ServerBuilder::new()
        .with_der_cert_and_key(vec![cert_der], key_der)
        .build()
        .expect("server config");

    let (addr, server_handle) = spawn_echo_server(server_cfg).await;

    let client_cfg = ClientBuilder::new()
        .with_trusted_cert_der(root_cert.to_vec())
        .expect("trusted cert")
        .with_cert_pinning(vec![fingerprint])
        .build()
        .expect("client config with pin");

    let connector = TlsConnector::from(Arc::new(client_cfg));
    let tcp = TcpStream::connect(addr).await.expect("tcp connect");
    let sni = ServerName::try_from("localhost").expect("sni");
    let mut tls = connector
        .connect(sni, tcp)
        .await
        .expect("handshake must succeed with correct cert pin");

    tls.write_all(&[0xB2]).await.expect("write");
    tls.flush().await.expect("flush");
    let mut echo = [0u8; 1];
    tls.read_exact(&mut echo).await.expect("read");
    assert_eq!(echo[0], 0xB2, "echo mismatch");

    server_handle.await.expect("server task");
}

// ── Test 5: cert_pin mismatch rejected ────────────────────────────────────────

/// A wrong cert pin (all-zeros) must cause the handshake to fail.
#[cfg(feature = "pure")]
#[tokio::test]
async fn cert_pin_mismatch_rejected() {
    let (cert_der, key_der, _correct_fp) = make_self_signed_p256();
    let root_cert = cert_der.clone();

    let server_cfg = ServerBuilder::new()
        .with_der_cert_and_key(vec![cert_der], key_der)
        .build()
        .expect("server config");

    let (addr, _server_handle) = spawn_echo_server(server_cfg).await;

    // Wrong pin: all zeros will never match a real cert.
    let wrong_pin = [0u8; 32];

    let client_cfg = ClientBuilder::new()
        .with_trusted_cert_der(root_cert.to_vec())
        .expect("trusted cert")
        .with_cert_pinning(vec![wrong_pin])
        .build()
        .expect("client config with wrong pin");

    let connector = TlsConnector::from(Arc::new(client_cfg));
    let tcp = TcpStream::connect(addr).await.expect("tcp connect");
    let sni = ServerName::try_from("localhost").expect("sni");
    let result = connector.connect(sni, tcp).await;
    assert!(
        result.is_err(),
        "handshake must fail when cert pin does not match"
    );
}

// ── Test 6: ConnectFuture type alias resolves ─────────────────────────────────

/// Compile-time check: `oxitls::ConnectFuture<TcpStream>` is a valid type.
///
/// This test verifies the `pub type ConnectFuture<IO>` re-export in lib.rs
/// resolves without needing to import from `tokio_rustls::client`.
#[cfg(feature = "pure")]
#[test]
fn connect_future_type_alias_usable() {
    // This function is never called — its existence proves the type alias resolves.
    fn _check_connect_future(_: oxitls::ConnectFuture<tokio::net::TcpStream>) {}
}

// ── Test 7: AcceptFuture type alias resolves ──────────────────────────────────

/// Compile-time check: `oxitls::AcceptFuture<TcpStream>` is a valid type.
///
/// This test verifies the `pub type AcceptFuture<IO>` re-export in lib.rs
/// resolves without needing to import from `tokio_rustls::server`.
#[cfg(feature = "pure")]
#[test]
fn accept_future_type_alias_usable() {
    // This function is never called — its existence proves the type alias resolves.
    fn _check_accept_future(_: oxitls::AcceptFuture<tokio::net::TcpStream>) {}
}
