//! Wave 13 ECH facade tests.
//!
//! Tests:
//!  1. `ech_grease_builder_compiles_and_builds` — GREASE ECH mode builds a valid ClientConfig.
//!  2. `ech_config_list_invalid_returns_error` — malformed ECHConfigList returns TlsError.
//!  3. `ech_grease_handshake_reports_grease_status` — loopback handshake; ech_status() == Grease.
//!
//! The full `Enable`/`Accepted` path is not tested here because rustls does not
//! provide a built-in ECH server; that path requires a real ECH-capable TLS server
//! and would require integration with an external test infrastructure.

#![allow(unused_imports)]

use std::sync::Arc;

use rcgen::{CertificateParams, KeyPair};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

use oxitls::tls13::{ClientBuilder, ServerBuilder};

// ── Test helpers ──────────────────────────────────────────────────────────────

/// Generate a self-signed certificate with SAN `localhost` via rcgen/ring.
#[cfg(feature = "ech")]
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
#[cfg(feature = "ech")]
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

// ── Test 1: GREASE ECH builder compiles and builds ────────────────────────────

/// Verify that `with_ech_grease()` produces a valid `ClientConfig` (no panic, no error).
#[cfg(feature = "ech")]
#[test]
fn ech_grease_builder_compiles_and_builds() {
    let config = ClientBuilder::new()
        .with_ech_grease()
        .with_danger_accept_invalid_certs()
        .build();
    assert!(
        config.is_ok(),
        "GREASE ECH build failed: {:?}",
        config.err()
    );
}

// ── Test 2: invalid ECHConfigList returns error ───────────────────────────────

/// Verify that `with_ech_config_list` with random bytes returns `TlsError::InvalidConfig`.
#[cfg(feature = "ech")]
#[test]
fn ech_config_list_invalid_returns_error() {
    let result = ClientBuilder::new()
        .with_danger_accept_invalid_certs()
        .with_ech_config_list(b"not a valid ech config list".to_vec());
    assert!(
        result.is_err(),
        "Expected error for malformed ECHConfigList, but got Ok"
    );
}

// ── Test 3: GREASE handshake reports EchStatus::Grease ───────────────────────

/// Perform a loopback TLS 1.3 handshake with `with_ech_grease()`.
/// After the handshake `OxiTlsStream::ech_status()` must return `Some(EchStatus::Grease)`.
///
/// The server is a plain TLS server; it does not support ECH.  The client sends
/// a GREASE ECH extension which the server silently ignores, and the status on
/// the client side after the handshake is `EchStatus::Grease` (not Accepted).
#[cfg(feature = "ech")]
#[tokio::test]
async fn ech_grease_handshake_reports_grease_status() {
    let (cert_der, key_der) = make_self_signed();
    let root_cert = cert_der.clone();

    let server_cfg = ServerBuilder::new()
        .with_der_cert_and_key(vec![cert_der], key_der)
        .build()
        .expect("server config");

    let (addr, server_handle) = spawn_echo_server(server_cfg).await;

    let client_cfg = ClientBuilder::new()
        .with_ech_grease()
        .with_trusted_cert_der(root_cert.to_vec())
        .expect("trusted cert")
        .build()
        .expect("client config with GREASE ECH");

    let connector = TlsConnector::from(Arc::new(client_cfg));
    let tcp = TcpStream::connect(addr).await.expect("tcp connect");
    let sni = ServerName::try_from("localhost").expect("sni");
    let tls_stream = connector
        .connect(sni, tcp)
        .await
        .expect("TLS handshake must succeed with GREASE ECH");

    // Wrap the tokio_rustls stream in OxiTlsStream to exercise ech_status().
    let mut oxi_stream = oxitls::OxiTlsStream::from_client(tls_stream, None);

    // Exchange one byte so the server task can finish cleanly.
    oxi_stream.write_all(&[0xEC]).await.expect("write");
    oxi_stream.flush().await.expect("flush");
    let mut echo = [0u8; 1];
    oxi_stream.read_exact(&mut echo).await.expect("read");
    assert_eq!(echo[0], 0xEC, "echo byte mismatch");

    // Verify ECH status is Grease (the server does not support ECH, so GREASE mode
    // is what gets reported on the client side after a successful handshake where
    // the server did not negotiate ECH).
    let status = oxi_stream.ech_status();
    assert!(
        status.is_some(),
        "ech_status() should return Some on a client stream"
    );
    assert_eq!(
        status,
        Some(oxitls::EchStatus::Grease),
        "Expected EchStatus::Grease after loopback handshake with GREASE ECH mode, got {status:?}"
    );

    server_handle.await.expect("server task");
}
