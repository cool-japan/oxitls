//! Wave 4 Slice C — 0-RTT early data integration tests.
//!
//! These tests verify:
//! - `ClientBuilder::with_early_data()` builds successfully and sets
//!   `ClientConfig::enable_early_data = true`
//! - `ServerBuilder::with_max_early_data_size(n)` builds successfully and
//!   sets `ServerConfig::max_early_data_size = n`
//! - The normal TLS 1.3 handshake still completes when these flags are set
//!
//! ## Deviation note
//! `OxiTlsStream::early_data()` accessor (task item 4) is **not implemented**
//! because `OxiTlsStream<S>` was not yet created (TODO.md item still `[ ]`).
//! The tokio-rustls 0.26 `client::TlsStream` also does not expose a public
//! `early_data()` method — the 0-RTT write path is handled internally inside
//! the `EarlyData` state machine (requires the `early-data` cargo feature).
//! Actual 0-RTT round-trips also require session ticket resumption which needs
//! a prior connected session; that is tested by dedicated bench/integration
//! tooling rather than unit tests.

use std::sync::Arc;

use rcgen::{CertificateParams, KeyPair};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

use oxitls::tls13::{ClientBuilder, ServerBuilder};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Generate a self-signed Ed25519 cert+key via rcgen (ring dev-dep path).
fn make_self_signed() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let kp = KeyPair::generate().expect("keygen failed");
    let cert = CertificateParams::new(vec!["localhost".into()])
        .expect("CertificateParams::new failed")
        .self_signed(&kp)
        .expect("self-sign failed");
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(kp.serialize_der().into());
    (cert_der, key_der)
}

/// Build a pure-Rust TLS 1.3 `ClientConfig` trusting one DER-encoded cert.
fn make_client_config(trust_root: &CertificateDer<'static>) -> Arc<ClientConfig> {
    let provider = oxitls_adapter_rustls_rustcrypto::pure_provider();
    let mut roots = RootCertStore::empty();
    roots.add(trust_root.clone()).expect("add root");
    Arc::new(
        ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3 not supported by provider")
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// Spawn a minimal TLS 1.3 echo server that accepts one connection, bounces
/// one byte, then returns. Returns the local address.
async fn spawn_echo_server(
    config: ServerConfig,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener bind failed");
    let addr = listener.local_addr().expect("local_addr");
    let handle = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept");
        let mut tls = acceptor.accept(tcp).await.expect("tls accept");
        let mut buf = [0u8; 1];
        tls.read_exact(&mut buf).await.expect("server read");
        tls.write_all(&buf).await.expect("server write");
        tls.flush().await.expect("server flush");
    });
    (addr, handle)
}

// ---------------------------------------------------------------------------
// Test 1: ClientBuilder::with_early_data() builds without error
// ---------------------------------------------------------------------------

#[tokio::test]
async fn with_early_data_flag_sets_client_config() {
    // Verify that the builder succeeds and the config has the flag set.
    let config = ClientBuilder::new()
        .with_webpki_roots()
        .with_early_data()
        .build()
        .expect("build with early_data should succeed");

    assert!(
        config.enable_early_data,
        "ClientConfig::enable_early_data should be true after with_early_data()"
    );
}

// ---------------------------------------------------------------------------
// Test 2: with_early_data() is false by default (guard against regression)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn early_data_disabled_by_default() {
    let config = ClientBuilder::new()
        .with_webpki_roots()
        .build()
        .expect("build should succeed");

    assert!(
        !config.enable_early_data,
        "ClientConfig::enable_early_data should default to false"
    );
}

// ---------------------------------------------------------------------------
// Test 3: ServerBuilder::with_max_early_data_size() sets the field
// ---------------------------------------------------------------------------

#[tokio::test]
async fn max_early_data_size_sets_server_config() {
    let (cert_der, key_der) = make_self_signed();
    let config = ServerBuilder::new()
        .with_der_cert_and_key(vec![cert_der], key_der)
        .with_max_early_data_size(16_384)
        .build()
        .expect("server build with max_early_data_size should succeed");

    assert_eq!(
        config.max_early_data_size, 16_384,
        "ServerConfig::max_early_data_size should be 16384"
    );
}

// ---------------------------------------------------------------------------
// Test 4: max_early_data_size defaults to 0 (rustls default — disabled)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn max_early_data_size_defaults_to_zero() {
    let (cert_der, key_der) = make_self_signed();
    let config = ServerBuilder::new()
        .with_der_cert_and_key(vec![cert_der], key_der)
        .build()
        .expect("server build should succeed");

    assert_eq!(
        config.max_early_data_size, 0,
        "ServerConfig::max_early_data_size should default to 0 (disabled)"
    );
}

// ---------------------------------------------------------------------------
// Test 5: Normal TLS 1.3 handshake succeeds with early_data enabled on client
// ---------------------------------------------------------------------------

#[tokio::test]
async fn handshake_succeeds_with_client_early_data_flag() {
    let (cert_der, key_der) = make_self_signed();
    let root_cert = cert_der.clone();

    let server_cfg = ServerBuilder::new()
        .with_der_cert_and_key(vec![cert_der], key_der)
        .build()
        .expect("server config failed");

    let (addr, server_handle) = spawn_echo_server(server_cfg).await;

    // Build client config with early_data enabled via our builder.
    let client_cfg_built = ClientBuilder::new()
        .with_trusted_cert_der(root_cert.to_vec())
        .expect("trusted cert")
        .with_early_data()
        .build()
        .expect("client config failed");

    assert!(client_cfg_built.enable_early_data);

    let connector = TlsConnector::from(Arc::new(client_cfg_built));
    let tcp = TcpStream::connect(addr).await.expect("tcp connect");
    let server_name = ServerName::try_from("localhost").expect("server name");
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .expect("tls connect with early_data flag should succeed");

    tls.write_all(&[0xC3]).await.expect("write");
    tls.flush().await.expect("flush");
    let mut reply = [0u8; 1];
    tls.read_exact(&mut reply).await.expect("read");
    assert_eq!(reply[0], 0xC3, "echo mismatch");

    server_handle.await.expect("server task");
}

// ---------------------------------------------------------------------------
// Test 6: Normal TLS 1.3 handshake succeeds with max_early_data_size on server
// ---------------------------------------------------------------------------

#[tokio::test]
async fn handshake_succeeds_with_server_max_early_data_size() {
    let (cert_der, key_der) = make_self_signed();
    let root_cert = cert_der.clone();

    let server_cfg = ServerBuilder::new()
        .with_der_cert_and_key(vec![cert_der], key_der)
        .with_max_early_data_size(16_384)
        .build()
        .expect("server config with max_early_data_size failed");

    assert_eq!(server_cfg.max_early_data_size, 16_384);

    let (addr, server_handle) = spawn_echo_server(server_cfg).await;

    let client_cfg = make_client_config(&root_cert);
    let connector = TlsConnector::from(client_cfg);
    let tcp = TcpStream::connect(addr).await.expect("tcp connect");
    let server_name = ServerName::try_from("localhost").expect("server name");
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .expect("tls connect with server early_data should succeed");

    tls.write_all(&[0x42]).await.expect("write");
    tls.flush().await.expect("flush");
    let mut reply = [0u8; 1];
    tls.read_exact(&mut reply).await.expect("read");
    assert_eq!(reply[0], 0x42, "echo mismatch");

    server_handle.await.expect("server task");
}

// ---------------------------------------------------------------------------
// Test 7: Both early_data flags set — handshake completes (no 0-RTT session
//         ticket means the first connection is a full handshake regardless)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn both_early_data_flags_set_handshake_completes() {
    let (cert_der, key_der) = make_self_signed();
    let root_cert = cert_der.clone();

    let server_cfg = ServerBuilder::new()
        .with_der_cert_and_key(vec![cert_der], key_der)
        .with_max_early_data_size(8_192)
        .build()
        .expect("server config failed");

    let (addr, server_handle) = spawn_echo_server(server_cfg).await;

    let client_cfg = ClientBuilder::new()
        .with_trusted_cert_der(root_cert.to_vec())
        .expect("trusted cert")
        .with_early_data()
        .build()
        .expect("client config failed");

    let connector = TlsConnector::from(Arc::new(client_cfg));
    let tcp = TcpStream::connect(addr).await.expect("tcp connect");
    let server_name = ServerName::try_from("localhost").expect("server name");
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .expect("tls connect");

    tls.write_all(&[0x77]).await.expect("write");
    tls.flush().await.expect("flush");
    let mut reply = [0u8; 1];
    tls.read_exact(&mut reply).await.expect("read");
    assert_eq!(reply[0], 0x77, "echo mismatch");

    server_handle.await.expect("server task");
}
