//! Wave 5 Slice C — 0-RTT early-data byte transit tests.
//!
//! Verifies:
//! 1. `OxiTlsStream::early_data()` returns `None` on a server stream (server
//!    streams never participate in early-data writes).
//! 2. `OxiTlsStream::early_data()` returns `None` on a fresh client stream
//!    with no resumption ticket (first connection — no stored session state).
//! 3. `with_early_data()` builder flag is honoured in the built `ClientConfig`
//!    (replay-protection / max-size guard: the field must be `true` so that
//!    rustls will attempt 0-RTT when a ticket is available; by default it is
//!    `false`, preventing accidental early-data without explicit opt-in).
//!
//! Note: actual 0-RTT round-trips require a prior session ticket.  Byte transit
//! across a 0-RTT session is tested end-to-end in the bench crate once ticket
//! resumption is fully wired.  These unit-level tests focus on the
//! `OxiTlsStream` API surface and the builder flag contract.

use std::sync::Arc;

use rcgen::{CertificateParams, KeyPair};
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

use oxitls::tls13::{ClientBuilder, ServerBuilder};
use oxitls::OxiTlsStream;

// ── Helpers ───────────────────────────────────────────────────────────────────

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
fn make_client_cfg(trust_root: &CertificateDer<'static>) -> Arc<ClientConfig> {
    let provider = oxitls_adapter_rustls_rustcrypto::pure_provider();
    let mut roots = RootCertStore::empty();
    roots.add(trust_root.clone()).expect("add root");
    Arc::new(
        ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3 must be supported")
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// Spawn a minimal TLS 1.3 echo server that accepts one connection, bounces
/// one byte, then returns.  Returns the local address and a join handle.
async fn spawn_echo_server(
    cert_der: CertificateDer<'static>,
    key_der: PrivateKeyDer<'static>,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let srv_cfg = ServerBuilder::new()
        .with_der_cert_and_key(vec![cert_der], key_der)
        .build()
        .expect("server config build");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(srv_cfg));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener bind");
    let addr = listener.local_addr().expect("local_addr");
    let handle = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("server accept");
        let mut tls = acceptor.accept(tcp).await.expect("server tls accept");
        let mut buf = [0u8; 1];
        tls.read_exact(&mut buf).await.expect("server read");
        tls.write_all(&buf).await.expect("server write");
        tls.flush().await.expect("server flush");
    });
    (addr, handle)
}

// ── Test 1: `early_data()` is `None` on a server stream ──────────────────────

/// A server-side `OxiTlsStream` must never expose an early-data writer —
/// only the *client* side writes early data.
#[tokio::test]
async fn early_data_is_none_on_server_stream() {
    let (cert_der, key_der) = make_self_signed();
    let client_cfg = make_client_cfg(&cert_der);

    let srv_cfg = ServerBuilder::new()
        .with_der_cert_and_key(vec![cert_der], key_der)
        .build()
        .expect("server config");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(srv_cfg));

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener bind");
    let addr = listener.local_addr().expect("local_addr");

    // Spawn a task that accepts one connection and checks early_data().
    let server_handle = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept");
        let tls_stream = acceptor.accept(tcp).await.expect("tls accept");
        // Wrap in OxiTlsStream<S> and verify early_data() returns None.
        let mut oxi = OxiTlsStream::from_server(tls_stream, None);
        assert!(
            oxi.early_data().is_none(),
            "server OxiTlsStream::early_data() must always return None"
        );
        // Echo one byte so the client can complete cleanly.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut buf = [0u8; 1];
        let _ = oxi.read_exact(&mut buf).await;
        let _ = oxi.write_all(&buf).await;
        let _ = oxi.flush().await;
    });

    // Client side.
    let connector = TlsConnector::from(client_cfg);
    let tcp = TcpStream::connect(addr).await.expect("client tcp connect");
    let sn = ServerName::try_from("localhost").expect("server name");
    let mut tls = connector.connect(sn, tcp).await.expect("client tls");
    tls.write_all(b"x").await.expect("client write");
    tls.flush().await.expect("client flush");
    let mut reply = [0u8; 1];
    tls.read_exact(&mut reply).await.expect("client read");

    server_handle.await.expect("server task");
}

// ── Test 2: `early_data()` is `None` on first-connection client stream ────────

/// On a fresh client connection (no prior session ticket), `early_data()`
/// must return `None` because there is no resumption state to carry data on.
#[tokio::test]
async fn early_data_is_none_without_resumption_ticket() {
    let (cert_der, key_der) = make_self_signed();
    let client_cfg = make_client_cfg(&cert_der);

    let (addr, server_handle) = spawn_echo_server(cert_der, key_der).await;

    let connector = TlsConnector::from(client_cfg);
    let tcp = TcpStream::connect(addr).await.expect("client tcp connect");
    let sn = ServerName::try_from("localhost").expect("server name");
    let tls_stream = connector.connect(sn, tcp).await.expect("client tls");

    // Wrap in OxiTlsStream and check early_data().
    let mut oxi = OxiTlsStream::from_client(tls_stream, None);

    // First connection — no ticket available yet.
    assert!(
        oxi.early_data().is_none(),
        "early_data() must be None on first connection (no resumption ticket)"
    );

    // Send a byte to let the server complete.
    oxi.write_all(b"y").await.expect("client write");
    oxi.flush().await.expect("client flush");
    let mut reply = [0u8; 1];
    oxi.read_exact(&mut reply).await.expect("client read");

    server_handle.await.expect("server task");
}

// ── Test 3: `with_early_data()` flag prevents accidental replay by being ──────
//            explicit opt-in — defaults to false, becomes true when called.

/// `ClientBuilder::with_early_data()` must set `ClientConfig::enable_early_data
/// = true`, and the flag must default to `false` (replay protection: accidental
/// 0-RTT must be impossible without explicit opt-in).
#[tokio::test]
async fn early_data_flag_is_explicit_opt_in() {
    // Default: flag must be false (no 0-RTT without opt-in).
    let default_cfg = ClientBuilder::new()
        .with_webpki_roots()
        .build()
        .expect("default ClientBuilder::build");
    assert!(
        !default_cfg.enable_early_data,
        "enable_early_data must default to false (replay protection)"
    );

    // After opt-in: flag must be true.
    let early_cfg = ClientBuilder::new()
        .with_webpki_roots()
        .with_early_data()
        .build()
        .expect("ClientBuilder::with_early_data().build");
    assert!(
        early_cfg.enable_early_data,
        "enable_early_data must be true after with_early_data()"
    );
}
