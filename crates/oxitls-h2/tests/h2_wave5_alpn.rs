//! Wave 5 ALPN-mismatch test for oxitls-h2.
//!
//! Verifies that `h2_client_handshake` returns `H2Error::AlpnNotH2` when the
//! TLS handshake completes but negotiates a protocol other than `"h2"`.
//!
//! Setup: client offers `[b"h2", b"http/1.1"]`; server offers only
//! `[b"http/1.1"]`.  rustls negotiates `"http/1.1"` (TLS succeeds), but
//! `verify_client_alpn` inside `h2_client_handshake` detects the mismatch and
//! returns `H2Error::AlpnNotH2` before any h2 framing is attempted.

use std::sync::Arc;

use rcgen::{CertificateParams, KeyPair};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use oxitls_h2::h2_client_handshake;

// ---------------------------------------------------------------------------
// Helper: generate self-signed cert + build TLS configs with mismatched ALPN
// ---------------------------------------------------------------------------

fn build_mismatched_alpn_configs() -> (Arc<ServerConfig>, Arc<ClientConfig>) {
    let kp = KeyPair::generate().expect("keygen");
    let cert = CertificateParams::new(vec!["localhost".into()])
        .expect("cert params")
        .self_signed(&kp)
        .expect("self-sign");

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(kp.serialize_der().into());

    let provider = oxitls_adapter_rustls_rustcrypto::pure_provider();

    // Server config: offers ONLY "http/1.1" — intentionally excludes "h2".
    let mut server_cfg = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .expect("server cert");
    server_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];

    // Client config: offers "h2" first, then "http/1.1" as fallback.
    // rustls will negotiate "http/1.1" because that is the only common protocol.
    let mut root_store = RootCertStore::empty();
    root_store.add(cert_der).expect("root cert");
    let mut client_cfg = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .with_root_certificates(root_store)
        .with_no_client_auth();
    client_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    (Arc::new(server_cfg), Arc::new(client_cfg))
}

// ---------------------------------------------------------------------------
// Test: ALPN mismatch returns H2Error::AlpnNotH2
// ---------------------------------------------------------------------------

#[tokio::test]
async fn alpn_mismatch_returns_error() {
    let (server_cfg, client_cfg) = build_mismatched_alpn_configs();

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local addr");

    let acceptor = TlsAcceptor::from(server_cfg);

    // Server task: accept the TLS handshake and hold the connection open long
    // enough for the client to attempt the h2 handshake.  The server does NOT
    // perform an h2 handshake — it simply holds the TLS stream open so the
    // client can observe the ALPN value and return an error.
    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("tcp accept");
        let _tls = acceptor.accept(tcp).await.expect("tls accept");
        // Hold the stream until the client is done so the TLS connection is not
        // torn down before `h2_client_handshake` can check the ALPN value.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    });

    // Client: connect with TLS, then call h2_client_handshake.
    // The negotiated ALPN will be "http/1.1", not "h2", so the call must fail.
    let connector = TlsConnector::from(client_cfg);
    let tcp = TcpStream::connect(addr).await.expect("tcp connect");
    let server_name = ServerName::try_from("localhost").expect("server name");
    let tls = connector
        .connect(server_name, tcp)
        .await
        .expect("tls connect");

    let result = h2_client_handshake(tls).await;

    assert!(result.is_err(), "expected H2Error::AlpnNotH2, got Ok");
    let err = result.unwrap_err();
    assert!(
        err.is_alpn_not_h2(),
        "expected is_alpn_not_h2() == true, got: {err}"
    );

    // The error message should mention the negotiated protocol.
    let msg = format!("{err}");
    assert!(
        msg.contains("not \"h2\"") || msg.contains("not h2"),
        "error message should mention h2 mismatch: {msg}"
    );

    server_task.await.expect("server task panicked");
}
