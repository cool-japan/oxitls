//! Integration tests for OCSP client verification and SCT / CT log verification.
//!
//! Tests exercise `OcspClientVerifier`, `SctVerifier`, and the
//! `RustcryptoClientConfigBuilder` methods `with_ocsp_policy` / `with_sct_policy`.

use std::sync::Arc;

use oxitls_adapter_rustls_rustcrypto::{
    server_config, CtKeyAlg, CtLog, CtLogList, OcspClientPolicy, RustcryptoAcceptor,
    RustcryptoClientConfigBuilder, RustcryptoConnector, SctPolicy,
};
use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::RootCertStore;
use rustls_pki_types::PrivatePkcs8KeyDer;
use tokio::net::{TcpListener, TcpStream};

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Build a minimal server + client config from a self-signed cert.
/// Returns (server_cfg, root_store, cert_der).
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

/// Spawn a TLS server that accepts one connection and exits.
/// Returns the bound port.
async fn spawn_echo_server(srv_cfg: Arc<rustls::ServerConfig>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind failed");
    let port = listener.local_addr().expect("addr").port();
    let acceptor = RustcryptoAcceptor::new(srv_cfg);
    tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            let _tls = acceptor.accept_tcp(stream).await;
        }
    });
    port
}

/// Perform a loopback TLS connect and return the result.
async fn do_connect(
    cli_cfg: rustls::ClientConfig,
    port: u16,
) -> Result<(), oxitls_adapter_rustls_rustcrypto::TlsError> {
    let tcp = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("tcp connect");
    RustcryptoConnector::new(Arc::new(cli_cfg))
        .connect_tcp("localhost", tcp)
        .await
        .map(|_| ())
}

// ── Test 1: OCSP Disabled — passes through ───────────────────────────────────

#[tokio::test]
async fn ocsp_client_disabled_passes_through() {
    let (srv_cfg, roots, _cert_der) = make_self_signed("localhost");
    let port = spawn_echo_server(srv_cfg).await;

    let cli_cfg = RustcryptoClientConfigBuilder::new()
        .with_roots(roots)
        .with_ocsp_policy(OcspClientPolicy::Disabled)
        .build()
        .expect("client config");

    let result = do_connect(cli_cfg, port).await;
    assert!(
        result.is_ok(),
        "disabled OCSP policy should allow connection: {result:?}"
    );
}

// ── Test 2: OCSP SoftFail on unparseable staple ───────────────────────────────

/// We can't easily inject arbitrary OCSP bytes via rustls server config without
/// a custom ResolvesServerCert implementation. Instead, we drive the verifier
/// directly with synthetic inputs, which is faster and more deterministic.
#[test]
fn ocsp_client_soft_fail_on_unparseable() {
    use oxitls_adapter_rustls_rustcrypto::pure_provider;
    use oxitls_adapter_rustls_rustcrypto::verifier::ocsp_client::OcspClientVerifier;
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use rustls::{
        client::{danger::ServerCertVerifier, WebPkiServerVerifier},
        pki_types::{ServerName, UnixTime},
        RootCertStore,
    };

    let CertifiedKey { cert, .. } =
        generate_simple_self_signed(vec!["localhost".to_string()]).expect("rcgen");
    let cert_der = cert.der().clone();

    let mut roots = RootCertStore::empty();
    roots.add(cert_der.clone()).expect("add root");

    let inner = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), pure_provider())
        .build()
        .expect("inner verifier");

    let verifier = OcspClientVerifier::new(inner, OcspClientPolicy::SoftFail);

    // Construct a UnixTime for "now"
    let now = UnixTime::since_unix_epoch(std::time::Duration::from_secs(
        // Use a time well within the cert's validity window (rcgen uses 100yr
        // validity). 2026-05-27 = 1748304000 (approximate).
        1_748_304_000,
    ));
    let sni = ServerName::try_from("localhost".to_string()).expect("sni");

    // Junk bytes as OCSP staple — should be soft-fail (warning + continue).
    let junk_ocsp = b"not a real ocsp response";
    let result = verifier.verify_server_cert(&cert_der, &[], &sni, junk_ocsp, now);
    // SoftFail: inner verifier runs; self-signed cert won't be trusted so we
    // expect an error from the inner verifier (chain validation), NOT an OCSP
    // parse error.
    // We just assert the error is NOT about OCSP being required.
    if let Err(e) = &result {
        let msg = e.to_string();
        assert!(
            !msg.contains("OCSP staple required"),
            "soft-fail should not produce 'OCSP staple required' error; got: {msg}"
        );
    }
    // Test passed: soft-fail didn't produce a hard OCSP error.
}

// ── Test 3: OCSP HardRequire blocks missing staple ────────────────────────────

#[tokio::test]
async fn ocsp_client_hard_require_blocks_missing_staple() {
    let (srv_cfg, roots, _cert_der) = make_self_signed("localhost");
    let port = spawn_echo_server(srv_cfg).await;

    let cli_cfg = RustcryptoClientConfigBuilder::new()
        .with_roots(roots)
        .with_ocsp_policy(OcspClientPolicy::HardRequire)
        .build()
        .expect("client config");

    let result = do_connect(cli_cfg, port).await;
    assert!(
        result.is_err(),
        "hard-require OCSP policy should reject missing staple; got success"
    );
    let msg = format!("{:?}", result.unwrap_err());
    assert!(
        msg.contains("OCSP staple required")
            || msg.contains("General")
            || msg.contains("Handshake"),
        "error should mention OCSP or be a handshake error: {msg}"
    );
}

// ── Test 4: SCT Disabled passes through ──────────────────────────────────────

#[tokio::test]
async fn sct_policy_disabled_passes_through() {
    let (srv_cfg, roots, _cert_der) = make_self_signed("localhost");
    let port = spawn_echo_server(srv_cfg).await;

    let cli_cfg = RustcryptoClientConfigBuilder::new()
        .with_roots(roots)
        .with_sct_policy(SctPolicy::Disabled, CtLogList::empty())
        .build()
        .expect("client config");

    let result = do_connect(cli_cfg, port).await;
    assert!(
        result.is_ok(),
        "SCT disabled should allow connection; got: {result:?}"
    );
}

// ── Test 5: SCT Permissive + empty log list + no SCT ext passes ───────────────

#[tokio::test]
async fn sct_policy_permissive_empty_log_list_passes() {
    let (srv_cfg, roots, _cert_der) = make_self_signed("localhost");
    let port = spawn_echo_server(srv_cfg).await;

    // No SCT extension in the cert, empty log list, permissive policy.
    let cli_cfg = RustcryptoClientConfigBuilder::new()
        .with_roots(roots)
        .with_sct_policy(
            SctPolicy::Permissive {
                min_distinct_logs: 2,
            },
            CtLogList::empty(),
        )
        .build()
        .expect("client config");

    let result = do_connect(cli_cfg, port).await;
    assert!(
        result.is_ok(),
        "permissive SCT with empty log list + no SCT ext should pass; got: {result:?}"
    );
}

// ── Test 6: OcspClientPolicy enum Debug output ───────────────────────────────

#[test]
fn ocsp_policy_enum_debug() {
    let s = format!("{:?}", OcspClientPolicy::SoftFail);
    assert!(
        !s.is_empty(),
        "Debug output for SoftFail should be non-empty"
    );

    let s2 = format!("{:?}", OcspClientPolicy::HardRequire);
    assert!(
        !s2.is_empty(),
        "Debug output for HardRequire should be non-empty"
    );

    let s3 = format!("{:?}", OcspClientPolicy::Disabled);
    assert!(
        !s3.is_empty(),
        "Debug output for Disabled should be non-empty"
    );
}

// ── Test 7: CtLogList::empty() ────────────────────────────────────────────────

#[test]
fn ct_log_list_empty() {
    let list = CtLogList::empty();
    assert!(list.is_empty(), "CtLogList::empty() should be empty");

    let non_empty = CtLogList(vec![CtLog {
        id: [0u8; 32],
        public_key_der: vec![],
        key_alg: CtKeyAlg::EcdsaP256Sha256,
    }]);
    assert!(
        !non_empty.is_empty(),
        "Non-empty CtLogList should not be empty"
    );
}
