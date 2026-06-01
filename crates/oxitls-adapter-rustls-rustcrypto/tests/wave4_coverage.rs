//! Wave-4 coverage tests for oxitls-adapter-rustls-rustcrypto.
//!
//! Covers:
//! - Pure provider cipher suite listing with TLS 1.3 AES-256 assertion
//! - Client builder ALPN round-trip
//! - Keylog builder path (build-only; actual key writing requires a full handshake)
//! - Server builder OCSP response round-trip via oxitls-rcgen

use oxitls_adapter_rustls_rustcrypto::{
    RustcryptoClientConfigBuilder, RustcryptoServerConfigBuilder,
};
use rustls::RootCertStore;

/// Verify that the pure provider lists TLS_AES_256_GCM_SHA384 as a supported
/// cipher suite. This is a mandatory TLS 1.3 cipher suite per RFC 8446 §9.1.
#[tokio::test]
async fn pure_provider_has_tls13_aes256_suite() {
    use oxitls_adapter_rustls_rustcrypto::pure_provider;
    use rustls::CipherSuite;
    let provider = pure_provider();
    let suites: Vec<_> = provider.cipher_suites.iter().map(|s| s.suite()).collect();
    assert!(
        suites.contains(&CipherSuite::TLS13_AES_256_GCM_SHA384),
        "expected TLS13_AES_256_GCM_SHA384 in pure provider cipher suites; found: {suites:?}"
    );
}

/// Verify that `.with_alpn()` stores the ALPN protocol list verbatim in the
/// built `ClientConfig`.
#[test]
fn client_builder_with_alpn_stores_alpn() {
    use oxitls_rcgen::generate_self_signed_ed25519;

    // We need at least one root trust anchor for the WebPkiServerVerifier.
    let ck = generate_self_signed_ed25519(&["localhost"]).expect("cert gen");
    let mut roots = RootCertStore::empty();
    roots
        .add(rustls_pki_types::CertificateDer::from(ck.cert_der.clone()))
        .expect("add root");

    let config = RustcryptoClientConfigBuilder::new()
        .with_roots(roots)
        .with_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()])
        .build()
        .expect("build ok");
    assert!(
        config.alpn_protocols.contains(&b"h2".to_vec()),
        "expected 'h2' in alpn_protocols"
    );
    assert!(
        config.alpn_protocols.contains(&b"http/1.1".to_vec()),
        "expected 'http/1.1' in alpn_protocols"
    );
    assert_eq!(
        config.alpn_protocols.len(),
        2,
        "expected exactly 2 ALPN protocols"
    );
}

/// Verify that the builder compiles and succeeds with a file-based keylog policy.
///
/// Note: actual log-file writing requires a completed TLS handshake.
/// This test validates the builder code path only.
#[test]
fn keylog_bridge_builds_without_error() {
    use oxitls_core::KeyLogPolicy;
    use oxitls_rcgen::generate_self_signed_ed25519;
    use std::env::temp_dir;

    let path = temp_dir().join("wave4_keylog_test.txt");
    // Clean up any residual file from previous runs.
    let _ = std::fs::remove_file(&path);

    // Need a valid root anchor for the verifier to build.
    let ck = generate_self_signed_ed25519(&["localhost"]).expect("cert gen");
    let mut roots = RootCertStore::empty();
    roots
        .add(rustls_pki_types::CertificateDer::from(ck.cert_der.clone()))
        .expect("add root");

    let result = RustcryptoClientConfigBuilder::new()
        .with_roots(roots)
        .with_keylog(KeyLogPolicy::File(path.clone()))
        .build();
    assert!(
        result.is_ok(),
        "build with keylog policy failed: {:?}",
        result.err()
    );

    // Clean up.
    let _ = std::fs::remove_file(&path);
}

/// Verify that `RustcryptoServerConfigBuilder` accepts an OCSP response and
/// produces a valid `ServerConfig` — the OCSP staple round-trip.
#[test]
fn server_builder_with_ocsp_response_round_trip() {
    use oxitls_rcgen::generate_self_signed_ed25519;
    use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

    // Generate a self-signed certificate using oxitls-rcgen.
    let ck = generate_self_signed_ed25519(&["example.com"]).expect("cert gen ok");

    // Build the cert chain and private key in rustls types.
    let cert_der = rustls_pki_types::CertificateDer::from(ck.cert_der.clone());
    let chain = vec![cert_der];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.pkcs8_der.clone()));

    // Fabricated OCSP response bytes (valid DER is not required here — the
    // round-trip only checks that the bytes are accepted by the builder).
    let ocsp_bytes = vec![0xDE, 0xAD, 0xBE, 0xEF];

    let config = RustcryptoServerConfigBuilder::new()
        .with_cert_and_key(chain, key)
        .with_ocsp_response(ocsp_bytes)
        .build();

    // rustls validates the cert/key pair during build; an invalid OCSP response
    // is stored opaquely and not parsed at config-build time, so this must succeed.
    assert!(
        config.is_ok(),
        "server builder with OCSP response failed: {:?}",
        config.err()
    );
}
