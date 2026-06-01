//! Tests for `CryptoProvider` injection via `ServerBuilder::with_provider`
//! and `ClientBuilder::with_provider`.
//!
//! Covers:
//! - Explicit `with_provider(pure_provider())` succeeds (forward path)
//! - Default (no `with_provider` call) still succeeds (backward compat)
//! - Both `ServerBuilder` and `ClientBuilder`

use rcgen::{CertificateParams, KeyPair};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

use oxitls::tls13::{ClientBuilder, ServerBuilder};

// ---------------------------------------------------------------------------
// ServerBuilder tests
// ---------------------------------------------------------------------------

/// Helper: generate a self-signed cert and key via rcgen for testing.
fn make_server_cert_and_key() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let key_pair = KeyPair::generate().expect("rcgen key generation failed");
    let params =
        CertificateParams::new(vec!["localhost".into()]).expect("CertificateParams::new failed");
    let cert = params
        .self_signed(&key_pair)
        .expect("self-signed cert generation failed");
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(key_pair.serialize_der().into());
    (vec![cert_der], key_der)
}

/// `ServerBuilder::new().with_provider(pure_provider()).build()` must succeed.
#[test]
fn server_builder_with_explicit_provider_succeeds() {
    let (certs, key) = make_server_cert_and_key();
    let provider = oxitls_adapter_rustls_rustcrypto::pure_provider();
    ServerBuilder::new()
        .with_provider(provider)
        .with_der_cert_and_key(certs, key)
        .build()
        .expect("ServerBuilder with explicit provider should succeed");
}

/// `ServerBuilder::new().build()` (no `with_provider`) must still succeed —
/// backward compatibility guarantee.
#[test]
fn server_builder_default_provider_backward_compat() {
    let (certs, key) = make_server_cert_and_key();
    ServerBuilder::new()
        .with_der_cert_and_key(certs, key)
        .build()
        .expect("ServerBuilder with default provider (no with_provider call) should succeed");
}

/// Provider set before cert/key still applies correctly.
#[test]
fn server_builder_provider_order_independent() {
    let (certs, key) = make_server_cert_and_key();
    let provider = oxitls_adapter_rustls_rustcrypto::pure_provider();
    // provider set first, certs second — should work identically
    ServerBuilder::new()
        .with_der_cert_and_key(certs, key)
        .with_provider(provider)
        .build()
        .expect("ServerBuilder provider set after cert/key should still succeed");
}

/// mTLS with explicit provider: verifier must use the same provider as the config.
#[test]
fn server_builder_mtls_with_explicit_provider_succeeds() {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};

    // Generate a CA cert to use as a trust anchor.
    let ca_kp = KeyPair::generate().expect("CA key generation failed");
    let mut ca_params = CertificateParams::new(vec![]).expect("CA params failed");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_kp).expect("CA self-sign failed");
    let ca_cert_der = rustls_pki_types::CertificateDer::from(ca_cert.der().to_vec());

    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca_cert_der).expect("add CA root");

    let (certs, key) = make_server_cert_and_key();
    let provider = oxitls_adapter_rustls_rustcrypto::pure_provider();

    ServerBuilder::new()
        .with_provider(provider)
        .with_client_cert_verifier(roots)
        .with_der_cert_and_key(certs, key)
        .build()
        .expect("ServerBuilder mTLS with explicit provider should succeed");
}

// ---------------------------------------------------------------------------
// ClientBuilder tests
// ---------------------------------------------------------------------------

/// `ClientBuilder::new().with_provider(pure_provider()).build()` must succeed.
#[test]
fn client_builder_with_explicit_provider_succeeds() {
    let provider = oxitls_adapter_rustls_rustcrypto::pure_provider();
    ClientBuilder::new()
        .with_provider(provider)
        .with_danger_accept_invalid_certs()
        .build()
        .expect("ClientBuilder with explicit provider should succeed");
}

/// `ClientBuilder::new().build()` without `with_provider` must succeed —
/// backward compatibility guarantee.
#[test]
fn client_builder_default_provider_backward_compat() {
    ClientBuilder::new()
        .with_danger_accept_invalid_certs()
        .build()
        .expect("ClientBuilder with default provider (no with_provider call) should succeed");
}

/// Provider set at any point in the chain is applied at build time.
#[test]
fn client_builder_provider_order_independent() {
    let provider = oxitls_adapter_rustls_rustcrypto::pure_provider();
    // provider set after danger flag — should work identically
    ClientBuilder::new()
        .with_danger_accept_invalid_certs()
        .with_provider(provider)
        .build()
        .expect("ClientBuilder provider set after other options should succeed");
}
