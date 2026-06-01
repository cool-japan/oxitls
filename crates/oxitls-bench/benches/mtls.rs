//! Mutual TLS (mTLS) handshake benchmarks.
//!
//! Benchmarks the overhead of client certificate presentation and server
//! verification using `WebPkiClientVerifier` with the pure-Rust crypto
//! provider.
//!
//! Run with: `cargo bench -p oxitls-bench --bench mtls`

mod bench_common;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::sync::Arc;

// ── Setup helpers ─────────────────────────────────────────────────────────────

struct MtlsFixture {
    /// Server certificate and key.
    server_cert: CertificateDer<'static>,
    server_key: PrivateKeyDer<'static>,
    /// Client certificate and key (separate key pair, client-auth EKU).
    client_cert: CertificateDer<'static>,
    client_key: PrivateKeyDer<'static>,
    /// Root store the server uses to verify the client's certificate.
    client_root_store: rustls::RootCertStore,
    /// Root store the client uses to verify the server's certificate.
    server_root_store: rustls::RootCertStore,
}

impl MtlsFixture {
    fn generate() -> Self {
        // Server cert (server-auth EKU, self-signed).
        let server_ck =
            oxitls_rcgen::generate_self_signed_ed25519(&["localhost"]).expect("server cert");
        let server_cert = CertificateDer::from(server_ck.cert_der.clone());
        let server_key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_ck.pkcs8_der.clone()));
        let mut server_root_store = rustls::RootCertStore::empty();
        server_root_store
            .add(server_cert.clone())
            .expect("add server root");

        // Client cert (client-auth EKU): generate a CA and sign a client cert.
        let ca = oxitls_rcgen::generate_ca("bench-ca", oxitls_rcgen::SigningAlgorithm::Ed25519)
            .expect("CA");
        let client_ck = oxitls_rcgen::generate_ca_signed_client_cert(
            &["bench-client"],
            oxitls_rcgen::SigningAlgorithm::Ed25519,
            &ca,
        )
        .expect("client cert");
        let client_cert = CertificateDer::from(client_ck.cert_der.clone());
        let client_key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(client_ck.pkcs8_der.clone()));

        // Build a root store containing the CA cert for client verification.
        let ca_cert_der = CertificateDer::from(ca.certified_key.cert_der.clone());
        let mut client_root_store = rustls::RootCertStore::empty();
        client_root_store
            .add(ca_cert_der)
            .expect("add client CA root");

        Self {
            server_cert,
            server_key,
            client_cert,
            client_key,
            client_root_store,
            server_root_store,
        }
    }
}

// ── mTLS handshake benchmark ──────────────────────────────────────────────────

fn bench_mtls_handshake_pure(c: &mut Criterion) {
    let fix = MtlsFixture::generate();
    let provider = bench_common::pure_crypto_provider();

    // Server config: requires and verifies client certificates.
    let client_verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(fix.client_root_store.clone()),
        provider.clone(),
    )
    .build()
    .expect("client verifier");

    let server_cfg = Arc::new(
        rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(vec![fix.server_cert.clone()], fix.server_key.clone_key())
            .expect("server config"),
    );

    // Client config: presents its certificate.
    let client_cfg = Arc::new(
        rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .with_root_certificates(fix.server_root_store.clone())
            .with_client_auth_cert(vec![fix.client_cert.clone()], fix.client_key.clone_key())
            .expect("client config with cert"),
    );

    c.bench_function("mtls_handshake/pure", |b| {
        b.iter_batched(
            || (client_cfg.clone(), server_cfg.clone()),
            |(cc, sc)| bench_common::sync_handshake(cc, sc, "localhost"),
            BatchSize::SmallInput,
        );
    });
}

// ── Entry point ───────────────────────────────────────────────────────────────

criterion_group!(mtls_benches, bench_mtls_handshake_pure);
criterion_main!(mtls_benches);
