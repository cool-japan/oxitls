//! ALPN negotiation and SNI dispatch overhead benchmarks.
//!
//! Measures:
//! - ALPN negotiation latency when both client and server offer h2 + http/1.1
//! - SNI dispatch overhead with 1, 10, and 100 virtual host certificates
//!
//! Run with: `cargo bench -p oxitls-bench --bench alpn_sni`

mod bench_common;

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use std::sync::Arc;

// ── ALPN benchmark ────────────────────────────────────────────────────────────

fn bench_alpn_negotiation(c: &mut Criterion) {
    let fix = bench_common::cert_fixture();
    let provider = bench_common::pure_crypto_provider();
    let alpn_protos: Vec<Vec<u8>> = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    // Server with ALPN.
    let mut server_cfg = bench_common::make_server_config(
        provider.clone(),
        vec![fix.leaf_cert_der.clone()],
        fix.leaf_key_der.clone_key(),
    );
    server_cfg.alpn_protocols = alpn_protos.clone();
    let server_cfg = Arc::new(server_cfg);

    // Client with ALPN.
    let mut client_cfg = bench_common::make_client_config(provider.clone(), fix.root_store.clone());
    client_cfg.alpn_protocols = alpn_protos;
    let client_cfg = Arc::new(client_cfg);

    c.bench_function("alpn_negotiation/h2_http11", |b| {
        b.iter_batched(
            || (client_cfg.clone(), server_cfg.clone()),
            |(cc, sc)| bench_common::sync_handshake(cc, sc, "localhost"),
            BatchSize::SmallInput,
        );
    });
}

// ── SNI dispatch benchmark ────────────────────────────────────────────────────

/// A pre-built SNI fixture for a given number of virtual hosts.
struct SniFixture {
    /// Server name used by the client (last in the list — exercises full scan).
    server_name: String,
    client_cfg: Arc<rustls::ClientConfig>,
    server_cfg: Arc<rustls::ServerConfig>,
}

impl SniFixture {
    fn build(n: usize, provider: Arc<rustls::crypto::CryptoProvider>) -> Self {
        // Generate `n` host certs and build the SNI resolver.
        let mut sni_resolver = rustls::server::ResolvesServerCertUsingSni::new();
        let mut root_store = rustls::RootCertStore::empty();
        let mut last_name = String::new();
        let mut last_cert_der = None;

        for i in 0..n {
            let name = format!("host{i}.bench.test");
            let ck =
                oxitls_rcgen::generate_self_signed_ed25519(&[name.as_str()]).expect("SNI cert gen");
            let rustls_ck = ck
                .to_rustls_certified_key()
                .expect("to_rustls_certified_key");
            let cert_der = rustls_pki_types::CertificateDer::from(ck.cert_der.clone());

            sni_resolver.add(&name, rustls_ck).expect("add SNI cert");
            root_store.add(cert_der.clone()).expect("add SNI root");

            last_name = name;
            last_cert_der = Some(cert_der);
        }

        let server_cfg = Arc::new(
            rustls::ServerConfig::builder_with_provider(provider.clone())
                .with_safe_default_protocol_versions()
                .expect("versions")
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(sni_resolver)),
        );

        // Client trusts only the last cert (it only connects to that host).
        let mut client_root_store = rustls::RootCertStore::empty();
        client_root_store
            .add(last_cert_der.expect("at least one cert"))
            .expect("add last root");

        let client_cfg = Arc::new(bench_common::make_client_config(
            provider.clone(),
            client_root_store,
        ));

        Self {
            server_name: last_name,
            client_cfg,
            server_cfg,
        }
    }
}

fn bench_sni_dispatch(c: &mut Criterion) {
    let provider = bench_common::pure_crypto_provider();
    let mut group = c.benchmark_group("sni_dispatch");

    for &n in &[1usize, 10, 100] {
        let fix = SniFixture::build(n, provider.clone());
        let server_name = fix.server_name.clone();
        let client_cfg = fix.client_cfg.clone();
        let server_cfg = fix.server_cfg.clone();

        group.bench_with_input(BenchmarkId::new("hosts", n), &server_name, |b, sname| {
            b.iter_batched(
                || (client_cfg.clone(), server_cfg.clone()),
                |(cc, sc)| bench_common::sync_handshake(cc, sc, sname),
                BatchSize::SmallInput,
            )
        });
    }

    group.finish();
}

// ── Entry point ───────────────────────────────────────────────────────────────

criterion_group!(alpn_sni_benches, bench_alpn_negotiation, bench_sni_dispatch,);
criterion_main!(alpn_sni_benches);
