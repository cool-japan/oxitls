//! Benchmark the construction cost of `ClientBuilder` and `ServerBuilder`.
//!
//! These benchmarks measure the overhead of calling `build()` — i.e. assembling
//! a `rustls::ClientConfig` or `rustls::ServerConfig` from a pre-loaded cert.
//! The cost is dominated by `CryptoProvider` setup and root-cert store
//! initialisation.
//!
//! Run with: `cargo bench -p oxitls-bench --bench builder_construction`

use std::sync::Arc;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

use oxitls::tls13::{ClientBuilder, ServerBuilder};
use oxitls_rcgen::generate_self_signed_ed25519;

// ── Shared fixture ─────────────────────────────────────────────────────────

fn cert_fixture() -> (Vec<u8>, Vec<u8>) {
    let ck = generate_self_signed_ed25519(&["localhost"]).expect("bench: cert gen failed");
    (ck.cert_der, ck.pkcs8_der)
}

// ── Bench 1: ClientBuilder::build() with a single trusted DER cert ───────────

fn bench_client_builder_build(c: &mut Criterion) {
    let (cert_der, _key_der) = cert_fixture();

    c.bench_function("client_builder_build_single_cert", |b| {
        b.iter_batched(
            || cert_der.clone(),
            |der| {
                ClientBuilder::new()
                    .with_trusted_cert_der(der)
                    .expect("trusted cert")
                    .build()
                    .expect("client config")
            },
            BatchSize::SmallInput,
        );
    });
}

// ── Bench 2: ServerBuilder::build() with a DER cert+key ──────────────────────

fn bench_server_builder_build(c: &mut Criterion) {
    let (cert_der, key_der) = cert_fixture();

    c.bench_function("server_builder_build_single_cert", |b| {
        b.iter_batched(
            || {
                (
                    CertificateDer::from(cert_der.clone()),
                    PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(
                        key_der.clone(),
                    )),
                )
            },
            |(cert, key)| {
                ServerBuilder::new()
                    .with_der_cert_and_key(vec![cert], key)
                    .build()
                    .expect("server config")
            },
            BatchSize::SmallInput,
        );
    });
}

// ── Bench 3: ClientBuilder::build() with webpki roots (cold path) ────────────

fn bench_client_builder_webpki_roots(c: &mut Criterion) {
    c.bench_function("client_builder_build_webpki_roots", |b| {
        b.iter(|| {
            ClientBuilder::new()
                .with_webpki_roots()
                .build()
                .expect("client config with webpki roots")
        });
    });
}

// ── Bench 4: ServerBuilder::build() + Arc::new (as tokio_acceptor does) ──────

fn bench_server_builder_full_acceptor(c: &mut Criterion) {
    let (cert_der, key_der) = cert_fixture();

    c.bench_function("server_builder_full_acceptor", |b| {
        b.iter_batched(
            || {
                (
                    CertificateDer::from(cert_der.clone()),
                    PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(
                        key_der.clone(),
                    )),
                )
            },
            |(cert, key)| {
                let cfg = ServerBuilder::new()
                    .with_der_cert_and_key(vec![cert], key)
                    .build()
                    .expect("server config");
                tokio_rustls::TlsAcceptor::from(Arc::new(cfg))
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(
    benches,
    bench_client_builder_build,
    bench_server_builder_build,
    bench_client_builder_webpki_roots,
    bench_server_builder_full_acceptor
);
criterion_main!(benches);
