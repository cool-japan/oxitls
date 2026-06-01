//! Benchmark the dispatch overhead of [`StaticOcspResolver::resolve`] and the
//! server-side `build()` cost when an OCSP resolver is installed.
//!
//! Because `ResolvesOcspResponse::resolve` is intended to be called once per
//! TLS handshake, the absolute cost of a single call is the figure of interest.
//!
//! Run with: `cargo bench -p oxitls-bench --bench ocsp_resolver_dispatch`

use std::sync::Arc;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

use oxitls::tls13::ServerBuilder;
use oxitls::{OcspResponseResolver, StaticOcspResolver};
use oxitls_rcgen::generate_self_signed_ed25519;

// ── Shared fixture ────────────────────────────────────────────────────────────

fn cert_fixture() -> (Vec<u8>, Vec<u8>) {
    let ck = generate_self_signed_ed25519(&["localhost"]).expect("bench: cert gen failed");
    (ck.cert_der, ck.pkcs8_der)
}

fn static_ocsp_bytes() -> Vec<u8> {
    // 16 bytes of pseudo-OCSP data — realistic size for a micro-benchmark.
    vec![
        0x30, 0x0e, 0x0a, 0x01, 0x00, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x35, 0x30, 0x31, 0x30, 0x31,
        0x5a,
    ]
}

// ── Bench 1: StaticOcspResolver::resolve() hot loop ──────────────────────────

fn bench_static_resolver_resolve(c: &mut Criterion) {
    let ocsp = static_ocsp_bytes();
    let resolver = StaticOcspResolver(ocsp);

    let mut group = c.benchmark_group("ocsp_resolver");
    group.bench_function("static_resolve_with_sni", |b| {
        b.iter(|| resolver.ocsp_response());
    });
    group.bench_function("static_resolve_no_sni", |b| {
        b.iter(|| resolver.ocsp_response());
    });
    group.finish();
}

// ── Bench 2: StaticOcspResolver via dyn ResolvesOcspResponse (vtable path) ───

fn bench_static_resolver_dyn_dispatch(c: &mut Criterion) {
    let resolver: Arc<dyn OcspResponseResolver> = Arc::new(StaticOcspResolver(static_ocsp_bytes()));

    c.bench_function("ocsp_resolver_dyn_dispatch", |b| {
        b.iter(|| resolver.ocsp_response());
    });
}

// ── Bench 3: ServerBuilder::build() with OCSP resolver installed ─────────────

fn bench_server_builder_with_ocsp_resolver(c: &mut Criterion) {
    let (cert_der, key_der) = cert_fixture();
    let resolver = Arc::new(StaticOcspResolver(static_ocsp_bytes()));

    c.bench_function("server_builder_build_with_ocsp_resolver", |b| {
        b.iter_batched(
            || {
                (
                    CertificateDer::from(cert_der.clone()),
                    PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(
                        key_der.clone(),
                    )),
                    Arc::clone(&resolver),
                )
            },
            |(cert, key, res)| {
                ServerBuilder::new()
                    .with_der_cert_and_key(vec![cert], key)
                    .with_ocsp_response_resolver(res)
                    .build()
                    .expect("server config with OCSP resolver")
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(
    benches,
    bench_static_resolver_resolve,
    bench_static_resolver_dyn_dispatch,
    bench_server_builder_with_ocsp_resolver
);
criterion_main!(benches);
