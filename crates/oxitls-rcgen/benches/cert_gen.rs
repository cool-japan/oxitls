//! Criterion benchmarks for self-signed certificate generation.
//!
//! Measures key generation + certificate signing time for all five supported
//! signing algorithms: Ed25519, P-256, P-384, RSA-2048, RSA-4096.
//!
//! Run: `cargo bench -p oxitls-rcgen --bench cert_gen`

use criterion::{criterion_group, criterion_main, Criterion};

fn bench_ed25519(c: &mut Criterion) {
    let mut group = c.benchmark_group("cert_gen");
    group.bench_function("ed25519", |b| {
        b.iter(|| {
            oxitls_rcgen::generate_self_signed_ed25519(&["bench.example.com"])
                .expect("ed25519 cert gen failed")
        });
    });
    group.finish();
}

fn bench_p256(c: &mut Criterion) {
    let mut group = c.benchmark_group("cert_gen");
    group.bench_function("p256", |b| {
        b.iter(|| {
            oxitls_rcgen::generate_self_signed_p256(&["bench.example.com"])
                .expect("p256 cert gen failed")
        });
    });
    group.finish();
}

fn bench_p384(c: &mut Criterion) {
    let mut group = c.benchmark_group("cert_gen");
    group.bench_function("p384", |b| {
        b.iter(|| {
            oxitls_rcgen::generate_self_signed_p384(&["bench.example.com"])
                .expect("p384 cert gen failed")
        });
    });
    group.finish();
}

fn bench_rsa2048(c: &mut Criterion) {
    let mut group = c.benchmark_group("cert_gen_rsa");
    // RSA key generation is slow (~100–500 ms); limit sample count.
    group.sample_size(20);
    group.bench_function("rsa2048", |b| {
        b.iter(|| {
            oxitls_rcgen::generate_self_signed_rsa2048(&["bench.example.com"])
                .expect("rsa2048 cert gen failed")
        });
    });
    group.finish();
}

fn bench_rsa4096(c: &mut Criterion) {
    let mut group = c.benchmark_group("cert_gen_rsa");
    // RSA-4096 key generation typically takes 2–5 s; minimal sample count.
    group.sample_size(10);
    group.bench_function("rsa4096", |b| {
        b.iter(|| {
            oxitls_rcgen::generate_self_signed_rsa4096(&["bench.example.com"])
                .expect("rsa4096 cert gen failed")
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_ed25519,
    bench_p256,
    bench_p384,
    bench_rsa2048,
    bench_rsa4096
);
criterion_main!(benches);
