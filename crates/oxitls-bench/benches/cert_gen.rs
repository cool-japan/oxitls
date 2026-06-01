//! Certificate generation benchmarks via oxitls-rcgen.
//!
//! Benchmarks Ed25519, P-256, RSA-2048, and RSA-4096 self-signed cert
//! generation.  RSA-4096 uses a smaller sample size since it is ~10x slower
//! than RSA-2048.
//!
//! Run with: `cargo bench -p oxitls-bench --bench cert_gen`

use criterion::{criterion_group, criterion_main, Criterion, SamplingMode};
use std::time::Duration;

// ── Ed25519 ───────────────────────────────────────────────────────────────────

fn bench_ed25519_self_signed(c: &mut Criterion) {
    c.bench_function("cert_gen/ed25519_self_signed", |b| {
        b.iter(|| {
            let ck = oxitls_rcgen::generate_self_signed_ed25519(&["example.com"])
                .expect("ed25519 cert gen");
            std::hint::black_box(ck)
        });
    });
}

// ── P-256 ─────────────────────────────────────────────────────────────────────

fn bench_p256_self_signed(c: &mut Criterion) {
    c.bench_function("cert_gen/p256_self_signed", |b| {
        b.iter(|| {
            let ck =
                oxitls_rcgen::generate_self_signed_p256(&["example.com"]).expect("p256 cert gen");
            std::hint::black_box(ck)
        });
    });
}

// ── P-384 ─────────────────────────────────────────────────────────────────────

fn bench_p384_self_signed(c: &mut Criterion) {
    c.bench_function("cert_gen/p384_self_signed", |b| {
        b.iter(|| {
            let ck =
                oxitls_rcgen::generate_self_signed_p384(&["example.com"]).expect("p384 cert gen");
            std::hint::black_box(ck)
        });
    });
}

// ── RSA-2048 ──────────────────────────────────────────────────────────────────

fn bench_rsa2048_self_signed(c: &mut Criterion) {
    c.bench_function("cert_gen/rsa2048_self_signed", |b| {
        b.iter(|| {
            let ck = oxitls_rcgen::generate_self_signed_rsa2048(&["example.com"])
                .expect("rsa2048 cert gen");
            std::hint::black_box(ck)
        });
    });
}

// ── RSA-4096 (reduced sample size due to slow keygen) ────────────────────────

fn bench_rsa4096_self_signed(c: &mut Criterion) {
    let mut group = c.benchmark_group("cert_gen_slow");
    group.sample_size(10);
    group.sampling_mode(SamplingMode::Flat);
    group.measurement_time(Duration::from_secs(30));
    group.bench_function("rsa4096_self_signed", |b| {
        b.iter(|| {
            let ck = oxitls_rcgen::generate_self_signed_rsa4096(&["example.com"])
                .expect("rsa4096 cert gen");
            std::hint::black_box(ck)
        });
    });
    group.finish();
}

// ── Entry point ───────────────────────────────────────────────────────────────

criterion_group!(
    cert_gen_benches,
    bench_ed25519_self_signed,
    bench_p256_self_signed,
    bench_p384_self_signed,
    bench_rsa2048_self_signed,
    bench_rsa4096_self_signed,
);
criterion_main!(cert_gen_benches);
