// SPDX-License-Identifier: Apache-2.0
// Copyright COOLJAPAN OU (Team Kitasan)
//! Performance benchmarks for the PKCS#11 signing adapter.
//!
//! These benchmarks require a live SoftHSM2 token.  When `SOFTHSM2_MODULE`
//! is not set in the environment the benchmark functions return early so that
//! `cargo bench` succeeds in CI without hardware.

use criterion::{criterion_group, criterion_main, Criterion};

/// Benchmark stub — skips gracefully when no HSM is available.
fn bench_stub(c: &mut Criterion) {
    if std::env::var("SOFTHSM2_MODULE").is_err() {
        eprintln!("SOFTHSM2_MODULE not set; skipping pkcs11 benches");
        return;
    }
    // When an HSM is present this would benchmark PKCS#11 sign operations.
    // For now it is a no-op harness so the benchmark binary compiles and
    // `cargo bench --bench pkcs11_perf -- --list` works.
    c.bench_function("pkcs11_sign_stub", |b| b.iter(|| {}));
}

criterion_group!(benches, bench_stub);
criterion_main!(benches);
