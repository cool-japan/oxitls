// SPDX-License-Identifier: Apache-2.0
// Copyright COOLJAPAN OU (Team Kitasan)
//! Benchmarks for oxitls-adapter-pkcs11.
//!
//! These benchmarks require a live HSM (`SOFTHSM2_MODULE` env var).
//! When no HSM is present the benchmark functions return early.

use criterion::{criterion_group, criterion_main, Criterion};

/// Placeholder benchmark that exits early if no HSM is configured.
///
/// When `SOFTHSM2_MODULE` is set this would benchmark sign operations;
/// for now it serves as a harness smoke-test so `cargo bench --no-run`
/// succeeds in CI.
fn bench_pkcs11_placeholder(c: &mut Criterion) {
    if std::env::var("SOFTHSM2_MODULE").is_err() {
        // No HSM available — benchmark is a no-op.
        return;
    }

    // When an HSM is present, benchmark a minimal placeholder iteration.
    c.bench_function("pkcs11_placeholder", |b| b.iter(|| {}));
}

criterion_group!(pkcs11_benches, bench_pkcs11_placeholder);
criterion_main!(pkcs11_benches);
