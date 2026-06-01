//! Criterion benchmark: `aws_lc_provider()` construction cost.
//!
//! Measures:
//! 1. The cost of constructing a fresh `Arc<CryptoProvider>` via `aws_lc_provider()`.
//! 2. The cost of cloning an already-constructed `Arc` (should be near-zero).
//!
//! Run with:
//! ```bash
//! cargo bench -p oxitls-adapter-aws-lc --features aws-lc --bench provider_construction
//! ```

#[cfg(not(feature = "aws-lc"))]
use criterion::Criterion;
use criterion::{criterion_group, criterion_main};

#[cfg(feature = "aws-lc")]
mod aws_lc_benches {
    use criterion::{BatchSize, Criterion};
    use oxitls_adapter_aws_lc::aws_lc_provider;
    use std::sync::Arc;

    // ── Bench: provider construction ─────────────────────────────────────────────

    pub fn bench_provider_construction(c: &mut Criterion) {
        let mut group = c.benchmark_group("aws_lc_provider_construction");

        // 1. Full construction via `aws_lc_provider()`.
        group.bench_function("aws_lc_provider_new", |b| {
            b.iter(|| {
                let p = aws_lc_provider();
                std::hint::black_box(p)
            });
        });

        // 2. Cloning a pre-existing `Arc` (reference-count bump only).
        let shared = aws_lc_provider();
        group.bench_function("aws_lc_provider_arc_clone", |b| {
            b.iter_batched(
                || shared.clone(),
                std::hint::black_box,
                BatchSize::SmallInput,
            );
        });

        // 3. `Arc::ptr_eq` — verifies the Arc indirection overhead.
        group.bench_function("aws_lc_provider_ptr_eq", |b| {
            let p2 = shared.clone();
            b.iter(|| {
                let result = Arc::ptr_eq(&shared, &p2);
                std::hint::black_box(result)
            });
        });

        group.finish();
    }

    // ── Bench: cipher suite list access ──────────────────────────────────────────

    pub fn bench_cipher_suite_list(c: &mut Criterion) {
        let provider = aws_lc_provider();

        c.bench_function("aws_lc_cipher_suites_iter", |b| {
            b.iter(|| {
                let count = provider.cipher_suites.len();
                std::hint::black_box(count)
            });
        });
    }
}

#[cfg(feature = "aws-lc")]
criterion_group!(
    benches,
    aws_lc_benches::bench_provider_construction,
    aws_lc_benches::bench_cipher_suite_list
);

#[cfg(not(feature = "aws-lc"))]
criterion_group!(benches, _noop);

#[cfg(not(feature = "aws-lc"))]
fn _noop(_c: &mut Criterion) {}

criterion_main!(benches);
