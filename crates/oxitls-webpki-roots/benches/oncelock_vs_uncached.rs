//! Side-by-side comparison: OnceLock-cached vs freshly built root store.
//!
//! Groups two variants under "root_store_init" so Criterion produces a
//! single comparison chart. The "once_lock_cached" variant calls the public
//! `webpki_root_certs()` API (which uses the global OnceLock). The
//! "fresh_build" variant constructs a new store from scratch on every
//! iteration, bypassing any caching, to show the raw cost.
//!
//! Run with: `cargo bench -p oxitls-webpki-roots --bench oncelock_vs_uncached`

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BenchmarkGroup, Criterion};
use rustls::RootCertStore;

// ── Group: cached vs uncached root store ─────────────────────────────────────

fn bench_oncelock_comparison(c: &mut Criterion) {
    // Warm the global cache so the "once_lock_cached" variant only measures
    // OnceLock lookup + RootCertStore clone, not the first-ever initialisation.
    let _ = oxitls_webpki_roots::webpki_root_certs();

    let mut group: BenchmarkGroup<_> = c.benchmark_group("root_store_init");

    group.bench_function("once_lock_cached", |b| {
        b.iter(|| black_box(oxitls_webpki_roots::webpki_root_certs()))
    });

    group.bench_function("fresh_build", |b| {
        b.iter(|| {
            // Build the cert store directly from the static trust anchor
            // slice, bypassing the global OnceLock.  This is the true cold-
            // path cost that `OnceLock` amortises over all subsequent calls.
            let mut store = RootCertStore::empty();
            store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            black_box(store)
        })
    });

    group.bench_function("arc_cached", |b| {
        b.iter(|| black_box(oxitls_webpki_roots::webpki_root_certs_arc()))
    });

    group.bench_function("root_cert_count", |b| {
        b.iter(|| black_box(oxitls_webpki_roots::root_cert_count()))
    });

    group.finish();
}

criterion_group!(benches, bench_oncelock_comparison);
criterion_main!(benches);
