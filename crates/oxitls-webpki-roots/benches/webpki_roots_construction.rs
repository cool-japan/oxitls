//! Benchmark the cold and cached cost of building the Mozilla CA bundle.
//!
//! `webpki_root_certs_cold_init` measures building the root store from scratch
//! (bypassing the global `OnceLock` cache) to capture the true first-call cost.
//! `webpki_root_certs_cached` measures the `OnceLock`-cached path that production
//! code normally hits.
//!
//! Run with: `cargo bench -p oxitls-webpki-roots --bench webpki_roots_construction`

use std::hint::black_box;
use std::sync::{Arc, OnceLock};

use criterion::{criterion_group, criterion_main, Criterion};
use rustls::RootCertStore;

// ── Bench 1: cold construction (no OnceLock reuse) ───────────────────────────

fn bench_roots_cold_init(c: &mut Criterion) {
    c.bench_function("webpki_root_certs_cold_init", |b| {
        b.iter(|| {
            // Simulate cold first-call cost: create a fresh OnceLock and
            // initialise it just as `webpki_root_certs()` does internally.
            // A new OnceLock is allocated per iteration so we always pay the
            // full construction cost.
            let lock: OnceLock<Arc<RootCertStore>> = OnceLock::new();
            lock.get_or_init(|| {
                let mut store = RootCertStore::empty();
                store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                Arc::new(store)
            });
            black_box(&lock);
        })
    });
}

// ── Bench 2: cached path (global OnceLock, already initialised) ──────────────

fn bench_roots_cached(c: &mut Criterion) {
    // Warm the cache before measuring.
    let _ = oxitls_webpki_roots::webpki_root_certs();

    c.bench_function("webpki_root_certs_cached", |b| {
        b.iter(|| black_box(oxitls_webpki_roots::webpki_root_certs()))
    });
}

// ── Bench 3: Arc reference path (shared, no clone) ───────────────────────────

fn bench_roots_arc_cached(c: &mut Criterion) {
    // Warm the cache before measuring.
    let _ = oxitls_webpki_roots::webpki_root_certs_arc();

    c.bench_function("webpki_root_certs_arc_cached", |b| {
        b.iter(|| black_box(oxitls_webpki_roots::webpki_root_certs_arc()))
    });
}

criterion_group!(
    benches,
    bench_roots_cold_init,
    bench_roots_cached,
    bench_roots_arc_cached,
);
criterion_main!(benches);
