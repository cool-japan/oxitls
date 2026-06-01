//! Memory footprint measurement for the Mozilla CA bundle root store.
//!
//! Under the `dhat-heap` feature, this bench activates the dhat heap profiler
//! as a global allocator so you can inspect per-call allocation counts and
//! bytes with `dhat-viewer`. Without that feature the bench still compiles and
//! runs Criterion timing measurements (useful for tracking allocation-count
//! regressions via wall-time as a proxy).
//!
//! Enable dhat profiling:
//!   `cargo bench -p oxitls-webpki-roots --features dhat-heap \
//!        --bench root_store_memory`
//!
//! Normal timing run (no feature required):
//!   `cargo bench -p oxitls-webpki-roots --bench root_store_memory`

#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

use std::cell::Cell;
use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use rustls::RootCertStore;

// ── Bench 1: memory footprint of a full cold-built root store ────────────────

fn bench_root_store_memory_footprint(c: &mut Criterion) {
    #[cfg(feature = "dhat-heap")]
    let _profiler = dhat::Profiler::new_heap();

    c.bench_function("root_store_memory_footprint", |b| {
        b.iter(|| {
            // Build a fresh root store from the static slice so dhat can
            // attribute every allocation to this benchmark site.
            let mut store = RootCertStore::empty();
            store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            black_box(store)
        })
    });
}

// ── Bench 2: cached store clone overhead ─────────────────────────────────────

fn bench_root_store_cached_clone(c: &mut Criterion) {
    // Warm the global OnceLock cache.
    let _ = oxitls_webpki_roots::webpki_root_certs();

    c.bench_function("root_store_cached_clone", |b| {
        b.iter(|| {
            // `webpki_root_certs()` clones from the Arc<RootCertStore>.
            // This measures the clone allocation cost only (no bundle parsing).
            black_box(oxitls_webpki_roots::webpki_root_certs())
        })
    });
}

// ── Bench 3: Arc reference — zero allocation path ────────────────────────────

fn bench_root_store_arc_no_alloc(c: &mut Criterion) {
    // Warm the global OnceLock cache.
    let _ = oxitls_webpki_roots::webpki_root_certs_arc();

    c.bench_function("root_store_arc_no_alloc", |b| {
        b.iter(|| {
            // Arc::clone increments the reference count — no heap allocation.
            black_box(oxitls_webpki_roots::webpki_root_certs_arc())
        })
    });
}

// ── Bench 4: filtered store — allocation proportional to surviving certs ─────

fn bench_filtered_store_half(c: &mut Criterion) {
    let total = oxitls_webpki_roots::root_cert_count();

    c.bench_function("root_store_filtered_half", |b| {
        b.iter(|| {
            // Accept roughly half the roots. Use Cell to allow interior
            // mutation inside the Fn closure required by webpki_root_certs_filtered.
            let i = Cell::new(0usize);
            let store = oxitls_webpki_roots::webpki_root_certs_filtered(|_| {
                let idx = i.get();
                i.set(idx + 1);
                idx < total / 2
            });
            black_box(store)
        })
    });
}

criterion_group!(
    benches,
    bench_root_store_memory_footprint,
    bench_root_store_cached_clone,
    bench_root_store_arc_no_alloc,
    bench_filtered_store_half,
);
criterion_main!(benches);
