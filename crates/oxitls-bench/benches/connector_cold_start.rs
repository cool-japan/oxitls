//! Benchmark `connector_with_webpki_roots()` cold-start vs cached cost.
//!
//! - "cold": create a brand-new `RustcryptoConnector` from the full webpki
//!   root store on every iteration (full `webpki_root_certs()` + config build).
//! - "cached": `Arc::clone` of a pre-built config — measures the cheap path
//!   that production code should use.
//!
//! Note: bench files may use `.unwrap()` / `.expect()` (not production code).
//!
//! Run with: `cargo bench -p oxitls-bench --bench connector_cold_start`

use std::hint::black_box;
use std::sync::Arc;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};

use oxitls::connector_with_webpki_roots;
use oxitls_adapter_rustls_rustcrypto::RustcryptoClientConfigBuilder;

// ── Bench 1: connector_with_webpki_roots() cold (rebuild every iter) ─────────

fn bench_connector_cold_start(c: &mut Criterion) {
    c.bench_function("connector_cold_start", |b| {
        b.iter(|| {
            let conn = connector_with_webpki_roots().unwrap();
            black_box(conn)
        });
    });
}

// ── Bench 2: webpki_root_certs() + config build (raw path without the helper) ─

fn bench_webpki_root_certs_build(c: &mut Criterion) {
    c.bench_function("webpki_root_certs_config_build", |b| {
        b.iter(|| {
            let root_store = oxitls_webpki_roots::webpki_root_certs();
            let cfg = RustcryptoClientConfigBuilder::new()
                .with_roots(root_store)
                .build()
                .unwrap();
            black_box(cfg)
        });
    });
}

// ── Bench 3: Arc::clone of cached config (the zero-cost production path) ──────

fn bench_connector_cached_arc_clone(c: &mut Criterion) {
    // Build once outside the hot loop.
    let cached = Arc::new(connector_with_webpki_roots().unwrap());

    c.bench_function("connector_cached_arc_clone", |b| {
        b.iter(|| {
            let cloned = Arc::clone(&cached);
            black_box(cloned)
        });
    });
}

// ── Bench 4: cold start batched — shows iter_batched vs iter amortisation ──────

fn bench_connector_cold_start_batched(c: &mut Criterion) {
    c.bench_function("connector_cold_start_batched", |b| {
        b.iter_batched(
            || (),
            |()| {
                let conn = connector_with_webpki_roots().unwrap();
                black_box(conn)
            },
            BatchSize::SmallInput,
        );
    });
}

// ── Entry point ───────────────────────────────────────────────────────────────

criterion_group!(
    connector_cold_start_benches,
    bench_connector_cold_start,
    bench_webpki_root_certs_build,
    bench_connector_cached_arc_clone,
    bench_connector_cold_start_batched,
);
criterion_main!(connector_cold_start_benches);
