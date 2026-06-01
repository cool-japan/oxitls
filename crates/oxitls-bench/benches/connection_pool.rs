//! Connection pool reuse benchmarks.
//!
//! Simulates the cost difference between:
//! - "pool hit": `Arc::clone` of a pre-built `ClientConfig` (near-zero cost)
//! - "cold build": constructing a fresh `ClientConfig` from roots each time
//!
//! In real servers, TLS configurations are built once and reused across
//! connections.  This bench quantifies the amortized savings of config
//! caching versus rebuilding per-connection.
//!
//! Run with: `cargo bench -p oxitls-bench --bench connection_pool`

mod bench_common;

use std::sync::Arc;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use oxitls_adapter_rustls_rustcrypto::RustcryptoClientConfigBuilder;

// ── Bench: pool hit (Arc::clone) ─────────────────────────────────────────────

fn bench_connection_pool_hit_arc_clone(c: &mut Criterion) {
    let fix = bench_common::cert_fixture();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(fix.leaf_cert_der.clone()).expect("add root cert");

    let config = Arc::new(
        RustcryptoClientConfigBuilder::new()
            .with_roots(roots)
            .build()
            .expect("client config ok"),
    );

    c.bench_function("connection_pool_hit_arc_clone", |b| {
        b.iter(|| Arc::clone(&config));
    });
}

// ── Bench: cold build (full config construction) ──────────────────────────────

fn bench_connection_cold_build_config(c: &mut Criterion) {
    let fix = bench_common::cert_fixture();

    c.bench_function("connection_cold_build_config", |b| {
        b.iter_batched(
            || {
                let mut roots = rustls::RootCertStore::empty();
                roots.add(fix.leaf_cert_der.clone()).expect("add root cert");
                roots
            },
            |roots| {
                RustcryptoClientConfigBuilder::new()
                    .with_roots(roots)
                    .build()
                    .expect("client config ok")
            },
            BatchSize::SmallInput,
        );
    });
}

// ── Bench: server config construction (pre-TLS accept setup) ─────────────────

fn bench_server_config_construction(c: &mut Criterion) {
    use oxitls_adapter_rustls_rustcrypto::RustcryptoServerConfigBuilder;

    let fix = bench_common::cert_fixture();

    c.bench_function("server_config_cold_build", |b| {
        b.iter_batched(
            || {
                (
                    vec![fix.leaf_cert_der.clone()],
                    fix.leaf_key_der.clone_key(),
                )
            },
            |(certs, key)| {
                RustcryptoServerConfigBuilder::new()
                    .with_cert_and_key(certs, key)
                    .build()
                    .expect("server config ok")
            },
            BatchSize::SmallInput,
        );
    });
}

// ── Bench: server config pool hit (Arc::clone) ────────────────────────────────

fn bench_server_pool_hit_arc_clone(c: &mut Criterion) {
    use oxitls_adapter_rustls_rustcrypto::RustcryptoServerConfigBuilder;

    let fix = bench_common::cert_fixture();

    let config = Arc::new(
        RustcryptoServerConfigBuilder::new()
            .with_cert_and_key(
                vec![fix.leaf_cert_der.clone()],
                fix.leaf_key_der.clone_key(),
            )
            .build()
            .expect("server config ok"),
    );

    c.bench_function("server_pool_hit_arc_clone", |b| {
        b.iter(|| Arc::clone(&config));
    });
}

// ── Entry point ───────────────────────────────────────────────────────────────

criterion_group!(
    pool_benches,
    bench_connection_pool_hit_arc_clone,
    bench_connection_cold_build_config,
    bench_server_config_construction,
    bench_server_pool_hit_arc_clone,
);
criterion_main!(pool_benches);
