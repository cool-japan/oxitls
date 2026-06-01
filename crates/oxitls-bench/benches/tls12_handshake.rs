//! TLS 1.2 full-handshake benchmarks using the pure-Rust RustCrypto provider.
//!
//! Compares TLS 1.2 full handshake vs TLS 1.3 full handshake latency to
//! quantify the protocol-version overhead.
//!
//! Note: ring / aws-lc-rs are not available as rustls CryptoProviders here
//! because the workspace disables the rustls `ring` and `aws_lc_rs` features
//! to keep the pure-Rust closure intact.  AEAD-level comparisons are in
//! `aead.rs` instead.
//!
//! Run with: `cargo bench -p oxitls-bench --bench tls12_handshake`

mod bench_common;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use std::sync::Arc;

// ── TLS 1.2 Full Handshake — pure provider ────────────────────────────────────

fn bench_tls12_full_handshake(c: &mut Criterion) {
    let fix = bench_common::cert_fixture();
    let provider = bench_common::pure_crypto_provider();
    let client_cfg = Arc::new(bench_common::make_client_config_with_versions(
        provider.clone(),
        fix.root_store.clone(),
        &[&rustls::version::TLS12],
    ));
    let server_cfg = Arc::new(bench_common::make_server_config_with_versions(
        provider.clone(),
        vec![fix.leaf_cert_der.clone()],
        fix.leaf_key_der.clone_key(),
        &[&rustls::version::TLS12],
    ));

    c.bench_function("tls12_full_handshake/pure", |b| {
        b.iter_batched(
            || (client_cfg.clone(), server_cfg.clone()),
            |(cc, sc)| bench_common::sync_handshake(cc, sc, "localhost"),
            BatchSize::SmallInput,
        );
    });
}

// ── TLS 1.2 vs TLS 1.3 comparison ────────────────────────────────────────────

fn bench_tls13_full_handshake(c: &mut Criterion) {
    let fix = bench_common::cert_fixture();
    let provider = bench_common::pure_crypto_provider();
    let client_cfg = Arc::new(bench_common::make_client_config(
        provider.clone(),
        fix.root_store.clone(),
    ));
    let server_cfg = Arc::new(bench_common::make_server_config(
        provider.clone(),
        vec![fix.leaf_cert_der.clone()],
        fix.leaf_key_der.clone_key(),
    ));

    c.bench_function("tls13_full_handshake/pure", |b| {
        b.iter_batched(
            || (client_cfg.clone(), server_cfg.clone()),
            |(cc, sc)| bench_common::sync_handshake(cc, sc, "localhost"),
            BatchSize::SmallInput,
        );
    });
}

// ── Entry point ───────────────────────────────────────────────────────────────

criterion_group!(
    tls12_benches,
    bench_tls12_full_handshake,
    bench_tls13_full_handshake,
);
criterion_main!(tls12_benches);
