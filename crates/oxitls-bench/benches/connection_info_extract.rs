//! Benchmark the overhead of `tls_connection_info()` extraction from an
//! established TLS 1.3 stream.
//!
//! The connection is set up ONCE in the bench setup step; only the
//! `tls_connection_info()` call is measured in the hot loop.
//!
//! Uses the synchronous rustls API (via `bench_common`) for a zero-socket
//! in-process handshake, then extracts connection info from the resulting
//! `ClientConnection` and `ServerConnection`.
//!
//! Run with: `cargo bench -p oxitls-bench --bench connection_info_extract`

mod bench_common;

use std::hint::black_box;
use std::sync::Arc;

use criterion::{criterion_group, criterion_main, Criterion};

use oxitls_adapter_rustls_rustcrypto::connection_info_from_state;

// ── Bench 1: extract ConnectionInfo from client-side session ─────────────────

fn bench_connection_info_from_client(c: &mut Criterion) {
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

    // Perform the handshake once — connection is reused across all iterations.
    let (client, _server) = bench_common::sync_handshake(client_cfg, server_cfg, "localhost");

    c.bench_function("connection_info_from_client_session", |b| {
        b.iter(|| {
            let info = connection_info_from_state(&client);
            black_box(info)
        });
    });
}

// ── Bench 2: extract ConnectionInfo from server-side session ─────────────────

fn bench_connection_info_from_server(c: &mut Criterion) {
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

    let (_client, server) = bench_common::sync_handshake(client_cfg, server_cfg, "localhost");

    c.bench_function("connection_info_from_server_session", |b| {
        b.iter(|| {
            let info = connection_info_from_state(&server);
            black_box(info)
        });
    });
}

// ── Bench 3: repeated extraction (amortised cache check) ─────────────────────
//
// Measures whether repeated calls (e.g. HTTP request path) show any overhead
// beyond the first extraction.

fn bench_connection_info_repeated(c: &mut Criterion) {
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

    let (client, _server) = bench_common::sync_handshake(client_cfg, server_cfg, "localhost");

    c.bench_function("connection_info_10x_repeated", |b| {
        b.iter(|| {
            for _ in 0..10 {
                let info = connection_info_from_state(&client);
                black_box(info);
            }
        });
    });
}

// ── Entry point ───────────────────────────────────────────────────────────────

criterion_group!(
    connection_info_benches,
    bench_connection_info_from_client,
    bench_connection_info_from_server,
    bench_connection_info_repeated,
);
criterion_main!(connection_info_benches);
