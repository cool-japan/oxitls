//! Bidirectional TLS 1.3 data transfer throughput benchmarks.
//!
//! Measures client-to-server throughput for 1KB, 64KB, 1MB, and 10MB payloads
//! over an in-memory TLS session using the pure-Rust crypto provider.
//!
//! Run with: `cargo bench -p oxitls-bench --bench throughput`

mod bench_common;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::sync::Arc;

/// Payload sizes to benchmark (bytes).
const PAYLOAD_SIZES: &[usize] = &[1024, 64 * 1024, 1024 * 1024, 10 * 1024 * 1024];

fn bench_tls13_throughput_pure(c: &mut Criterion) {
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

    let mut group = c.benchmark_group("tls13_throughput_pure");
    for &size in PAYLOAD_SIZES {
        let data = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::new("client_to_server", size),
            &data,
            |b, data| {
                b.iter_batched(
                    || {
                        let (client, server) = bench_common::sync_handshake(
                            client_cfg.clone(),
                            server_cfg.clone(),
                            "localhost",
                        );
                        // Return owned copies for the hot loop.
                        let payload = data.clone();
                        (client, server, payload)
                    },
                    |(mut client, mut server, payload): (
                        rustls::ClientConnection,
                        rustls::ServerConnection,
                        Vec<u8>,
                    )| {
                        let received = bench_common::tls_send_client_to_server(
                            &mut client,
                            &mut server,
                            &payload,
                        );
                        std::hint::black_box(received)
                    },
                    criterion::BatchSize::LargeInput,
                );
            },
        );
    }
    group.finish();
}

// ── Entry point ───────────────────────────────────────────────────────────────

criterion_group!(
    name = throughput_benches;
    config = Criterion::default()
        .sample_size(200)
        .measurement_time(std::time::Duration::from_secs(20));
    targets = bench_tls13_throughput_pure,
);
criterion_main!(throughput_benches);
