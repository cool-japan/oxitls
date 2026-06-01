//! H2 data-transfer throughput over TLS benchmark.
//!
//! Measures end-to-end data throughput for a single HTTP/2 stream tunnelled
//! through a TLS 1.3 loopback connection.
//!
//! Each iteration:
//! 1. Establishes a TLS 1.3 connection (h2 ALPN) over an in-memory duplex.
//! 2. Completes the H2 connection handshake (SETTINGS exchange).
//! 3. Opens one HTTP/2 stream and sends `N` bytes as POST body.
//! 4. Server reads the body, responds 200, handshake considered complete.
//!
//! This isolates H2-over-TLS framing + flow-control cost from bare TLS
//! overhead.  Compare with `h2_over_tls.rs` for the pure-handshake cost.
//!
//! Payload sizes benchmarked: 64 KiB and 1 MiB.
//!
//! Run with: `cargo bench -p oxitls-bench --bench h2_tls_throughput`

mod bench_common;

use std::sync::Arc;

use bytes::Bytes;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rustls::{ClientConfig, ServerConfig};
use rustls_pki_types::ServerName;
use tokio::sync::oneshot;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use oxitls_h2::{h2_client_handshake, h2_server_handshake};

// ── Payload sizes ─────────────────────────────────────────────────────────────

const PAYLOAD_SIZES: &[(u64, &str)] = &[(64 * 1024, "64KiB"), (1024 * 1024, "1MiB")];

// ── TLS config with h2 ALPN ───────────────────────────────────────────────────

fn make_h2_client_config(
    provider: Arc<rustls::crypto::CryptoProvider>,
    root_store: rustls::RootCertStore,
) -> Arc<ClientConfig> {
    let mut cfg = bench_common::make_client_config(provider, root_store);
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    Arc::new(cfg)
}

fn make_h2_server_config(
    provider: Arc<rustls::crypto::CryptoProvider>,
    certs: Vec<rustls_pki_types::CertificateDer<'static>>,
    key: rustls_pki_types::PrivateKeyDer<'static>,
) -> Arc<ServerConfig> {
    let mut cfg = bench_common::make_server_config(provider, certs, key);
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    Arc::new(cfg)
}

// ── Transfer helper ───────────────────────────────────────────────────────────

/// Send `payload` from client to server over a single H2 stream on a fresh
/// TLS connection.  Measures the full round-trip including TLS handshake,
/// H2 SETTINGS exchange, and DATA frame delivery.
async fn h2_tls_single_stream_transfer(
    server_cfg: Arc<ServerConfig>,
    client_cfg: Arc<ClientConfig>,
    payload: Bytes,
) {
    // Duplex pipe sized to hold the whole payload plus H2 framing headroom so
    // the in-memory pipe never stalls on capacity.
    let buf = 2 * payload.len().max(256 * 1024);
    let (client_io, server_io) = tokio::io::duplex(buf);

    let acceptor = TlsAcceptor::from(server_cfg);
    let connector = TlsConnector::from(client_cfg);
    let sn = ServerName::try_from("localhost").expect("server name");

    // TLS handshake — both sides in parallel.
    let (server_tls_res, client_tls_res) =
        tokio::join!(acceptor.accept(server_io), connector.connect(sn, client_io),);

    let server_tls = server_tls_res.expect("server TLS handshake");
    let client_tls = client_tls_res.expect("client TLS handshake");

    // H2 connection handshake (SETTINGS exchange).
    let (server_h2_res, client_h2_res) = tokio::join!(
        h2_server_handshake(server_tls),
        h2_client_handshake(client_tls),
    );

    let mut server_h2 = server_h2_res.expect("server h2 handshake");
    let (mut client_send_req, client_h2_conn) = client_h2_res.expect("client h2 handshake");

    // Oneshot to signal that the server has finished accepting the stream.
    let (done_tx, done_rx) = oneshot::channel::<()>();

    // Server task: accept one stream, send 200 empty response, signal done.
    let server_task = tokio::spawn(async move {
        if let Some(Ok((_req, mut respond))) = server_h2.accept().await {
            let response = http::Response::builder()
                .status(200)
                .body(())
                .expect("response build");
            let _ = respond.send_response(response, true);
        }
        let _ = done_tx.send(());
    });

    // H2 connection driver: must be polled or the connection stalls.
    let conn_task = tokio::spawn(async move {
        let _ = client_h2_conn.await;
    });

    // Client: POST with the full payload as the request body.
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri("https://localhost/data")
        .body(())
        .expect("request build");

    let payload_len = payload.len() as u64;
    let (response_fut, mut req_body) = client_send_req
        .send_request(request, false)
        .expect("send request");

    // Reserve flow-control window and send DATA frame.
    req_body.reserve_capacity(payload.len());
    req_body.send_data(payload, true).expect("send data");

    // Await the server 200 response and done signal.
    let _response = response_fut.await.expect("response future");
    let _ = done_rx.await;

    std::hint::black_box(payload_len);

    server_task.await.expect("server task join");
    conn_task.await.expect("conn task join");
}

// ── Benchmark ─────────────────────────────────────────────────────────────────

fn bench_h2_tls_throughput(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");

    let fix = bench_common::cert_fixture();
    let provider = bench_common::pure_crypto_provider();

    let client_cfg = make_h2_client_config(provider.clone(), fix.root_store.clone());
    let server_cfg = make_h2_server_config(
        provider.clone(),
        vec![fix.leaf_cert_der.clone()],
        fix.leaf_key_der.clone_key(),
    );

    let mut group = c.benchmark_group("h2_tls_throughput");

    for &(size_bytes, label) in PAYLOAD_SIZES {
        group.throughput(Throughput::Bytes(size_bytes));
        group.bench_with_input(BenchmarkId::new("send", label), &size_bytes, |b, &size| {
            let sc = server_cfg.clone();
            let cc = client_cfg.clone();
            let payload = Bytes::from(vec![0u8; size as usize]);

            b.iter_batched(
                || (sc.clone(), cc.clone(), payload.clone()),
                |(sc, cc, payload)| {
                    rt.block_on(h2_tls_single_stream_transfer(sc, cc, payload));
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

// ── Entry point ───────────────────────────────────────────────────────────────

criterion_group!(h2_tls_throughput_benches, bench_h2_tls_throughput);
criterion_main!(h2_tls_throughput_benches);
