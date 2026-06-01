//! HTTP/1.1 over TLS full-request latency benchmarks.
//!
//! Measures the end-to-end latency of a complete HTTPS request (TCP connect +
//! TLS handshake + HTTP send + HTTP receive) using oxihttp as the HTTP layer.
//!
//! The server is started once per benchmark group and reused across all
//! iterations so that connection-pool reuse is measured (amortised cost).
//!
//! Compare against raw TLS benchmarks in `handshake.rs` to isolate HTTP overhead.
//!
//! Payload sizes benchmarked: 1 B, 1 KB, 64 KB.
//!
//! Run with: `cargo bench -p oxitls-bench --bench http_latency`

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::Request as HyperRequest;
use hyper::Response as HyperResponse;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::TcpListener;
use tokio::runtime::Runtime;
use tokio_rustls::TlsAcceptor;

use oxihttp::ClientBuilder;

// ── TLS server helpers ────────────────────────────────────────────────────────

/// Spawn a minimal TLS+HTTP/1.1 server on an ephemeral port.
///
/// The server echoes the request body back as the response body (for POST) or
/// returns a static payload (for GET).  Returns the bound `SocketAddr` and the
/// raw cert DER bytes for building a trusting client.
async fn spawn_tls_echo_server() -> (SocketAddr, Vec<u8>) {
    let ck =
        oxitls_rcgen::generate_self_signed_ed25519(&["localhost"]).expect("bench: cert gen failed");

    let cert = CertificateDer::from(ck.cert_der.clone());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.pkcs8_der));

    let server_cfg = oxitls::tls13::ServerBuilder::new()
        .with_der_cert_and_key(vec![cert], key)
        .build()
        .expect("bench: server TLS config");

    let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bench: TCP bind");
    let addr = listener.local_addr().expect("bench: local addr");

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let acc = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls_stream) = acc.accept(stream).await else {
                    return;
                };
                let io = hyper_util::rt::TokioIo::new(tls_stream);
                let _ = http1::Builder::new()
                    .serve_connection(io, service_fn(echo_handler))
                    .await;
            });
        }
    });

    (addr, ck.cert_der)
}

async fn echo_handler(
    req: HyperRequest<hyper::body::Incoming>,
) -> Result<HyperResponse<Full<Bytes>>, std::convert::Infallible> {
    use http_body_util::BodyExt;
    let body = req
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes();
    Ok(HyperResponse::new(Full::new(body)))
}

// ── Payload sizes ─────────────────────────────────────────────────────────────

const PAYLOAD_SIZES: &[(usize, &str)] = &[(1, "1B"), (1024, "1KB"), (64 * 1024, "64KB")];

// ── Benchmarks ────────────────────────────────────────────────────────────────

fn bench_https_post_latency(c: &mut Criterion) {
    let rt = Runtime::new().expect("bench: tokio runtime");

    // Start the server once; reuse across all iterations.
    let (addr, cert_der) = rt.block_on(spawn_tls_echo_server());
    let port = addr.port();
    let base_url = format!("https://localhost:{port}/echo");

    // Build the client once (connection pooling enabled by default).
    let client = ClientBuilder::new()
        .with_trusted_cert_der(cert_der)
        .build_https()
        .expect("bench: build_https");

    let mut group = c.benchmark_group("https_post_latency");
    for &(size, label) in PAYLOAD_SIZES {
        let payload = Bytes::from(vec![0u8; size]);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("payload", label), &payload, |b, pl| {
            b.to_async(&rt).iter(|| async {
                let resp = client
                    .post(&base_url)
                    .expect("bench: POST builder")
                    .body(pl.clone())
                    .send()
                    .await
                    .expect("bench: POST send");
                // Drain the body to ensure full round-trip is measured.
                let _ = resp.body_bytes().await.expect("bench: drain body");
            });
        });
    }
    group.finish();
}

fn bench_https_get_latency(c: &mut Criterion) {
    let rt = Runtime::new().expect("bench: tokio runtime");

    let (addr, cert_der) = rt.block_on(spawn_tls_echo_server());
    let port = addr.port();
    // GET /ping returns an empty echo (no body sent).
    let url = format!("https://localhost:{port}/ping");

    let client = ClientBuilder::new()
        .with_trusted_cert_der(cert_der)
        .build_https()
        .expect("bench: build_https");

    let mut group = c.benchmark_group("https_get_latency");
    group.bench_function("empty_body", |b| {
        b.to_async(&rt).iter(|| async {
            let resp = client
                .get(&url)
                .expect("bench: GET builder")
                .send()
                .await
                .expect("bench: GET send");
            let _ = resp.body_bytes().await.expect("bench: drain body");
        });
    });
    group.finish();
}

criterion_group!(
    http_latency_benches,
    bench_https_post_latency,
    bench_https_get_latency
);
criterion_main!(http_latency_benches);
