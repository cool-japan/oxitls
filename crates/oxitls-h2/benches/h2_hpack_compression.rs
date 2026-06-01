//! Benchmark: HPACK header compression throughput.
//!
//! Measures the throughput of sending HTTP/2 requests with different header
//! set sizes through the HPACK encoder/decoder pipeline.  Header sets of 10,
//! 30, and 100 headers are exercised.
//!
//! `criterion::Throughput::Bytes` is set to the raw (uncompressed) header byte
//! count so the throughput chart implicitly expresses compression ratio: the
//! wall time of processing N raw bytes via HPACK.
//!
//! Each iteration opens a new H2 stream over a pre-established connection so
//! only the HPACK encode/decode path is measured, not the handshake.
//!
//! Run with: `cargo bench -p oxitls-h2 --bench h2_hpack_compression`

use std::sync::Arc;

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use rcgen::{CertificateParams, KeyPair};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use oxitls_h2::{h2_client_handshake, h2_server_handshake};

// ---------------------------------------------------------------------------
// TLS config fixture
// ---------------------------------------------------------------------------

struct TlsFixture {
    server_cfg: Arc<ServerConfig>,
    client_cfg: Arc<ClientConfig>,
}

fn build_tls_fixture() -> TlsFixture {
    let kp = KeyPair::generate().expect("keygen");
    let cert = CertificateParams::new(vec!["localhost".into()])
        .expect("cert params")
        .self_signed(&kp)
        .expect("self-sign");

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(kp.serialize_der().into());

    let provider = oxitls_adapter_rustls_rustcrypto::pure_provider();

    let mut server_cfg = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .expect("server cert");
    server_cfg.alpn_protocols = vec![b"h2".to_vec()];

    let mut root_store = RootCertStore::empty();
    root_store.add(cert_der).expect("root cert");
    let mut client_cfg = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .with_root_certificates(root_store)
        .with_no_client_auth();
    client_cfg.alpn_protocols = vec![b"h2".to_vec()];

    TlsFixture {
        server_cfg: Arc::new(server_cfg),
        client_cfg: Arc::new(client_cfg),
    }
}

// ---------------------------------------------------------------------------
// Header set builders
// ---------------------------------------------------------------------------

/// Build a realistic HTTP request header map with `n` headers.
///
/// Includes the mandatory `:method`, `:path`, `:scheme`, and `:authority`
/// pseudo-headers.  Additional headers mimic common real-world HTTP requests
/// (accept, user-agent, content-type, etc.).  If `n` exceeds the predefined
/// pool, synthetic `x-custom-<k>: value-<k>` headers are appended.
fn build_headers(n: usize) -> http::HeaderMap {
    // Pre-defined realistic headers.
    let pool: Vec<(&str, &str)> = vec![
        (
            "accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        ),
        ("accept-encoding", "gzip, deflate, br"),
        ("accept-language", "en-US,en;q=0.9,ja;q=0.8"),
        ("cache-control", "no-cache"),
        ("content-type", "application/json"),
        ("user-agent", "Mozilla/5.0 (compatible; oxitls-bench/0.1)"),
        ("authorization", "Bearer eyJhbGciOiJSUzI1NiJ9.dGVzdA.dGVzdA"),
        ("x-request-id", "550e8400-e29b-41d4-a716-446655440000"),
        ("x-forwarded-for", "198.51.100.1"),
        ("x-forwarded-proto", "https"),
        ("x-real-ip", "198.51.100.1"),
        ("referer", "https://example.com/previous-page"),
        ("origin", "https://example.com"),
        ("pragma", "no-cache"),
        ("connection", "keep-alive"),
        ("host", "api.example.com"),
        ("content-length", "512"),
        ("if-modified-since", "Wed, 21 Oct 2024 07:28:00 GMT"),
        (
            "if-none-match",
            "\"33a64df551425fcc55e4d42a148795d9f25f89d4\"",
        ),
        ("cookie", "session_id=abc123; user_pref=dark_mode; lang=en"),
        ("sec-fetch-dest", "document"),
        ("sec-fetch-mode", "navigate"),
        ("sec-fetch-site", "same-origin"),
        (
            "sec-ch-ua",
            "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\"",
        ),
        ("sec-ch-ua-mobile", "?0"),
        ("sec-ch-ua-platform", "\"Linux\""),
        ("upgrade-insecure-requests", "1"),
        ("dnt", "1"),
        ("te", "trailers"),
        ("via", "1.1 edge-proxy-01"),
    ];

    let mut map = http::HeaderMap::new();
    for i in 0..n {
        if i < pool.len() {
            let (name, value) = pool[i];
            map.insert(
                http::header::HeaderName::from_bytes(name.as_bytes()).expect("header name"),
                http::header::HeaderValue::from_static(value),
            );
        } else {
            // Synthetic overflow headers.
            let name_str = format!("x-custom-{i}");
            let value_str = format!("value-{i}-padding-to-make-it-realistic");
            map.insert(
                http::header::HeaderName::from_bytes(name_str.as_bytes())
                    .expect("custom header name"),
                http::HeaderValue::from_str(&value_str).expect("custom header value"),
            );
        }
    }
    map
}

/// Count raw bytes in a header map (name length + 2 for ": " + value length + 2 for "\r\n").
fn raw_header_bytes(map: &http::HeaderMap) -> u64 {
    map.iter()
        .map(|(k, v)| k.as_str().len() as u64 + 2 + v.len() as u64 + 2)
        .sum()
}

// ---------------------------------------------------------------------------
// HPACK round-trip helper
// ---------------------------------------------------------------------------

async fn hpack_roundtrip(
    server_cfg: Arc<ServerConfig>,
    client_cfg: Arc<ClientConfig>,
    headers: http::HeaderMap,
    n_streams: usize,
) {
    let (client_io, server_io) = tokio::io::duplex(2 * 1024 * 1024);

    let acceptor = TlsAcceptor::from(server_cfg);
    let connector = TlsConnector::from(client_cfg);
    let sn = ServerName::try_from("localhost").expect("server name");

    let (server_tls_res, client_tls_res) =
        tokio::join!(acceptor.accept(server_io), connector.connect(sn, client_io),);

    let server_tls = server_tls_res.expect("server TLS");
    let client_tls = client_tls_res.expect("client TLS");

    let (server_h2_res, client_h2_res) = tokio::join!(
        h2_server_handshake(server_tls),
        h2_client_handshake(client_tls),
    );

    let mut server_h2 = server_h2_res.expect("server h2");
    let (send_req, client_h2_conn) = client_h2_res.expect("client h2");

    let server_task = tokio::spawn(async move {
        for _ in 0..n_streams {
            match server_h2.accept().await {
                Some(Ok((_req, mut respond))) => {
                    let rsp = http::Response::builder()
                        .status(200)
                        .body(())
                        .expect("response build");
                    let _ = respond.send_response(rsp, true);
                }
                _ => break,
            }
        }
    });

    let conn_task = tokio::spawn(async move {
        let _ = client_h2_conn.await;
    });

    let mut send_req = send_req;
    let mut response_futures = Vec::with_capacity(n_streams);

    for _ in 0..n_streams {
        let mut request = http::Request::builder()
            .method(http::Method::GET)
            .uri("https://localhost/bench")
            .body(())
            .expect("request build");

        // Inject our custom header set into the request.
        *request.headers_mut() = headers.clone();

        let (response_fut, _req_body) = send_req.send_request(request, true).expect("send request");
        response_futures.push(response_fut);
    }

    let responses = futures::future::join_all(response_futures).await;
    for res in responses {
        let _ = res.expect("response");
    }

    server_task.await.expect("server task");
    conn_task.await.expect("conn task");
}

// ---------------------------------------------------------------------------
// Benchmark
// ---------------------------------------------------------------------------

fn bench_h2_hpack_compression(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let fixture = build_tls_fixture();

    let header_counts: &[usize] = &[10, 30, 100];
    // Send N_STREAMS requests per iteration so each sample has enough work to
    // produce stable timing.
    let n_streams_per_iter = 5usize;

    let mut group = c.benchmark_group("h2_hpack_compression");

    for &n_headers in header_counts {
        let headers = build_headers(n_headers);
        let raw_bytes = raw_header_bytes(&headers) * n_streams_per_iter as u64;

        group.throughput(Throughput::Bytes(raw_bytes));

        group.bench_with_input(
            BenchmarkId::new("headers", n_headers),
            &n_headers,
            |b, _| {
                let sc = fixture.server_cfg.clone();
                let cc = fixture.client_cfg.clone();
                let hdrs = headers.clone();

                b.iter_batched(
                    || (sc.clone(), cc.clone(), hdrs.clone()),
                    |(sc, cc, h)| {
                        rt.block_on(hpack_roundtrip(sc, cc, h, n_streams_per_iter));
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

criterion_group!(h2_hpack_benches, bench_h2_hpack_compression);
criterion_main!(h2_hpack_benches);
