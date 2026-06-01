//! Benchmark: memory and scheduling behaviour under 100 concurrent H2 streams.
//!
//! Opens 100 simultaneous HTTP/2 streams over a single TLS+H2 connection,
//! each transferring 1 KiB of data.  Wall-clock time is the primary metric.
//! Memory pressure is implicitly captured: if the process OOMs, the benchmark
//! will fail loudly.
//!
//! Run with: `cargo bench -p oxitls-h2 --bench h2_memory_high_concurrency`

use std::sync::Arc;

use bytes::Bytes;
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
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
// High-concurrency stream exercise
// ---------------------------------------------------------------------------

const NUM_STREAMS: usize = 100;
const STREAM_PAYLOAD_BYTES: usize = 1024; // 1 KiB per stream

async fn high_concurrency_streams(server_cfg: Arc<ServerConfig>, client_cfg: Arc<ClientConfig>) {
    // Duplex buffer must be large enough for all concurrent stream DATA frames
    // plus TLS record overhead.
    let buf = NUM_STREAMS * STREAM_PAYLOAD_BYTES * 4;
    let (client_io, server_io) = tokio::io::duplex(buf);

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

    // Server: accept all NUM_STREAMS requests and send empty 200 responses.
    let server_task = tokio::spawn(async move {
        for _ in 0..NUM_STREAMS {
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

    // Client connection driver.
    let conn_task = tokio::spawn(async move {
        let _ = client_h2_conn.await;
    });

    // Client: open NUM_STREAMS concurrent streams each with a 1 KiB payload.
    let payload = Bytes::from(vec![0xabu8; STREAM_PAYLOAD_BYTES]);
    let mut response_futures = Vec::with_capacity(NUM_STREAMS);
    let mut send_req = send_req;

    for _i in 0..NUM_STREAMS {
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://localhost/data")
            .body(())
            .expect("request build");

        let (response_fut, mut req_body) =
            send_req.send_request(request, false).expect("send request");

        req_body.reserve_capacity(payload.len());
        req_body
            .send_data(payload.clone(), true)
            .expect("send data");

        response_futures.push(response_fut);
    }

    // Await all responses concurrently.
    let responses = futures::future::join_all(response_futures).await;
    for res in responses {
        let _ = res.expect("response");
    }

    std::hint::black_box(NUM_STREAMS);

    server_task.await.expect("server task");
    conn_task.await.expect("conn task");
}

// ---------------------------------------------------------------------------
// Benchmark
// ---------------------------------------------------------------------------

fn bench_h2_memory_high_concurrency(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let fixture = build_tls_fixture();

    let mut group = c.benchmark_group("h2_memory_high_concurrency");

    group.bench_function("100_streams_1KiB", |b| {
        b.iter_batched(
            || (fixture.server_cfg.clone(), fixture.client_cfg.clone()),
            |(sc, cc)| {
                rt.block_on(high_concurrency_streams(sc, cc));
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

criterion_group!(
    h2_memory_high_concurrency_benches,
    bench_h2_memory_high_concurrency
);
criterion_main!(h2_memory_high_concurrency_benches);
