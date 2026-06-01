//! Benchmark: multi-stream H2 concurrent throughput.
//!
//! Measures combined throughput when 10 concurrent HTTP/2 streams are opened
//! simultaneously, each transferring 1 MiB from client to server.
//!
//! The benchmark establishes a fresh TLS+H2 connection per iteration so that
//! stream multiplexing behaviour is consistently measured from a clean state.
//!
//! Run with: `cargo bench -p oxitls-h2 --bench h2_throughput_multi_stream`

use std::sync::Arc;

use bytes::Bytes;
use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
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
// Multi-stream transfer helper
// ---------------------------------------------------------------------------

const NUM_STREAMS: usize = 10;
const STREAM_PAYLOAD_BYTES: usize = 1_024 * 1_024; // 1 MiB per stream

async fn multi_stream_transfer(server_cfg: Arc<ServerConfig>, client_cfg: Arc<ClientConfig>) {
    // Large duplex buffer to prevent stalling on flow control.
    let buf = NUM_STREAMS * STREAM_PAYLOAD_BYTES + 256 * 1024;
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
    let (mut send_req, client_h2_conn) = client_h2_res.expect("client h2");

    // Server: accept NUM_STREAMS requests and respond with 200 (empty body).
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

    // Client: send NUM_STREAMS concurrent POST requests each with STREAM_PAYLOAD_BYTES.
    let payload = Bytes::from(vec![0u8; STREAM_PAYLOAD_BYTES]);
    let mut response_futures = Vec::with_capacity(NUM_STREAMS);

    for _i in 0..NUM_STREAMS {
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://localhost/data")
            .body(())
            .expect("request build");

        // Reserve flow control before sending.
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

    let total_bytes = (NUM_STREAMS * STREAM_PAYLOAD_BYTES) as u64;
    std::hint::black_box(total_bytes);

    server_task.await.expect("server task");
    conn_task.await.expect("conn task");
}

// ---------------------------------------------------------------------------
// Benchmark
// ---------------------------------------------------------------------------

fn bench_h2_throughput_multi_stream(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let fixture = build_tls_fixture();

    let total_bytes = (NUM_STREAMS * STREAM_PAYLOAD_BYTES) as u64;

    let mut group = c.benchmark_group("h2_multi_stream_throughput");
    group.throughput(Throughput::Bytes(total_bytes));

    group.bench_function("10x1MiB", |b| {
        b.iter_batched(
            || (fixture.server_cfg.clone(), fixture.client_cfg.clone()),
            |(sc, cc)| {
                rt.block_on(multi_stream_transfer(sc, cc));
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
    h2_throughput_multi_benches,
    bench_h2_throughput_multi_stream
);
criterion_main!(h2_throughput_multi_benches);
