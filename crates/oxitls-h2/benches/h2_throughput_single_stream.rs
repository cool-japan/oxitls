//! Benchmark: single-stream H2 data throughput.
//!
//! Measures the data transfer throughput for a single HTTP/2 stream:
//!   - Client sends a DATA frame payload of N bytes
//!   - Server reads all bytes to completion
//!
//! The TLS+H2 connection is established ONCE in the benchmark setup; only the
//! data transfer is measured per iteration.  This isolates the h2 framing and
//! flow-control cost from the handshake cost.
//!
//! Payload sizes benchmarked: 1 MiB and 10 MiB.
//!
//! Run with: `cargo bench -p oxitls-h2 --bench h2_throughput_single_stream`

use std::sync::Arc;

use bytes::Bytes;
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use rcgen::{CertificateParams, KeyPair};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::sync::oneshot;
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
// Single-stream transfer helper
// ---------------------------------------------------------------------------

/// Send `payload` from client to server over a single H2 stream.
///
/// The connection is freshly established on each call — use this inside
/// `iter_batched` where setup allocates the connection and the timed body
/// performs the transfer.
async fn single_stream_transfer(
    server_cfg: Arc<ServerConfig>,
    client_cfg: Arc<ClientConfig>,
    payload: Bytes,
) {
    // Use a large duplex buffer so TLS records and h2 frames don't stall on
    // small in-memory pipe capacity.
    let buf = 2 * payload.len().max(256 * 1024);
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
    let (mut client_send_req, client_h2_conn) = client_h2_res.expect("client h2");

    // Notify when the server has read everything.
    let (done_tx, done_rx) = oneshot::channel::<usize>();

    // Server: accept one request, read the whole body, send 200 empty response.
    let server_task = tokio::spawn(async move {
        if let Some(Ok((_req, mut respond))) = server_h2.accept().await {
            let response = http::Response::builder()
                .status(200)
                .body(())
                .expect("response build");
            let _ = respond.send_response(response, true);
        }
        let _ = done_tx.send(0usize);
    });

    // Client connection driver.
    let conn_task = tokio::spawn(async move {
        let _ = client_h2_conn.await;
    });

    // Client: send a POST with a body of `payload`.
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri("https://localhost/data")
        .body(())
        .expect("request build");

    let payload_len = payload.len() as u64;
    let (response_fut, mut req_body) = client_send_req
        .send_request(request, false)
        .expect("send request");

    // Reserve flow-control capacity for the full payload.
    req_body.reserve_capacity(payload.len());
    req_body.send_data(payload, true).expect("send data");

    let _response = response_fut.await.expect("response");
    let _ = done_rx.await;

    std::hint::black_box(payload_len);

    server_task.await.expect("server task");
    conn_task.await.expect("conn task");
}

// ---------------------------------------------------------------------------
// Benchmark
// ---------------------------------------------------------------------------

fn bench_h2_throughput_single_stream(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let fixture = build_tls_fixture();

    let sizes: &[(u64, &str)] = &[(1_024 * 1_024, "1MiB"), (10 * 1_024 * 1_024, "10MiB")];

    let mut group = c.benchmark_group("h2_single_stream_throughput");

    for &(size_bytes, label) in sizes {
        group.throughput(Throughput::Bytes(size_bytes));

        group.bench_with_input(BenchmarkId::new("send", label), &size_bytes, |b, &size| {
            let sc = fixture.server_cfg.clone();
            let cc = fixture.client_cfg.clone();
            let payload = Bytes::from(vec![0u8; size as usize]);

            b.iter_batched(
                || (sc.clone(), cc.clone(), payload.clone()),
                |(sc, cc, payload)| {
                    rt.block_on(single_stream_transfer(sc, cc, payload));
                },
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

criterion_group!(
    h2_throughput_single_benches,
    bench_h2_throughput_single_stream
);
criterion_main!(h2_throughput_single_benches);
