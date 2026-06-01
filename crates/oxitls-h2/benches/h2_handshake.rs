//! Benchmark: full TLS+H2 handshake latency.
//!
//! Measures the round-trip cost of:
//!   1. TLS 1.3 handshake (with ALPN "h2")
//!   2. h2 SETTINGS frame exchange (client and server connection prefaces)
//!
//! Each iteration establishes a fresh in-memory duplex stream and performs
//! the complete TLS+H2 handshake from scratch so that connection setup cost
//! is accurately captured.
//!
//! Run with: `cargo bench -p oxitls-h2 --bench h2_handshake`

use std::sync::Arc;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use rcgen::{CertificateParams, KeyPair};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use oxitls_h2::{h2_client_handshake, h2_server_handshake};

// ---------------------------------------------------------------------------
// TLS config fixture with ALPN "h2"
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
// Benchmark: full TLS+H2 handshake (including SETTINGS exchange)
// ---------------------------------------------------------------------------

fn bench_h2_full_handshake(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let fixture = build_tls_fixture();

    let server_cfg = fixture.server_cfg.clone();
    let client_cfg = fixture.client_cfg.clone();

    c.bench_function("h2_full_handshake", |b| {
        b.iter_batched(
            || (server_cfg.clone(), client_cfg.clone()),
            |(sc, cc)| {
                rt.block_on(async {
                    // In-memory duplex stream — no real TCP needed.
                    let (client_io, server_io) = tokio::io::duplex(256 * 1024);

                    let acceptor = TlsAcceptor::from(sc);
                    let connector = TlsConnector::from(cc);
                    let sn = ServerName::try_from("localhost").expect("server name");

                    // Run TLS handshake on both sides concurrently.
                    let (server_tls_res, client_tls_res) =
                        tokio::join!(acceptor.accept(server_io), connector.connect(sn, client_io),);

                    let server_tls = server_tls_res.expect("server TLS");
                    let client_tls = client_tls_res.expect("client TLS");

                    // h2 handshake (SETTINGS exchange) on both sides concurrently.
                    let (server_h2_res, client_h2_res) = tokio::join!(
                        h2_server_handshake(server_tls),
                        h2_client_handshake(client_tls),
                    );

                    let server_h2 = server_h2_res.expect("server h2");
                    let (send_req, client_conn) = client_h2_res.expect("client h2");

                    // Drive the client connection briefly to confirm the first
                    // stream is ready (h2 SETTINGS ACK exchange complete).
                    let _send_req_ready = send_req.ready().await.expect("send_req ready");

                    // Cleanly drop everything.
                    drop(server_h2);
                    drop(client_conn);

                    std::hint::black_box(())
                })
            },
            BatchSize::SmallInput,
        );
    });
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

criterion_group!(h2_handshake_benches, bench_h2_full_handshake);
criterion_main!(h2_handshake_benches);
