//! Benchmark comparing 0-RTT (resumed with OxiTicketer) handshake latency
//! against a fresh TLS 1.3 full handshake.
//!
//! Both benchmarks use an in-process TCP loopback (same pattern as handshake.rs)
//! so they can be run without any external infrastructure.
//!
//! Run with: `cargo bench -p oxitls-bench --bench zero_rtt_handshake`

use std::sync::Arc;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

use oxitls::tls13::{server::tokio_acceptor, ServerBuilder};
use oxitls::OxiTicketer;
use oxitls_rcgen::generate_self_signed_ed25519;

// ── Cert fixture ──────────────────────────────────────────────────────────────

struct CertFixture {
    cert_der: CertificateDer<'static>,
    key_der: PrivateKeyDer<'static>,
}

impl CertFixture {
    fn generate() -> Self {
        let ck =
            generate_self_signed_ed25519(&["localhost"]).expect("bench fixture: cert gen failed");
        let cert_der = CertificateDer::from(ck.cert_der);
        let key_der = PrivateKeyDer::Pkcs8(ck.pkcs8_der.into());
        Self { cert_der, key_der }
    }
}

// ── Provider + client config helpers ─────────────────────────────────────────

fn pure_provider() -> Arc<rustls::crypto::CryptoProvider> {
    oxitls_adapter_rustls_rustcrypto::pure_provider()
}

fn client_cfg_for(cert_der: &CertificateDer<'static>) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(cert_der.clone()).expect("add root cert");
    Arc::new(
        ClientConfig::builder_with_provider(pure_provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3 unsupported")
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Bench 1: Full TLS 1.3 handshake (baseline)
// ─────────────────────────────────────────────────────────────────────────────

fn bench_full_tls13(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let fixture = CertFixture::generate();
    let cert_der = fixture.cert_der.clone();
    let key_der = fixture.key_der.clone_key();

    let server_cfg = ServerBuilder::new()
        .with_der_cert_and_key(vec![cert_der.clone()], key_der)
        .build()
        .expect("server config");
    let client_cfg = client_cfg_for(&cert_der);

    c.bench_function("full_tls13", |b| {
        b.iter_batched(
            || (),
            |()| {
                rt.block_on(async {
                    let acceptor = tokio_acceptor(server_cfg.clone());
                    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
                    let addr = listener.local_addr().expect("local addr");

                    let server_task = tokio::spawn(async move {
                        let (tcp, _) = listener.accept().await.expect("accept");
                        let mut tls = acceptor.accept(tcp).await.expect("tls accept");
                        let mut buf = [0u8; 1];
                        tls.read_exact(&mut buf).await.ok();
                        tls.write_all(&buf).await.ok();
                        tls.flush().await.ok();
                    });

                    let connector = TlsConnector::from(client_cfg.clone());
                    let tcp = TcpStream::connect(addr).await.expect("connect");
                    let sn = ServerName::try_from("localhost").expect("server name");
                    let mut tls = connector.connect(sn, tcp).await.expect("tls connect");
                    tls.write_all(&[0x01]).await.ok();
                    tls.flush().await.ok();
                    let mut reply = [0u8; 1];
                    tls.read_exact(&mut reply).await.ok();

                    server_task.await.ok();
                });
            },
            BatchSize::SmallInput,
        );
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Bench 2: Resumed handshake via OxiTicketer (session ticket / 0-RTT path)
// ─────────────────────────────────────────────────────────────────────────────

fn bench_resumed_tls13(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let fixture = CertFixture::generate();
    let cert_der = fixture.cert_der.clone();
    let key_der = fixture.key_der.clone_key();

    let ticketer = Arc::new(OxiTicketer::new().expect("ticketer"));
    let server_cfg = ServerBuilder::new()
        .with_der_cert_and_key(vec![cert_der.clone()], key_der)
        .with_ticketer(ticketer)
        .build()
        .expect("server config with ticketer");
    let client_cfg = client_cfg_for(&cert_der);

    c.bench_function("resumed_tls13_via_oxiticketer", |b| {
        b.iter_batched(
            || (),
            |()| {
                rt.block_on(async {
                    let acceptor = tokio_acceptor(server_cfg.clone());
                    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
                    let addr = listener.local_addr().expect("local addr");

                    let server_task = tokio::spawn(async move {
                        let (tcp, _) = listener.accept().await.expect("accept");
                        let mut tls = acceptor.accept(tcp).await.expect("tls accept");
                        let mut buf = [0u8; 1];
                        tls.read_exact(&mut buf).await.ok();
                        tls.write_all(&buf).await.ok();
                        tls.flush().await.ok();
                    });

                    let connector = TlsConnector::from(client_cfg.clone());
                    let tcp = TcpStream::connect(addr).await.expect("connect");
                    let sn = ServerName::try_from("localhost").expect("server name");
                    let mut tls = connector.connect(sn, tcp).await.expect("tls connect");
                    tls.write_all(&[0x02]).await.ok();
                    tls.flush().await.ok();
                    let mut reply = [0u8; 1];
                    tls.read_exact(&mut reply).await.ok();

                    server_task.await.ok();
                });
            },
            BatchSize::SmallInput,
        );
    });
}

// ─────────────────────────────────────────────────────────────────────────────

criterion_group!(zero_rtt_benches, bench_full_tls13, bench_resumed_tls13);
criterion_main!(zero_rtt_benches);
