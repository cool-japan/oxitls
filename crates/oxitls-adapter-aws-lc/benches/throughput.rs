//! Criterion benchmark: bulk data throughput over an aws-lc-rs TLS connection.
//!
//! Establishes a single TLS 1.3 connection (loopback TCP) and then writes +
//! reads fixed-size payloads to measure record-layer encryption throughput.
//!
//! Run with:
//! ```bash
//! cargo bench -p oxitls-adapter-aws-lc --features aws-lc --bench throughput
//! ```

#[cfg(not(feature = "aws-lc"))]
use criterion::Criterion;
use criterion::{criterion_group, criterion_main};

#[cfg(feature = "aws-lc")]
mod aws_lc_benches {
    use criterion::{BatchSize, BenchmarkId, Criterion};
    use oxitls_adapter_aws_lc::aws_lc_provider;
    use oxitls_rcgen::generate_self_signed_ed25519;
    use rustls::{ClientConfig, RootCertStore, ServerConfig};
    use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    // ── Cert fixture ──────────────────────────────────────────────────────────────

    struct CertFixture {
        cert_der: CertificateDer<'static>,
        key_der: PrivateKeyDer<'static>,
    }

    impl CertFixture {
        fn generate() -> Self {
            let ck = generate_self_signed_ed25519(&["localhost"])
                .expect("bench fixture: cert gen failed");
            let cert_der = CertificateDer::from(ck.cert_der);
            let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.pkcs8_der));
            Self { cert_der, key_der }
        }
    }

    // ── Config builders ───────────────────────────────────────────────────────────

    fn server_cfg(
        cert_der: CertificateDer<'static>,
        key_der: PrivateKeyDer<'static>,
    ) -> Arc<ServerConfig> {
        let cfg = ServerConfig::builder_with_provider(aws_lc_provider())
            .with_safe_default_protocol_versions()
            .expect("server protocol versions")
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .expect("server cert/key");
        Arc::new(cfg)
    }

    fn client_cfg(cert_der: &CertificateDer<'static>) -> Arc<ClientConfig> {
        let mut roots = RootCertStore::empty();
        roots.add(cert_der.clone()).expect("add root");
        let cfg = ClientConfig::builder_with_provider(aws_lc_provider())
            .with_safe_default_protocol_versions()
            .expect("client protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        Arc::new(cfg)
    }

    // ── Bench: write+read a fixed-size payload ─────────────────────────────────

    fn bench_throughput(c: &mut Criterion, payload_bytes: usize, label: &str) {
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        let fixture = CertFixture::generate();

        let srv_cfg = server_cfg(fixture.cert_der.clone(), fixture.key_der.clone_key());
        let cli_cfg = client_cfg(&fixture.cert_der);

        let payload = vec![0xABu8; payload_bytes];

        let mut group = c.benchmark_group("aws_lc_throughput");
        group.throughput(criterion::Throughput::Bytes(payload_bytes as u64));

        group.bench_with_input(
            BenchmarkId::new(label, payload_bytes),
            &payload_bytes,
            |b, _| {
                b.iter_batched(
                    || payload.clone(),
                    |data| {
                        rt.block_on(async {
                            let acceptor = TlsAcceptor::from(srv_cfg.clone());
                            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
                            let addr = listener.local_addr().expect("local addr");

                            let expected_len = data.len();
                            let server_task = tokio::spawn(async move {
                                let (tcp, _) = listener.accept().await.expect("accept");
                                let mut tls = acceptor.accept(tcp).await.expect("tls accept");
                                // Read exactly `expected_len` bytes then echo them.
                                let mut buf = vec![0u8; expected_len];
                                tls.read_exact(&mut buf).await.expect("server read");
                                tls.write_all(&buf).await.expect("server write");
                                tls.flush().await.ok();
                            });

                            let connector = TlsConnector::from(cli_cfg.clone());
                            let tcp = TcpStream::connect(addr).await.expect("connect");
                            let sn = ServerName::try_from("localhost")
                                .expect("server name")
                                .to_owned();
                            let mut tls = connector.connect(sn, tcp).await.expect("tls connect");

                            tls.write_all(&data).await.expect("client write");
                            tls.flush().await.ok();

                            let mut reply = vec![0u8; data.len()];
                            tls.read_exact(&mut reply).await.expect("client read");

                            server_task.await.ok();
                        });
                    },
                    BatchSize::SmallInput,
                );
            },
        );

        group.finish();
    }

    pub fn bench_throughput_1kb(c: &mut Criterion) {
        bench_throughput(c, 1024, "1kb");
    }

    pub fn bench_throughput_64kb(c: &mut Criterion) {
        bench_throughput(c, 65536, "64kb");
    }
}

#[cfg(feature = "aws-lc")]
criterion_group!(
    benches,
    aws_lc_benches::bench_throughput_1kb,
    aws_lc_benches::bench_throughput_64kb
);

#[cfg(not(feature = "aws-lc"))]
criterion_group!(benches, _noop);

#[cfg(not(feature = "aws-lc"))]
fn _noop(_c: &mut Criterion) {}

criterion_main!(benches);
