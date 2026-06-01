//! Criterion benchmark: TLS 1.3 full handshake with the aws-lc-rs provider.
//!
//! Uses a TCP loopback on an ephemeral port (same pattern as `oxitls-bench`)
//! so both the server and client tasks run concurrently inside a Tokio runtime.
//!
//! Run with:
//! ```bash
//! cargo bench -p oxitls-adapter-aws-lc --features aws-lc --bench handshake
//! ```

#[cfg(not(feature = "aws-lc"))]
use criterion::Criterion;
use criterion::{criterion_group, criterion_main};

#[cfg(feature = "aws-lc")]
mod aws_lc_benches {
    use criterion::{BatchSize, Criterion};
    use oxitls_adapter_aws_lc::aws_lc_provider;
    use oxitls_rcgen::generate_self_signed_ed25519;
    use rustls::{ClientConfig, RootCertStore, ServerConfig};
    use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    // ── Shared cert fixture ───────────────────────────────────────────────────────

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

    fn aws_lc_server_cfg(
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

    fn aws_lc_client_cfg(cert_der: &CertificateDer<'static>) -> Arc<ClientConfig> {
        let mut roots = RootCertStore::empty();
        roots.add(cert_der.clone()).expect("add root");
        let cfg = ClientConfig::builder_with_provider(aws_lc_provider())
            .with_safe_default_protocol_versions()
            .expect("client protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        Arc::new(cfg)
    }

    // ── Bench: full TLS 1.3 handshake (aws-lc provider, loopback TCP) ────────────

    pub fn bench_aws_lc_tls13_handshake(c: &mut Criterion) {
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        let fixture = CertFixture::generate();

        let server_cfg = aws_lc_server_cfg(fixture.cert_der.clone(), fixture.key_der.clone_key());
        let client_cfg = aws_lc_client_cfg(&fixture.cert_der);

        c.bench_function("aws_lc_tls13_full_handshake", |b| {
            b.iter_batched(
                || (),
                |()| {
                    rt.block_on(async {
                        let acceptor = TlsAcceptor::from(server_cfg.clone());
                        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
                        let addr = listener.local_addr().expect("local addr");

                        let server_task = tokio::spawn(async move {
                            let (tcp, _) = listener.accept().await.expect("accept");
                            let mut tls = acceptor.accept(tcp).await.expect("tls accept");
                            // Echo one byte to complete the handshake.
                            let mut buf = [0u8; 1];
                            tls.read_exact(&mut buf).await.ok();
                            tls.write_all(&buf).await.ok();
                            tls.flush().await.ok();
                        });

                        let connector = TlsConnector::from(client_cfg.clone());
                        let tcp = TcpStream::connect(addr).await.expect("connect");
                        let sn = ServerName::try_from("localhost")
                            .expect("server name")
                            .to_owned();
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
}

#[cfg(feature = "aws-lc")]
criterion_group!(benches, aws_lc_benches::bench_aws_lc_tls13_handshake);

#[cfg(not(feature = "aws-lc"))]
criterion_group!(benches, _noop);

#[cfg(not(feature = "aws-lc"))]
fn _noop(_c: &mut Criterion) {}

criterion_main!(benches);
