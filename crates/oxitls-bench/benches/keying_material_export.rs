//! Benchmark the overhead of `OxiTlsStream::export_keying_material` on an
//! established TLS 1.3 connection.
//!
//! The TLS pair is established once in a thread-local and reused across all
//! iterations so the measured cost is purely the keying-material derivation,
//! not the handshake.
//!
//! Run with: `cargo bench -p oxitls-bench --bench keying_material_export`

use std::sync::Arc;

use criterion::{criterion_group, criterion_main, Criterion};
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

use oxitls::tls13::{server::tokio_acceptor, ServerBuilder};
use oxitls::OxiTlsStream;
use oxitls_rcgen::generate_self_signed_ed25519;

// ── Helper: build a client config trusting a single root ─────────────────────

fn client_cfg_for(cert_der: &CertificateDer<'static>) -> Arc<ClientConfig> {
    let provider = oxitls_adapter_rustls_rustcrypto::pure_provider();
    let mut roots = RootCertStore::empty();
    roots.add(cert_der.clone()).expect("add root cert");
    Arc::new(
        ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3 unsupported")
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

// ── Build a pre-warmed OxiTlsStream pair for benchmarking ────────────────────

fn build_warmed_client_stream() -> OxiTlsStream<TcpStream> {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime for setup");

    let ck = generate_self_signed_ed25519(&["localhost"]).expect("cert gen");
    let cert_der = CertificateDer::from(ck.cert_der.clone());
    let key_der = PrivateKeyDer::Pkcs8(ck.pkcs8_der.clone().into());

    let server_cfg = ServerBuilder::new()
        .with_der_cert_and_key(vec![cert_der.clone()], key_der)
        .build()
        .expect("server config");

    let client_cfg = client_cfg_for(&cert_der);

    rt.block_on(async move {
        let acceptor = tokio_acceptor(server_cfg);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");

        // Spawn server side; we don't need to keep it or its stream alive since
        // keying-material export is a local computation on the client state.
        tokio::spawn(async move {
            if let Ok((tcp, _)) = listener.accept().await {
                let _ = acceptor.accept(tcp).await;
            }
        });

        let tcp = TcpStream::connect(addr).await.expect("connect");
        let sn = ServerName::try_from("localhost").expect("server name");
        let tls = TlsConnector::from(client_cfg)
            .connect(sn, tcp)
            .await
            .expect("tls connect");

        OxiTlsStream::from(tls)
    })
}

// ── Benchmark: export_keying_material 32 bytes ───────────────────────────────

fn bench_export_keying_material_32b(c: &mut Criterion) {
    let stream = build_warmed_client_stream();

    let mut group = c.benchmark_group("export_keying_material");
    group.bench_function("32_bytes", |b| {
        let mut output = [0u8; 32];
        b.iter(|| {
            stream
                .export_keying_material(&mut output, b"EXPORTER-Bench", Some(b"ctx"))
                .expect("export ok");
        });
    });

    // Also bench with a larger output to measure scaling.
    group.bench_function("64_bytes", |b| {
        let mut output = [0u8; 64];
        b.iter(|| {
            stream
                .export_keying_material(&mut output, b"EXPORTER-Bench64", Some(b"ctx"))
                .expect("export ok");
        });
    });

    group.finish();
}

criterion_group!(benches, bench_export_keying_material_32b);
criterion_main!(benches);
