//! Benchmark full TLS 1.3 handshake overhead introduced by OCSP stapling.
//!
//! Compares:
//!   1. Handshake with no OCSP staple (baseline)
//!   2. Handshake with an empty staple field (staple field present but zero bytes)
//!   3. Handshake with a non-empty static OCSP staple (realistic path)
//!
//! All sessions run over loopback TCP with a fresh connection per iteration.
//!
//! NOTE: Full cryptographic OCSP verification (signature chain on the staple)
//! is Wave 5 Slice A work; these benchmarks measure the plumbing overhead only.
//!
//! Run with: `cargo bench -p oxitls-bench --bench ocsp_stapling_overhead`

use std::sync::Arc;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use oxitls::tls13::ServerBuilder;
use oxitls::StaticOcspResolver;
use oxitls_rcgen::generate_self_signed_ed25519;
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::ServerName;

// ── Shared cert fixture ───────────────────────────────────────────────────────

struct Fixture {
    cert_der: CertificateDer<'static>,
    key_der: PrivateKeyDer<'static>,
    root_store: RootCertStore,
}

fn make_fixture() -> Fixture {
    let ck = generate_self_signed_ed25519(&["localhost"]).expect("cert gen");
    let cert_der = CertificateDer::from(ck.cert_der.clone());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.pkcs8_der.clone()));
    let mut root_store = RootCertStore::empty();
    root_store.add(cert_der.clone()).expect("add root");
    Fixture {
        cert_der,
        key_der,
        root_store,
    }
}

fn client_config(root_store: RootCertStore) -> Arc<ClientConfig> {
    let provider = oxitls_adapter_rustls_rustcrypto::pure_provider();
    Arc::new(
        ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3")
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    )
}

// ── One-shot async handshake helper ──────────────────────────────────────────

async fn do_handshake(acceptor: TlsAcceptor, client_cfg: Arc<ClientConfig>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept");
        if let Ok(mut tls) = acceptor.accept(tcp).await {
            let mut buf = [0u8; 1];
            let _ = tls.read_exact(&mut buf).await;
            let _ = tls.write_all(&buf).await;
            let _ = tls.flush().await;
        }
    });

    let connector = TlsConnector::from(client_cfg);
    let tcp = TcpStream::connect(addr).await.expect("tcp connect");
    let sn = ServerName::try_from("localhost").expect("sn");
    if let Ok(mut tls) = connector.connect(sn, tcp).await {
        let _ = tls.write_all(&[0x01]).await;
        let _ = tls.flush().await;
        let mut reply = [0u8; 1];
        let _ = tls.read_exact(&mut reply).await;
    }
    let _ = server_task.await;
}

// ── Bench 1: no OCSP staple ───────────────────────────────────────────────────

fn bench_handshake_without_ocsp(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let fix = make_fixture();

    let server_cfg = ServerBuilder::new()
        .with_der_cert_and_key(vec![fix.cert_der.clone()], fix.key_der.clone_key())
        .build()
        .expect("server cfg");
    let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
    let client_cfg = client_config(fix.root_store);

    c.bench_function("handshake_without_ocsp", |b| {
        b.iter_batched(
            || (acceptor.clone(), Arc::clone(&client_cfg)),
            |(acc, cfg)| rt.block_on(do_handshake(acc, cfg)),
            BatchSize::SmallInput,
        );
    });
}

// ── Bench 2: empty staple field ───────────────────────────────────────────────
//
// Measures overhead of routing through the OCSP resolver path even when the
// resolver returns an empty response (StaticOcspResolver([]) returns None).

fn bench_handshake_with_empty_staple(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let fix = make_fixture();

    let server_cfg = ServerBuilder::new()
        .with_der_cert_and_key(vec![fix.cert_der.clone()], fix.key_der.clone_key())
        .with_ocsp_response_resolver(Arc::new(StaticOcspResolver(vec![])))
        .build()
        .expect("server cfg with empty staple");
    let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
    let client_cfg = client_config(fix.root_store);

    c.bench_function("handshake_with_empty_staple", |b| {
        b.iter_batched(
            || (acceptor.clone(), Arc::clone(&client_cfg)),
            |(acc, cfg)| rt.block_on(do_handshake(acc, cfg)),
            BatchSize::SmallInput,
        );
    });
}

// ── Bench 3: non-empty static OCSP staple ─────────────────────────────────────
//
// This exercises the full staple injection path.  The client receives the
// bytes but (without an OcspClientPolicy verifier) simply ignores them.

fn bench_handshake_with_ocsp_staple(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let fix = make_fixture();

    // Realistic-size OCSP response (128 bytes of pseudo-DER).
    let ocsp_bytes: Vec<u8> = vec![
        0x30, 0x7e, 0x0a, 0x01, 0x00, 0x30, 0x79, 0x30, 0x77, 0x30, 0x75, 0x02, 0x01, 0x00, 0x30,
        0x19, 0x31, 0x17, 0x30, 0x15, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x0e, 0x65, 0x78, 0x61,
        0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x36, 0x30,
        0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x18, 0x0f, 0x32, 0x30, 0x32,
        0x37, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x0a, 0x0a,
        0x01, 0x00, 0x18, 0x05, 0x30, 0x03, 0x02, 0x01, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86,
        0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x01, 0x01, 0x00, 0x30, 0x0a,
        0x02, 0x01, 0x00, 0x18, 0x05, 0x30, 0x03, 0x02, 0x01, 0x00, 0x30, 0x0a, 0x02, 0x01, 0x00,
        0x18, 0x05, 0x30, 0x03, 0x02, 0x01, 0x00,
    ];

    let server_cfg = ServerBuilder::new()
        .with_der_cert_and_key(vec![fix.cert_der.clone()], fix.key_der.clone_key())
        .with_ocsp_response_resolver(Arc::new(StaticOcspResolver(ocsp_bytes)))
        .build()
        .expect("server cfg with OCSP staple");
    let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
    let client_cfg = client_config(fix.root_store);

    c.bench_function("handshake_with_ocsp_staple", |b| {
        b.iter_batched(
            || (acceptor.clone(), Arc::clone(&client_cfg)),
            |(acc, cfg)| rt.block_on(do_handshake(acc, cfg)),
            BatchSize::SmallInput,
        );
    });
}

// ── Entry point ───────────────────────────────────────────────────────────────

criterion_group!(
    ocsp_stapling_benches,
    bench_handshake_without_ocsp,
    bench_handshake_with_empty_staple,
    bench_handshake_with_ocsp_staple,
);
criterion_main!(ocsp_stapling_benches);
