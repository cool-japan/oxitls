//! OxiTLS benchmark suite — compares:
//!
//! 1. TLS 1.3 full handshake throughput (OxiTLS / rustls-rustcrypto)
//! 2. TLS 1.3 resumed handshake throughput (OxiTicketer session tickets)
//! 3. AES-256-GCM 1 KiB encrypt: OxiCrypto (aes-gcm crate) vs ring vs aws-lc-rs
//!
//! Run with: `cargo bench -p oxitls-bench`
//! Compile-only gate: `cargo bench -p oxitls-bench --no-run`

use std::sync::Arc;

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};

// ── OxiTLS / RustCrypto AEAD ─────────────────────────────────────────────────

use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes256Gcm, Key, Nonce,
};

// ── ring AEAD ─────────────────────────────────────────────────────────────────

use ring::aead::{self as ring_aead, LessSafeKey, UnboundKey, AES_256_GCM as RING_AES256GCM};

// ── aws-lc-rs AEAD (drop-in ring replacement) ────────────────────────────────

use aws_lc_rs::aead::{
    self as lc_aead, LessSafeKey as LcLessSafeKey, UnboundKey as LcUnboundKey,
    AES_256_GCM as LC_AES256GCM,
};

// ── TLS helpers ───────────────────────────────────────────────────────────────

use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

use oxitls::tls13::{server::tokio_acceptor, ServerBuilder};
use oxitls::OxiTicketer;
use oxitls_rcgen::generate_self_signed_ed25519;

// ── Shared cert fixture ───────────────────────────────────────────────────────

/// A pre-generated cert/key pair for benchmarking (avoids keygen overhead
/// inside the hot loop).
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

// ── Build rustls CryptoProvider (pure-Rust / RustCrypto) ─────────────────────

fn pure_provider() -> Arc<rustls::crypto::CryptoProvider> {
    oxitls_adapter_rustls_rustcrypto::pure_provider()
}

// ── Build client config trusting a single root cert ──────────────────────────

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
// Bench 1: OxiTLS TLS 1.3 full handshake (loopback in-process)
// ─────────────────────────────────────────────────────────────────────────────

fn bench_tls13_full_handshake(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let fixture = CertFixture::generate();

    let cert_der = fixture.cert_der.clone();
    let key_der = fixture.key_der.clone_key();

    // Pre-build server config once; reuse across iterations.
    let server_cfg = ServerBuilder::new()
        .with_der_cert_and_key(vec![cert_der.clone()], key_der)
        .build()
        .expect("server config");
    let client_cfg = client_cfg_for(&cert_der);

    c.bench_function("oxitls_tls13_full_handshake", |b| {
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
                        // Echo one byte so both sides complete the handshake.
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
// Bench 2: OxiTLS TLS 1.3 resumed handshake (OxiTicketer session tickets)
// ─────────────────────────────────────────────────────────────────────────────

fn bench_tls13_resumed_handshake(c: &mut Criterion) {
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

    c.bench_function("oxitls_tls13_resumed_handshake", |b| {
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
// Bench 3: AES-256-GCM 1 KiB encrypt — OxiCrypto vs ring vs aws-lc-rs
// ─────────────────────────────────────────────────────────────────────────────

const BENCH_DATA_LEN: usize = 1024;

fn bench_aead_1kb(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes256gcm_encrypt_1kb");
    let key_bytes = [0u8; 32];
    let nonce_bytes = [0u8; 12];
    let data = [0u8; BENCH_DATA_LEN];

    // ── OxiCrypto / aes-gcm (pure Rust / RustCrypto) ─────────────────────────
    {
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&nonce_bytes);

        group.bench_with_input(
            BenchmarkId::new("oxicrypto_aes256gcm", BENCH_DATA_LEN),
            &BENCH_DATA_LEN,
            |b, _| {
                b.iter_batched(
                    || data.to_vec(),
                    |mut buf| {
                        // Returns an authentication tag; discard via std::hint::black_box
                        let tag = cipher
                            .encrypt_in_place_detached(nonce, b"", &mut buf)
                            .expect("oxicrypto encrypt");
                        std::hint::black_box(tag);
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    // ── ring AES-256-GCM ─────────────────────────────────────────────────────
    {
        let ring_key =
            LessSafeKey::new(UnboundKey::new(&RING_AES256GCM, &key_bytes).expect("ring key"));
        group.bench_with_input(
            BenchmarkId::new("ring_aes256gcm", BENCH_DATA_LEN),
            &BENCH_DATA_LEN,
            |b, _| {
                b.iter_batched(
                    || data.to_vec(),
                    |mut buf| {
                        let nonce = ring_aead::Nonce::assume_unique_for_key(nonce_bytes);
                        ring_key
                            .seal_in_place_append_tag(nonce, ring_aead::Aad::empty(), &mut buf)
                            .expect("ring encrypt");
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    // ── aws-lc-rs AES-256-GCM ────────────────────────────────────────────────
    {
        let lc_key = LcLessSafeKey::new(
            LcUnboundKey::new(&LC_AES256GCM, &key_bytes).expect("aws-lc-rs key"),
        );
        group.bench_with_input(
            BenchmarkId::new("aws_lc_rs_aes256gcm", BENCH_DATA_LEN),
            &BENCH_DATA_LEN,
            |b, _| {
                b.iter_batched(
                    || data.to_vec(),
                    |mut buf| {
                        let nonce = lc_aead::Nonce::assume_unique_for_key(nonce_bytes);
                        lc_key
                            .seal_in_place_append_tag(nonce, lc_aead::Aad::empty(), &mut buf)
                            .expect("aws-lc-rs encrypt");
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

// ─────────────────────────────────────────────────────────────────────────────

criterion_group!(
    name = benches;
    config = Criterion::default()
        .sample_size(200)
        .measurement_time(std::time::Duration::from_secs(20));
    targets = bench_tls13_full_handshake, bench_tls13_resumed_handshake, bench_aead_1kb,
);
criterion_main!(benches);
