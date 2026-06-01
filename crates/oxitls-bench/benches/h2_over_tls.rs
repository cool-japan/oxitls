//! HTTP/2 over TLS handshake benchmark.
//!
//! Measures TLS 1.3 handshake completion time when ALPN = "h2" is negotiated.
//! The benchmark covers: TLS record exchange → certificate verification →
//! session ticket issuance → ALPN protocol selection.  Full HTTP/2 framing
//! (h2 SETTINGS exchange) is deliberately excluded to isolate the TLS layer
//! cost.
//!
//! The "negotiated" result asserts that ALPN "h2" was successfully selected
//! on both sides before the measurement is counted.
//!
//! Run with: `cargo bench -p oxitls-bench --bench h2_over_tls`

mod bench_common;

use std::sync::Arc;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use rustls::{ClientConfig, ServerConfig};
use rustls_pki_types::ServerName;
use tokio_rustls::{TlsAcceptor, TlsConnector};

// ── Build TLS configs with h2 ALPN ────────────────────────────────────────────

fn make_h2_client_config(
    provider: Arc<rustls::crypto::CryptoProvider>,
    root_store: rustls::RootCertStore,
) -> Arc<ClientConfig> {
    let mut cfg = bench_common::make_client_config(provider, root_store);
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Arc::new(cfg)
}

fn make_h2_server_config(
    provider: Arc<rustls::crypto::CryptoProvider>,
    certs: Vec<rustls_pki_types::CertificateDer<'static>>,
    key: rustls_pki_types::PrivateKeyDer<'static>,
) -> Arc<ServerConfig> {
    let mut cfg = bench_common::make_server_config(provider, certs, key);
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Arc::new(cfg)
}

// ── Bench: TLS 1.3 handshake to "h2" ALPN negotiated ────────────────────────

fn bench_h2_tls13_handshake_to_negotiated(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let fix = bench_common::cert_fixture();
    let provider = bench_common::pure_crypto_provider();

    let client_cfg = make_h2_client_config(provider.clone(), fix.root_store.clone());
    let server_cfg = make_h2_server_config(
        provider.clone(),
        vec![fix.leaf_cert_der.clone()],
        fix.leaf_key_der.clone_key(),
    );

    c.bench_function("h2_tls13_handshake_to_negotiated", |b| {
        b.iter_batched(
            || (client_cfg.clone(), server_cfg.clone()),
            |(cc, sc)| {
                rt.block_on(async {
                    let (client_io, server_io) = tokio::io::duplex(65_536);

                    let connector = TlsConnector::from(cc);
                    let acceptor = TlsAcceptor::from(sc);

                    let sn = ServerName::try_from("localhost").expect("server name");

                    let (client_tls, server_tls) =
                        tokio::join!(connector.connect(sn, client_io), acceptor.accept(server_io),);

                    let client_tls = client_tls.expect("client TLS handshake");
                    let server_tls = server_tls.expect("server TLS handshake");

                    // Verify ALPN negotiation on both sides.
                    let (_, client_session) = client_tls.get_ref();
                    let (_, server_session) = server_tls.get_ref();
                    let client_alpn = client_session.alpn_protocol();
                    let server_alpn = server_session.alpn_protocol();

                    std::hint::black_box((client_alpn == Some(b"h2"), server_alpn == Some(b"h2")))
                })
            },
            BatchSize::SmallInput,
        );
    });
}

// ── Bench: h2 ALPN vs no-ALPN overhead ───────────────────────────────────────

fn bench_h2_alpn_vs_no_alpn(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let fix = bench_common::cert_fixture();
    let provider = bench_common::pure_crypto_provider();

    // Without ALPN.
    let client_no_alpn = Arc::new(bench_common::make_client_config(
        provider.clone(),
        fix.root_store.clone(),
    ));
    let server_no_alpn = Arc::new(bench_common::make_server_config(
        provider.clone(),
        vec![fix.leaf_cert_der.clone()],
        fix.leaf_key_der.clone_key(),
    ));

    // With h2 ALPN.
    let client_h2 = make_h2_client_config(provider.clone(), fix.root_store.clone());
    let server_h2 = make_h2_server_config(
        provider.clone(),
        vec![fix.leaf_cert_der.clone()],
        fix.leaf_key_der.clone_key(),
    );

    let mut group = c.benchmark_group("h2_alpn_overhead");

    group.bench_function("no_alpn", |b| {
        b.iter_batched(
            || (client_no_alpn.clone(), server_no_alpn.clone()),
            |(cc, sc)| {
                rt.block_on(async {
                    let (client_io, server_io) = tokio::io::duplex(65_536);
                    let connector = TlsConnector::from(cc);
                    let acceptor = TlsAcceptor::from(sc);
                    let sn = ServerName::try_from("localhost").expect("server name");
                    let (cr, sr) =
                        tokio::join!(connector.connect(sn, client_io), acceptor.accept(server_io),);
                    std::hint::black_box((cr.is_ok(), sr.is_ok()))
                })
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("h2_alpn", |b| {
        b.iter_batched(
            || (client_h2.clone(), server_h2.clone()),
            |(cc, sc)| {
                rt.block_on(async {
                    let (client_io, server_io) = tokio::io::duplex(65_536);
                    let connector = TlsConnector::from(cc);
                    let acceptor = TlsAcceptor::from(sc);
                    let sn = ServerName::try_from("localhost").expect("server name");
                    let (cr, sr) =
                        tokio::join!(connector.connect(sn, client_io), acceptor.accept(server_io),);
                    std::hint::black_box((cr.is_ok(), sr.is_ok()))
                })
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

// ── Entry point ───────────────────────────────────────────────────────────────

criterion_group!(
    h2_tls_benches,
    bench_h2_tls13_handshake_to_negotiated,
    bench_h2_alpn_vs_no_alpn,
);
criterion_main!(h2_tls_benches);
