//! TLS 1.2 session-resumption benchmark.
//!
//! Complements `tls12_handshake.rs` (full TLS 1.2 handshake) by benchmarking
//! the much cheaper **session-ID resumed** handshake path.
//!
//! Strategy:
//! - Perform a first (full) handshake to allow the server to store a session.
//! - Enable `Resumption::in_memory_sessions(32)` on the client so the session
//!   ticket / session-ID is cached client-side.
//! - Perform subsequent handshakes and benchmark those; the server will issue
//!   a session ticket during the first, and the client will offer it on the
//!   second — this exercises the resumed path.
//!
//! Note: rustls TLS 1.2 session resumption uses session tickets (RFC 5077)
//! rather than raw session IDs.  Both result in a shorter resumed handshake
//! that avoids the full certificate exchange.
//!
//! Run with: `cargo bench -p oxitls-bench --bench tls12_handshake_resumed`

mod bench_common;

use std::sync::Arc;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use rustls::{ClientConfig, ServerConfig};

// ── Criterion config ──────────────────────────────────────────────────────────

fn make_criterion() -> Criterion {
    Criterion::default()
        .measurement_time(std::time::Duration::from_secs(10))
        .sample_size(100)
}

// ── Build TLS 1.2-only client config with in-memory session cache ─────────────

fn client_cfg_tls12_with_resumption(
    provider: Arc<rustls::crypto::CryptoProvider>,
    root_store: rustls::RootCertStore,
) -> Arc<ClientConfig> {
    let mut cfg = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS12])
        .expect("TLS 1.2 unsupported")
        .with_root_certificates(root_store)
        .with_no_client_auth();
    // Enable in-memory session cache so resumed handshakes are possible.
    cfg.resumption = rustls::client::Resumption::in_memory_sessions(32);
    Arc::new(cfg)
}

// ── Build TLS 1.2-only server config ─────────────────────────────────────────

fn server_cfg_tls12(
    provider: Arc<rustls::crypto::CryptoProvider>,
    certs: Vec<rustls_pki_types::CertificateDer<'static>>,
    key: rustls_pki_types::PrivateKeyDer<'static>,
) -> Arc<ServerConfig> {
    Arc::new(bench_common::make_server_config_with_versions(
        provider,
        certs,
        key,
        &[&rustls::version::TLS12],
    ))
}

// ── Bench: TLS 1.2 resumed handshake ─────────────────────────────────────────

fn bench_tls12_resumed_handshake(c: &mut Criterion) {
    let fix = bench_common::cert_fixture();
    let provider = bench_common::pure_crypto_provider();

    let client_cfg = client_cfg_tls12_with_resumption(provider.clone(), fix.root_store.clone());
    let server_cfg = server_cfg_tls12(
        provider.clone(),
        vec![fix.leaf_cert_der.clone()],
        fix.leaf_key_der.clone_key(),
    );

    // Warm-up: drive one full handshake so the session is cached client-side.
    // Subsequent calls from iter_batched will use the same client_cfg (which
    // holds the session cache) and will do a resumed handshake on the second+
    // call.  Each iteration gets a fresh server connection but reuses the
    // client's session cache.
    bench_common::sync_handshake(client_cfg.clone(), server_cfg.clone(), "localhost");

    c.bench_function("tls12_resumed_handshake/pure", |b| {
        b.iter_batched(
            || (client_cfg.clone(), server_cfg.clone()),
            |(cc, sc)| bench_common::sync_handshake(cc, sc, "localhost"),
            BatchSize::SmallInput,
        );
    });
}

// ── Bench: full vs resumed comparison ────────────────────────────────────────

fn bench_tls12_full_handshake_baseline(c: &mut Criterion) {
    let fix = bench_common::cert_fixture();
    let provider = bench_common::pure_crypto_provider();

    // Use a client config WITHOUT session cache — forces a full handshake every
    // iteration for a fair baseline comparison.
    let client_cfg = Arc::new(bench_common::make_client_config_with_versions(
        provider.clone(),
        fix.root_store.clone(),
        &[&rustls::version::TLS12],
    ));
    let server_cfg = server_cfg_tls12(
        provider.clone(),
        vec![fix.leaf_cert_der.clone()],
        fix.leaf_key_der.clone_key(),
    );

    c.bench_function("tls12_full_handshake_baseline/pure", |b| {
        b.iter_batched(
            || (client_cfg.clone(), server_cfg.clone()),
            |(cc, sc)| bench_common::sync_handshake(cc, sc, "localhost"),
            BatchSize::SmallInput,
        );
    });
}

// ── Entry point ───────────────────────────────────────────────────────────────

criterion_group! {
    name = tls12_resumed_benches;
    config = make_criterion();
    targets = bench_tls12_resumed_handshake, bench_tls12_full_handshake_baseline
}
criterion_main!(tls12_resumed_benches);
