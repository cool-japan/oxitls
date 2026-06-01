//! Benchmarks for 0-RTT early data builder construction cost.
//!
//! Measures `ClientBuilder::with_early_data().build()` construction overhead
//! vs a plain `ClientBuilder::build()` without the flag, and
//! `ServerBuilder::with_max_early_data_size(n).build()` vs baseline.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use rustls_pki_types::CertificateDer;

use oxitls::tls13::{ClientBuilder, ServerBuilder};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// A minimal pre-generated DER certificate (self-signed localhost Ed25519).
/// Re-generated each bench run to avoid cross-benchmark contamination.
fn make_server_cert_der() -> (
    CertificateDer<'static>,
    rustls_pki_types::PrivateKeyDer<'static>,
) {
    use oxitls_rcgen::generate_self_signed_ed25519;
    let ck = generate_self_signed_ed25519(&["localhost"]).expect("rcgen failed");
    let cert_der = CertificateDer::from(ck.cert_der);
    let key_der = rustls_pki_types::PrivateKeyDer::Pkcs8(
        rustls_pki_types::PrivatePkcs8KeyDer::from(ck.pkcs8_der),
    );
    (cert_der, key_der)
}

// ---------------------------------------------------------------------------
// Client builder benchmarks
// ---------------------------------------------------------------------------

fn bench_client_builder_baseline(c: &mut Criterion) {
    c.bench_function("client_builder_baseline_build", |b| {
        b.iter(|| {
            ClientBuilder::new()
                .with_webpki_roots()
                .build()
                .expect("build ok")
        });
    });
}

fn bench_client_builder_with_early_data(c: &mut Criterion) {
    c.bench_function("client_builder_with_early_data_build", |b| {
        b.iter(|| {
            ClientBuilder::new()
                .with_webpki_roots()
                .with_early_data()
                .build()
                .expect("build ok")
        });
    });
}

fn bench_client_builder_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("client_builder");

    for early_data in [false, true] {
        group.bench_with_input(
            BenchmarkId::new("with_early_data", early_data),
            &early_data,
            |b, &flag| {
                b.iter(|| {
                    let builder = ClientBuilder::new().with_webpki_roots();
                    let builder = if flag {
                        builder.with_early_data()
                    } else {
                        builder
                    };
                    builder.build().expect("build ok")
                });
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Server builder benchmarks
// ---------------------------------------------------------------------------

fn bench_server_builder_with_max_early_data(c: &mut Criterion) {
    let mut group = c.benchmark_group("server_builder");

    // Pre-generate cert outside the timing loop.
    let (cert_der, key_der) = make_server_cert_der();

    for size_kb in [0u32, 4, 16, 64] {
        let size_bytes = size_kb * 1024;
        let cert_der = cert_der.clone();
        let key_der_bytes: Vec<u8> = match &key_der {
            rustls_pki_types::PrivateKeyDer::Pkcs8(k) => k.secret_pkcs8_der().to_vec(),
            _ => panic!("unexpected key type"),
        };

        group.bench_with_input(
            BenchmarkId::new("max_early_data_size_kb", size_kb),
            &(cert_der, key_der_bytes, size_bytes),
            |b, (cert, key_bytes, size)| {
                b.iter(|| {
                    let key = rustls_pki_types::PrivateKeyDer::Pkcs8(
                        rustls_pki_types::PrivatePkcs8KeyDer::from(key_bytes.clone()),
                    );
                    let mut builder =
                        ServerBuilder::new().with_der_cert_and_key(vec![cert.clone()], key);
                    if *size > 0 {
                        builder = builder.with_max_early_data_size(*size);
                    }
                    builder.build().expect("build ok")
                });
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Criterion groups
// ---------------------------------------------------------------------------

criterion_group!(
    early_data_benches,
    bench_client_builder_baseline,
    bench_client_builder_with_early_data,
    bench_client_builder_comparison,
    bench_server_builder_with_max_early_data,
);
criterion_main!(early_data_benches);
