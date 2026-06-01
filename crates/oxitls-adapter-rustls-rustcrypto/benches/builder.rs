//! Criterion benchmark: `RustcryptoClientConfigBuilder` construction cost.
//!
//! Measures the time to build a `ClientConfig` from a populated root store
//! using the RustCrypto provider. This covers the path through:
//! `pure_provider()` → `WebPkiServerVerifier::builder_with_provider` → `build()`.

use criterion::{criterion_group, criterion_main, Criterion};
use oxitls_adapter_rustls_rustcrypto::RustcryptoClientConfigBuilder;
use oxitls_webpki_roots::webpki_root_certs;
use rustls::RootCertStore;

// RootCertStore is used in bench_builder_empty_roots and bench_builder_with_alpn.

fn bench_builder_empty_roots(c: &mut Criterion) {
    c.bench_function("client_builder/empty_roots", |b| {
        b.iter(|| {
            let roots = RootCertStore::empty();
            RustcryptoClientConfigBuilder::new()
                .with_roots(roots)
                .build()
                .expect("build ok")
        });
    });
}

fn bench_builder_webpki_roots(c: &mut Criterion) {
    // Load the WebPKI root store once outside the timed loop.
    let roots = webpki_root_certs();

    c.bench_function("client_builder/webpki_roots", |b| {
        let roots = roots.clone();
        b.iter(move || {
            RustcryptoClientConfigBuilder::new()
                .with_roots(roots.clone())
                .build()
                .expect("build ok")
        });
    });
}

fn bench_builder_with_alpn(c: &mut Criterion) {
    c.bench_function("client_builder/with_alpn_h2", |b| {
        b.iter(|| {
            let roots = RootCertStore::empty();
            RustcryptoClientConfigBuilder::new()
                .with_roots(roots)
                .with_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()])
                .build()
                .expect("build ok")
        });
    });
}

fn bench_pure_provider_construction(c: &mut Criterion) {
    c.bench_function("pure_provider/construction", |b| {
        b.iter(oxitls_adapter_rustls_rustcrypto::pure_provider);
    });
}

criterion_group!(
    benches,
    bench_builder_empty_roots,
    bench_builder_webpki_roots,
    bench_builder_with_alpn,
    bench_pure_provider_construction,
);
criterion_main!(benches);
