//! Criterion benchmark: `RustcryptoClientConfigBuilder` with CRL configuration.
//!
//! Measures the overhead of building a `ClientConfig` with CRL-based
//! revocation checking enabled (using an empty CRL list as the baseline),
//! compared to building without CRL checking.
//!
//! Also benchmarks builder construction with various option combinations to
//! characterise configuration overhead.

use criterion::{criterion_group, criterion_main, Criterion};
use oxitls_adapter_rustls_rustcrypto::RustcryptoClientConfigBuilder;
use rustls::RootCertStore;

fn bench_builder_no_crl(c: &mut Criterion) {
    c.bench_function("crl_check/builder_no_crl", |b| {
        b.iter(|| {
            let roots = RootCertStore::empty();
            RustcryptoClientConfigBuilder::new()
                .with_roots(roots)
                .build()
                .expect("build ok")
        });
    });
}

fn bench_builder_with_empty_crl_list(c: &mut Criterion) {
    // An empty CRL list still goes through the CrlAwareServerVerifier path
    // in the builder, so this measures that routing overhead.
    c.bench_function("crl_check/builder_empty_crl_list", |b| {
        b.iter(|| {
            let roots = RootCertStore::empty();
            RustcryptoClientConfigBuilder::new()
                .with_roots(roots)
                .with_crl(vec![])
                .build()
                .expect("build ok")
        });
    });
}

fn bench_builder_with_alpn_and_resumption_disabled(c: &mut Criterion) {
    c.bench_function("crl_check/builder_alpn_no_resumption", |b| {
        b.iter(|| {
            let roots = RootCertStore::empty();
            RustcryptoClientConfigBuilder::new()
                .with_roots(roots)
                .with_alpn(vec![b"h2".to_vec()])
                .with_resumption_disabled()
                .build()
                .expect("build ok")
        });
    });
}

fn bench_server_builder_basic(c: &mut Criterion) {
    use oxitls_adapter_rustls_rustcrypto::RustcryptoServerConfigBuilder;
    use oxitls_rcgen::generate_self_signed_ed25519;
    use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

    // Generate cert once outside the timing loop.
    let ck = generate_self_signed_ed25519(&["localhost"]).expect("cert gen");
    let cert_der = rustls_pki_types::CertificateDer::from(ck.cert_der.clone());
    let pkcs8 = ck.pkcs8_der.clone();

    c.bench_function("crl_check/server_builder_basic", |b| {
        b.iter(|| {
            let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8.clone()));
            RustcryptoServerConfigBuilder::new()
                .with_cert_and_key(vec![cert_der.clone()], key)
                .build()
                .expect("server build ok")
        });
    });
}

criterion_group!(
    benches,
    bench_builder_no_crl,
    bench_builder_with_empty_crl_list,
    bench_builder_with_alpn_and_resumption_disabled,
    bench_server_builder_basic,
);
criterion_main!(benches);
