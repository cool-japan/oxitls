//! Criterion benchmarks for PKCS#12 (PFX) export.
//!
//! Pre-generates certificates outside the hot loop (key generation is not
//! what's being measured here) and measures only the PFX serialization +
//! password-based key derivation cost.
//!
//! Run: `cargo bench -p oxitls-rcgen --bench pkcs12`

use criterion::{criterion_group, criterion_main, Criterion};

fn bench_pkcs12_ed25519(c: &mut Criterion) {
    // Pre-generate outside the bench loop — keygen is not the subject.
    let ck = oxitls_rcgen::generate_self_signed_ed25519(&["bench.example.com"])
        .expect("ed25519 cert gen for pkcs12 bench");

    c.bench_function("pkcs12_export_ed25519", |b| {
        b.iter(|| {
            ck.to_pkcs12("password123", "my_cert")
                .expect("pkcs12 export failed")
        });
    });
}

fn bench_pkcs12_rsa2048(c: &mut Criterion) {
    // RSA-2048 keygen is slow — generate once, bench only the PKCS#12 step.
    let ck = oxitls_rcgen::generate_self_signed_rsa2048(&["bench.example.com"])
        .expect("rsa2048 cert gen for pkcs12 bench");

    let mut group = c.benchmark_group("pkcs12_rsa2048");
    group.sample_size(20);
    group.bench_function("pkcs12_export_rsa2048", |b| {
        b.iter(|| {
            ck.to_pkcs12("password123", "my_cert")
                .expect("pkcs12 export failed")
        });
    });
    group.finish();
}

criterion_group!(benches, bench_pkcs12_ed25519, bench_pkcs12_rsa2048);
criterion_main!(benches);
