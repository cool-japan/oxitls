//! Criterion benchmarks for multi-level certificate chain construction.
//!
//! Measures root CA → intermediate CA → leaf certificate signing chains,
//! covering both homogeneous (all Ed25519) and mixed algorithm chains.
//!
//! Run: `cargo bench -p oxitls-rcgen --bench chain_build`

use criterion::{criterion_group, criterion_main, Criterion};
use oxitls_rcgen::{
    generate_ca, generate_ca_signed_leaf, generate_intermediate_ca, SigningAlgorithm,
};

fn bench_chain_3_ed25519(c: &mut Criterion) {
    c.bench_function("chain_3_ed25519", |b| {
        b.iter(|| {
            let root =
                generate_ca("Root CA", SigningAlgorithm::Ed25519).expect("root CA gen failed");
            let intermediate =
                generate_intermediate_ca("Intermediate CA", SigningAlgorithm::Ed25519, &root)
                    .expect("intermediate CA gen failed");
            let _leaf = generate_ca_signed_leaf(
                &["leaf.example.com"],
                SigningAlgorithm::Ed25519,
                &intermediate,
            )
            .expect("leaf cert gen failed");
        });
    });
}

fn bench_chain_3_mixed(c: &mut Criterion) {
    // Mixed-algorithm chain: P-256 root → P-384 intermediate → P-256 leaf.
    // Proves cross-algorithm signing works without the RSA slowness.
    c.bench_function("chain_3_mixed_p256_p384_p256", |b| {
        b.iter(|| {
            let root =
                generate_ca("Root CA", SigningAlgorithm::EcdsaP256).expect("root CA gen failed");
            let intermediate =
                generate_intermediate_ca("Intermediate CA", SigningAlgorithm::EcdsaP384, &root)
                    .expect("intermediate CA gen failed");
            let _leaf = generate_ca_signed_leaf(
                &["leaf.example.com"],
                SigningAlgorithm::EcdsaP256,
                &intermediate,
            )
            .expect("leaf cert gen failed");
        });
    });
}

criterion_group!(benches, bench_chain_3_ed25519, bench_chain_3_mixed);
criterion_main!(benches);
