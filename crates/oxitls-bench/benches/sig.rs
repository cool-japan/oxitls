//! Signature algorithm micro-benchmarks: Ed25519, ECDSA-P256, ECDSA-P384,
//! and RSA-2048 PKCS#1 v1.5 with SHA-256.
//!
//! Benchmarks sign + verify for each algorithm using the pure-Rust OxiCrypto
//! crates (ed25519-dalek, p256, p384, rsa).  Key generation uses getrandom
//! (directly, or via the `oxitls_core::OsRng` rand_core-0.6 adapter for the RSA
//! paths) for compatibility across rand_core version boundaries.
//!
//! Run with: `cargo bench -p oxitls-bench --bench sig`

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

// ── Ed25519 ───────────────────────────────────────────────────────────────────

fn bench_ed25519_sign(c: &mut Criterion) {
    use ed25519_dalek::{Signer, SigningKey, Verifier};

    // Use getrandom directly to avoid rand 0.8 / rand_core version mismatch.
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("getrandom");
    let signing_key = SigningKey::from_bytes(&seed);
    let msg = [0u8; 64];

    let mut group = c.benchmark_group("ed25519");
    group.bench_with_input(BenchmarkId::new("sign", 64), &msg, |b, msg| {
        b.iter(|| {
            let sig = signing_key.sign(msg);
            std::hint::black_box(sig)
        });
    });

    let verifying_key = signing_key.verifying_key();
    let sig = signing_key.sign(&msg);
    group.bench_with_input(
        BenchmarkId::new("verify", 64),
        &(msg, sig),
        |b, (msg, sig)| {
            b.iter(|| {
                let result = verifying_key.verify(msg, sig);
                std::hint::black_box(result)
            });
        },
    );
    group.finish();
}

// ── ECDSA P-256 ───────────────────────────────────────────────────────────────

fn bench_ecdsa_p256_sign(c: &mut Criterion) {
    use p256::ecdsa::signature::{Signer, Verifier};
    use p256::ecdsa::{Signature, SigningKey};

    // Generate a scalar via getrandom, convert to SigningKey.
    let signing_key = loop {
        let mut scalar = [0u8; 32];
        getrandom::fill(&mut scalar).expect("getrandom");
        if let Ok(k) = SigningKey::from_bytes((&scalar).into()) {
            break k;
        }
    };
    let msg = [0u8; 64];

    let mut group = c.benchmark_group("ecdsa_p256");
    group.bench_with_input(BenchmarkId::new("sign", 64), &msg, |b, msg| {
        b.iter(|| {
            let sig: Signature = signing_key.sign(msg);
            std::hint::black_box(sig)
        });
    });

    let verifying_key = *signing_key.verifying_key();
    let sig: Signature = signing_key.sign(&msg);
    group.bench_with_input(
        BenchmarkId::new("verify", 64),
        &(msg, sig),
        |b, (msg, sig)| {
            b.iter(|| {
                let result = verifying_key.verify(msg, sig);
                std::hint::black_box(result)
            });
        },
    );
    group.finish();
}

// ── ECDSA P-384 ───────────────────────────────────────────────────────────────

fn bench_ecdsa_p384_sign(c: &mut Criterion) {
    use p384::ecdsa::signature::{Signer, Verifier};
    use p384::ecdsa::{Signature, SigningKey};

    // Generate a scalar via getrandom, convert to SigningKey.
    let signing_key = loop {
        let mut scalar = [0u8; 48];
        getrandom::fill(&mut scalar).expect("getrandom");
        if let Ok(k) = SigningKey::from_bytes((&scalar).into()) {
            break k;
        }
    };
    let msg = [0u8; 64];

    let mut group = c.benchmark_group("ecdsa_p384");
    group.bench_with_input(BenchmarkId::new("sign", 64), &msg, |b, msg| {
        b.iter(|| {
            let sig: Signature = signing_key.sign(msg);
            std::hint::black_box(sig)
        });
    });

    let verifying_key = *signing_key.verifying_key();
    let sig: Signature = signing_key.sign(&msg);
    group.bench_with_input(
        BenchmarkId::new("verify", 64),
        &(msg, sig),
        |b, (msg, sig)| {
            b.iter(|| {
                let result = verifying_key.verify(msg, sig);
                std::hint::black_box(result)
            });
        },
    );
    group.finish();
}

// ── RSA-2048 PKCS#1 v1.5 / SHA-256 ──────────────────────────────────────────

fn bench_rsa2048_sign(c: &mut Criterion) {
    use rsa::pkcs1v15::SigningKey;
    use rsa::sha2::Sha256;
    use rsa::signature::{Keypair, RandomizedSigner, Verifier};

    // RSA keygen + PKCS#1 v1.5 signing bind to the rand_core 0.6 `CryptoRngCore`
    // trait. The workspace `rand` is 0.10 (rand_core 0.10), whose `ThreadRng`
    // does not satisfy that bound, so we use the getrandom-backed rand_core-0.6
    // `OsRng` adapter from `oxitls-core` instead.
    let mut rng = oxitls_core::OsRng;
    let priv_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("rsa keygen");
    let signing_key = SigningKey::<Sha256>::new(priv_key);
    let verifying_key = signing_key.verifying_key();
    let msg = [0u8; 64];

    let mut group = c.benchmark_group("rsa2048_pkcs1v15_sha256");
    group.bench_with_input(BenchmarkId::new("sign", 64), &msg, |b, msg| {
        let mut rng = oxitls_core::OsRng;
        b.iter(|| {
            let sig = signing_key.sign_with_rng(&mut rng, msg);
            std::hint::black_box(sig)
        });
    });

    let sig = signing_key.sign_with_rng(&mut rng, &msg);
    group.bench_with_input(
        BenchmarkId::new("verify", 64),
        &(msg, sig),
        |b, (msg, sig)| {
            b.iter(|| {
                let result = verifying_key.verify(msg, sig);
                std::hint::black_box(result)
            });
        },
    );
    group.finish();
}

// ── Entry point ───────────────────────────────────────────────────────────────

criterion_group!(
    sig_benches,
    bench_ed25519_sign,
    bench_ecdsa_p256_sign,
    bench_ecdsa_p384_sign,
    bench_rsa2048_sign,
);
criterion_main!(sig_benches);
