//! Multi-size AEAD benchmarks: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305
//! across three providers (OxiCrypto/RustCrypto, ring, aws-lc-rs)
//! and three payload sizes (1 KiB, 16 KiB, 256 KiB).
//!
//! Run with: `cargo bench -p oxitls-bench --bench aead_per_suite`
//!
//! # Expected performance ratios (reference)
//!
//! Based on algorithmic parity (all implementations use AES-NI on x86-64):
//! - **AES-128-GCM** and **AES-256-GCM**: oxicrypto/RustCrypto ≈ ring ≈ aws-lc-rs
//!   (≥ 95% throughput parity; all use hardware AES-NI + CLMUL)
//! - **ChaCha20-Poly1305**: oxicrypto/RustCrypto ≈ ring ≈ aws-lc-rs
//!   (≥ 90% parity; no hardware acceleration; slight variance from Poly1305 impl)
//!
//! Actual measured numbers vary by CPU generation and memory bandwidth.
//! Run `./scripts/bench-report.sh` after `./scripts/bench-json.sh` for current values.

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};

// ── RustCrypto ────────────────────────────────────────────────────────────────

use aes_gcm::{
    aead::{AeadInOut, KeyInit},
    Aes128Gcm, Aes256Gcm,
};
use chacha20poly1305::ChaCha20Poly1305;

// ── ring ──────────────────────────────────────────────────────────────────────

use ring::aead::{
    self as ring_aead, LessSafeKey, UnboundKey, AES_128_GCM as RING_AES128GCM,
    AES_256_GCM as RING_AES256GCM, CHACHA20_POLY1305 as RING_CHACHA,
};

// ── aws-lc-rs ─────────────────────────────────────────────────────────────────

use aws_lc_rs::aead::{
    self as lc_aead, LessSafeKey as LcLessSafeKey, UnboundKey as LcUnboundKey,
    AES_128_GCM as LC_AES128GCM, AES_256_GCM as LC_AES256GCM, CHACHA20_POLY1305 as LC_CHACHA,
};

// ── Constants ─────────────────────────────────────────────────────────────────

const SIZES: &[usize] = &[1024, 16 * 1024, 256 * 1024];

const KEY_128: [u8; 16] = [0u8; 16];
const KEY_256: [u8; 32] = [0u8; 32];
const KEY_CHACHA: [u8; 32] = [0u8; 32];
const NONCE_BYTES: [u8; 12] = [0u8; 12];

// ── AES-128-GCM ───────────────────────────────────────────────────────────────

fn bench_aes128gcm_per_suite(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes128gcm_per_provider");

    for &size in SIZES {
        group.throughput(Throughput::Bytes(size as u64));

        // OxiCrypto / RustCrypto
        {
            use aes_gcm::Nonce;
            let cipher = Aes128Gcm::new_from_slice(&KEY_128).expect("aes128gcm key");
            let nonce = Nonce::from(NONCE_BYTES);

            group.bench_with_input(BenchmarkId::new("oxicrypto", size), &size, |b, &sz| {
                let payload = vec![0u8; sz];
                b.iter_batched(
                    || payload.clone(),
                    |mut buf| {
                        let tag = cipher
                            .encrypt_inout_detached(&nonce, b"", (&mut buf[..]).into())
                            .expect("aes128gcm oxicrypto encrypt");
                        std::hint::black_box(tag);
                    },
                    BatchSize::SmallInput,
                );
            });
        }

        // ring
        {
            let ring_key =
                LessSafeKey::new(UnboundKey::new(&RING_AES128GCM, &KEY_128).expect("ring key"));

            group.bench_with_input(BenchmarkId::new("ring", size), &size, |b, &sz| {
                let payload = vec![0u8; sz];
                b.iter_batched(
                    || payload.clone(),
                    |mut buf| {
                        let nonce = ring_aead::Nonce::assume_unique_for_key(NONCE_BYTES);
                        ring_key
                            .seal_in_place_append_tag(nonce, ring_aead::Aad::empty(), &mut buf)
                            .expect("ring aes128gcm encrypt");
                    },
                    BatchSize::SmallInput,
                );
            });
        }

        // aws-lc-rs
        {
            let lc_key = LcLessSafeKey::new(
                LcUnboundKey::new(&LC_AES128GCM, &KEY_128).expect("aws-lc-rs key"),
            );

            group.bench_with_input(BenchmarkId::new("aws_lc_rs", size), &size, |b, &sz| {
                let payload = vec![0u8; sz];
                b.iter_batched(
                    || payload.clone(),
                    |mut buf| {
                        let nonce = lc_aead::Nonce::assume_unique_for_key(NONCE_BYTES);
                        lc_key
                            .seal_in_place_append_tag(nonce, lc_aead::Aad::empty(), &mut buf)
                            .expect("aws-lc-rs aes128gcm encrypt");
                    },
                    BatchSize::SmallInput,
                );
            });
        }
    }

    group.finish();
}

// ── AES-256-GCM ───────────────────────────────────────────────────────────────

fn bench_aes256gcm_per_suite(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes256gcm_per_provider");

    for &size in SIZES {
        group.throughput(Throughput::Bytes(size as u64));

        // OxiCrypto / RustCrypto
        {
            use aes_gcm::Nonce;
            let cipher = Aes256Gcm::new_from_slice(&KEY_256).expect("aes256gcm key");
            let nonce = Nonce::from(NONCE_BYTES);

            group.bench_with_input(BenchmarkId::new("oxicrypto", size), &size, |b, &sz| {
                let payload = vec![0u8; sz];
                b.iter_batched(
                    || payload.clone(),
                    |mut buf| {
                        let tag = cipher
                            .encrypt_inout_detached(&nonce, b"", (&mut buf[..]).into())
                            .expect("aes256gcm oxicrypto encrypt");
                        std::hint::black_box(tag);
                    },
                    BatchSize::SmallInput,
                );
            });
        }

        // ring
        {
            let ring_key =
                LessSafeKey::new(UnboundKey::new(&RING_AES256GCM, &KEY_256).expect("ring key"));

            group.bench_with_input(BenchmarkId::new("ring", size), &size, |b, &sz| {
                let payload = vec![0u8; sz];
                b.iter_batched(
                    || payload.clone(),
                    |mut buf| {
                        let nonce = ring_aead::Nonce::assume_unique_for_key(NONCE_BYTES);
                        ring_key
                            .seal_in_place_append_tag(nonce, ring_aead::Aad::empty(), &mut buf)
                            .expect("ring aes256gcm encrypt");
                    },
                    BatchSize::SmallInput,
                );
            });
        }

        // aws-lc-rs
        {
            let lc_key = LcLessSafeKey::new(
                LcUnboundKey::new(&LC_AES256GCM, &KEY_256).expect("aws-lc-rs key"),
            );

            group.bench_with_input(BenchmarkId::new("aws_lc_rs", size), &size, |b, &sz| {
                let payload = vec![0u8; sz];
                b.iter_batched(
                    || payload.clone(),
                    |mut buf| {
                        let nonce = lc_aead::Nonce::assume_unique_for_key(NONCE_BYTES);
                        lc_key
                            .seal_in_place_append_tag(nonce, lc_aead::Aad::empty(), &mut buf)
                            .expect("aws-lc-rs aes256gcm encrypt");
                    },
                    BatchSize::SmallInput,
                );
            });
        }
    }

    group.finish();
}

// ── ChaCha20-Poly1305 ─────────────────────────────────────────────────────────

fn bench_chacha20_per_suite(c: &mut Criterion) {
    let mut group = c.benchmark_group("chacha20poly1305_per_provider");

    for &size in SIZES {
        group.throughput(Throughput::Bytes(size as u64));

        // OxiCrypto / RustCrypto
        {
            use chacha20poly1305::Nonce;
            let cipher =
                ChaCha20Poly1305::new_from_slice(&KEY_CHACHA).expect("chacha20poly1305 key");
            let nonce = Nonce::from(NONCE_BYTES);

            group.bench_with_input(BenchmarkId::new("oxicrypto", size), &size, |b, &sz| {
                let payload = vec![0u8; sz];
                b.iter_batched(
                    || payload.clone(),
                    |mut buf| {
                        let tag = cipher
                            .encrypt_inout_detached(&nonce, b"", (&mut buf[..]).into())
                            .expect("chacha20poly1305 oxicrypto encrypt");
                        std::hint::black_box(tag);
                    },
                    BatchSize::SmallInput,
                );
            });
        }

        // ring
        {
            let ring_key =
                LessSafeKey::new(UnboundKey::new(&RING_CHACHA, &KEY_CHACHA).expect("ring key"));

            group.bench_with_input(BenchmarkId::new("ring", size), &size, |b, &sz| {
                let payload = vec![0u8; sz];
                b.iter_batched(
                    || payload.clone(),
                    |mut buf| {
                        let nonce = ring_aead::Nonce::assume_unique_for_key(NONCE_BYTES);
                        ring_key
                            .seal_in_place_append_tag(nonce, ring_aead::Aad::empty(), &mut buf)
                            .expect("ring chacha20poly1305 encrypt");
                    },
                    BatchSize::SmallInput,
                );
            });
        }

        // aws-lc-rs
        {
            let lc_key = LcLessSafeKey::new(
                LcUnboundKey::new(&LC_CHACHA, &KEY_CHACHA).expect("aws-lc-rs key"),
            );

            group.bench_with_input(BenchmarkId::new("aws_lc_rs", size), &size, |b, &sz| {
                let payload = vec![0u8; sz];
                b.iter_batched(
                    || payload.clone(),
                    |mut buf| {
                        let nonce = lc_aead::Nonce::assume_unique_for_key(NONCE_BYTES);
                        lc_key
                            .seal_in_place_append_tag(nonce, lc_aead::Aad::empty(), &mut buf)
                            .expect("aws-lc-rs chacha20poly1305 encrypt");
                    },
                    BatchSize::SmallInput,
                );
            });
        }
    }

    group.finish();
}

// ── Entry point ───────────────────────────────────────────────────────────────

criterion_group!(
    aead_per_suite_benches,
    bench_aes128gcm_per_suite,
    bench_aes256gcm_per_suite,
    bench_chacha20_per_suite
);
criterion_main!(aead_per_suite_benches);
