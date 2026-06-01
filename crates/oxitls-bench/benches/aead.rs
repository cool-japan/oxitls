//! AEAD micro-benchmarks: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305
//! for a 1 KiB payload.
//!
//! Compares OxiCrypto (RustCrypto) against ring and aws-lc-rs.
//!
//! Run with: `cargo bench -p oxitls-bench --bench aead`
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

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};

// ── RustCrypto ────────────────────────────────────────────────────────────────

use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
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

const DATA_LEN: usize = 1024;
const KEY_128: [u8; 16] = [0u8; 16];
const KEY_256: [u8; 32] = [0u8; 32];
const KEY_CHACHA: [u8; 32] = [0u8; 32];
const NONCE_BYTES: [u8; 12] = [0u8; 12];

// ── AES-128-GCM ───────────────────────────────────────────────────────────────

fn bench_aes128gcm(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes128gcm_encrypt_1kb");
    let data = [0u8; DATA_LEN];

    // RustCrypto
    {
        use aes_gcm::{Key, Nonce};
        let key = Key::<Aes128Gcm>::from_slice(&KEY_128);
        let cipher = Aes128Gcm::new(key);
        let nonce = Nonce::from_slice(&NONCE_BYTES);
        group.bench_with_input(
            BenchmarkId::new("oxicrypto", DATA_LEN),
            &DATA_LEN,
            |b, _| {
                b.iter_batched(
                    || data.to_vec(),
                    |mut buf| {
                        let tag = cipher
                            .encrypt_in_place_detached(nonce, b"", &mut buf)
                            .expect("aes128gcm encrypt");
                        std::hint::black_box(tag);
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

    // ring
    {
        let ring_key =
            LessSafeKey::new(UnboundKey::new(&RING_AES128GCM, &KEY_128).expect("ring key"));
        group.bench_with_input(BenchmarkId::new("ring", DATA_LEN), &DATA_LEN, |b, _| {
            b.iter_batched(
                || data.to_vec(),
                |mut buf| {
                    let nonce = ring_aead::Nonce::assume_unique_for_key(NONCE_BYTES);
                    ring_key
                        .seal_in_place_append_tag(nonce, ring_aead::Aad::empty(), &mut buf)
                        .expect("ring aes128gcm encrypt");
                },
                BatchSize::SmallInput,
            )
        });
    }

    // aws-lc-rs
    {
        let lc_key =
            LcLessSafeKey::new(LcUnboundKey::new(&LC_AES128GCM, &KEY_128).expect("aws-lc-rs key"));
        group.bench_with_input(
            BenchmarkId::new("aws_lc_rs", DATA_LEN),
            &DATA_LEN,
            |b, _| {
                b.iter_batched(
                    || data.to_vec(),
                    |mut buf| {
                        let nonce = lc_aead::Nonce::assume_unique_for_key(NONCE_BYTES);
                        lc_key
                            .seal_in_place_append_tag(nonce, lc_aead::Aad::empty(), &mut buf)
                            .expect("aws-lc-rs aes128gcm encrypt");
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

    group.finish();
}

// ── AES-256-GCM ───────────────────────────────────────────────────────────────

fn bench_aes256gcm(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes256gcm_encrypt_1kb");
    let data = [0u8; DATA_LEN];

    // RustCrypto
    {
        use aes_gcm::{Key, Nonce};
        let key = Key::<Aes256Gcm>::from_slice(&KEY_256);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&NONCE_BYTES);
        group.bench_with_input(
            BenchmarkId::new("oxicrypto", DATA_LEN),
            &DATA_LEN,
            |b, _| {
                b.iter_batched(
                    || data.to_vec(),
                    |mut buf| {
                        let tag = cipher
                            .encrypt_in_place_detached(nonce, b"", &mut buf)
                            .expect("aes256gcm encrypt");
                        std::hint::black_box(tag);
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

    // ring
    {
        let ring_key =
            LessSafeKey::new(UnboundKey::new(&RING_AES256GCM, &KEY_256).expect("ring key"));
        group.bench_with_input(BenchmarkId::new("ring", DATA_LEN), &DATA_LEN, |b, _| {
            b.iter_batched(
                || data.to_vec(),
                |mut buf| {
                    let nonce = ring_aead::Nonce::assume_unique_for_key(NONCE_BYTES);
                    ring_key
                        .seal_in_place_append_tag(nonce, ring_aead::Aad::empty(), &mut buf)
                        .expect("ring aes256gcm encrypt");
                },
                BatchSize::SmallInput,
            )
        });
    }

    // aws-lc-rs
    {
        let lc_key =
            LcLessSafeKey::new(LcUnboundKey::new(&LC_AES256GCM, &KEY_256).expect("aws-lc-rs key"));
        group.bench_with_input(
            BenchmarkId::new("aws_lc_rs", DATA_LEN),
            &DATA_LEN,
            |b, _| {
                b.iter_batched(
                    || data.to_vec(),
                    |mut buf| {
                        let nonce = lc_aead::Nonce::assume_unique_for_key(NONCE_BYTES);
                        lc_key
                            .seal_in_place_append_tag(nonce, lc_aead::Aad::empty(), &mut buf)
                            .expect("aws-lc-rs aes256gcm encrypt");
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

    group.finish();
}

// ── ChaCha20-Poly1305 ─────────────────────────────────────────────────────────

fn bench_chacha20poly1305(c: &mut Criterion) {
    let mut group = c.benchmark_group("chacha20poly1305_encrypt_1kb");
    let data = [0u8; DATA_LEN];

    // RustCrypto
    {
        use chacha20poly1305::{Key, Nonce};
        let key = Key::from_slice(&KEY_CHACHA);
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = Nonce::from_slice(&NONCE_BYTES);
        group.bench_with_input(
            BenchmarkId::new("oxicrypto", DATA_LEN),
            &DATA_LEN,
            |b, _| {
                b.iter_batched(
                    || data.to_vec(),
                    |mut buf| {
                        let tag = cipher
                            .encrypt_in_place_detached(nonce, b"", &mut buf)
                            .expect("chacha20poly1305 encrypt");
                        std::hint::black_box(tag);
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

    // ring
    {
        let ring_key =
            LessSafeKey::new(UnboundKey::new(&RING_CHACHA, &KEY_CHACHA).expect("ring key"));
        group.bench_with_input(BenchmarkId::new("ring", DATA_LEN), &DATA_LEN, |b, _| {
            b.iter_batched(
                || data.to_vec(),
                |mut buf| {
                    let nonce = ring_aead::Nonce::assume_unique_for_key(NONCE_BYTES);
                    ring_key
                        .seal_in_place_append_tag(nonce, ring_aead::Aad::empty(), &mut buf)
                        .expect("ring chacha encrypt");
                },
                BatchSize::SmallInput,
            )
        });
    }

    // aws-lc-rs
    {
        let lc_key =
            LcLessSafeKey::new(LcUnboundKey::new(&LC_CHACHA, &KEY_CHACHA).expect("aws-lc-rs key"));
        group.bench_with_input(
            BenchmarkId::new("aws_lc_rs", DATA_LEN),
            &DATA_LEN,
            |b, _| {
                b.iter_batched(
                    || data.to_vec(),
                    |mut buf| {
                        let nonce = lc_aead::Nonce::assume_unique_for_key(NONCE_BYTES);
                        lc_key
                            .seal_in_place_append_tag(nonce, lc_aead::Aad::empty(), &mut buf)
                            .expect("aws-lc-rs chacha encrypt");
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

    group.finish();
}

// ── Entry point ───────────────────────────────────────────────────────────────

criterion_group!(
    aead_benches,
    bench_aes128gcm,
    bench_aes256gcm,
    bench_chacha20poly1305
);
criterion_main!(aead_benches);
