//! SHA-256 digest micro-benchmarks across providers (sha2/OxiCrypto, ring, aws-lc-rs)
//! and three payload sizes (1 KiB, 64 KiB, 1 MiB).
//!
//! Run with: `cargo bench -p oxitls-bench --bench digest`

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

// ── Constants ─────────────────────────────────────────────────────────────────

const SIZES: &[usize] = &[1024, 64 * 1024, 1024 * 1024];

// ── SHA-256 ───────────────────────────────────────────────────────────────────

fn bench_sha256(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha256");

    for &size in SIZES {
        group.throughput(Throughput::Bytes(size as u64));
        let data = vec![0u8; size];

        // sha2 (RustCrypto / OxiCrypto)
        {
            use sha2::{Digest, Sha256};
            group.bench_with_input(BenchmarkId::new("sha2", size), &data, |b, d| {
                b.iter(|| {
                    let mut hasher = Sha256::new();
                    hasher.update(d);
                    std::hint::black_box(hasher.finalize())
                });
            });
        }

        // ring
        {
            group.bench_with_input(BenchmarkId::new("ring", size), &data, |b, d| {
                b.iter(|| std::hint::black_box(ring::digest::digest(&ring::digest::SHA256, d)));
            });
        }

        // aws-lc-rs
        {
            group.bench_with_input(BenchmarkId::new("aws_lc_rs", size), &data, |b, d| {
                b.iter(|| {
                    std::hint::black_box(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, d))
                });
            });
        }
    }

    group.finish();
}

// ── Entry point ───────────────────────────────────────────────────────────────

criterion_group!(digest_benches, bench_sha256);
criterion_main!(digest_benches);
