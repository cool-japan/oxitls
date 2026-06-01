//! Benchmark `IntermediateCertCache` under concurrent read and write access.
//!
//! Tests multiple thread-counts (1, 4, 8) so you can see how the RwLock
//! scales. Reads use `get()` (no LRU promotion). A separate group tests
//! `insert()` write-lock contention and a mixed read/write workload.
//!
//! Run with:
//!   `cargo bench -p oxitls-webpki-roots --bench intermediate_cache_contention`

use std::num::NonZeroUsize;
use std::sync::Arc;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use rustls_pki_types::CertificateDer;

use oxitls_webpki_roots::IntermediateCertCache;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn non_zero(n: usize) -> NonZeroUsize {
    NonZeroUsize::new(n).expect("bench capacity must be non-zero")
}

/// Build a synthetic DER blob with unique content for each seed value.
fn make_cert(seed: u8) -> CertificateDer<'static> {
    let bytes: Vec<u8> = (0..64).map(|i| (i as u8).wrapping_add(seed)).collect();
    CertificateDer::from(bytes)
}

/// Populate a cache with `count` entries and return their fingerprints.
fn populate_cache(cache: &IntermediateCertCache, count: u8) -> Vec<[u8; 32]> {
    (0..count)
        .map(|seed| {
            cache
                .insert(make_cert(seed))
                .expect("insert must succeed in bench setup")
        })
        .collect()
}

// ── Group 1: concurrent reads ─────────────────────────────────────────────────

fn bench_concurrent_reads(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_concurrent_reads");

    for &thread_count in &[1usize, 4, 8] {
        // Build a shared cache pre-populated with 100 entries.
        let cache = Arc::new(IntermediateCertCache::new(non_zero(1000)));
        let fingerprints = Arc::new(populate_cache(&cache, 100));

        group.bench_with_input(
            BenchmarkId::from_parameter(thread_count),
            &thread_count,
            |b, &n| {
                b.iter(|| {
                    let handles: Vec<_> = (0..n)
                        .map(|t| {
                            let cache = Arc::clone(&cache);
                            let fps = Arc::clone(&fingerprints);
                            std::thread::spawn(move || {
                                // Each thread reads 50 entries, cycling through
                                // the pre-populated fingerprints.
                                for i in 0..50_usize {
                                    let fp = &fps[i % fps.len()];
                                    let _ = cache.get(fp).expect("get should not fail in bench");
                                    // Stagger accesses slightly per thread.
                                    let _ = cache
                                        .get(&fps[(i + t) % fps.len()])
                                        .expect("get should not fail");
                                }
                            })
                        })
                        .collect();
                    for h in handles {
                        h.join().expect("bench thread panicked");
                    }
                })
            },
        );
    }

    group.finish();
}

// ── Group 2: concurrent inserts (write contention) ───────────────────────────

fn bench_concurrent_inserts(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_concurrent_inserts");

    for &thread_count in &[1usize, 4, 8] {
        group.bench_with_input(
            BenchmarkId::from_parameter(thread_count),
            &thread_count,
            |b, &n| {
                b.iter(|| {
                    // Fresh cache each iteration so we always exercise insertion,
                    // not eviction of an already-full store.
                    let cache = Arc::new(IntermediateCertCache::new(non_zero(512)));
                    let handles: Vec<_> = (0..n)
                        .map(|t| {
                            let cache = Arc::clone(&cache);
                            std::thread::spawn(move || {
                                for i in 0..20_usize {
                                    // Each thread uses a distinct seed range
                                    // so collisions don't mask write contention.
                                    let seed = ((t * 20 + i) % 256) as u8;
                                    let _ = cache
                                        .insert(make_cert(seed))
                                        .expect("insert must not fail");
                                }
                            })
                        })
                        .collect();
                    for h in handles {
                        h.join().expect("bench thread panicked");
                    }
                })
            },
        );
    }

    group.finish();
}

// ── Group 3: mixed read/write workload ────────────────────────────────────────

fn bench_mixed_read_write(c: &mut Criterion) {
    let cache = Arc::new(IntermediateCertCache::new(non_zero(1000)));
    let fingerprints = Arc::new(populate_cache(&cache, 200));

    let mut group = c.benchmark_group("cache_mixed_rw");

    for &thread_count in &[4usize, 8] {
        group.bench_with_input(
            BenchmarkId::from_parameter(thread_count),
            &thread_count,
            |b, &n| {
                b.iter(|| {
                    let handles: Vec<_> = (0..n)
                        .map(|t| {
                            let cache = Arc::clone(&cache);
                            let fps = Arc::clone(&fingerprints);
                            std::thread::spawn(move || {
                                for i in 0..40_usize {
                                    if (i + t) % 5 == 0 {
                                        // ~20 % writes
                                        let seed = ((t * 40 + i) % 256) as u8;
                                        let _ = cache.insert(make_cert(seed));
                                    } else {
                                        // ~80 % reads
                                        let fp = &fps[(i + t) % fps.len()];
                                        let _ = cache.get(fp);
                                    }
                                }
                            })
                        })
                        .collect();
                    for h in handles {
                        h.join().expect("bench thread panicked");
                    }
                })
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_concurrent_reads,
    bench_concurrent_inserts,
    bench_mixed_read_write,
);
criterion_main!(benches);
