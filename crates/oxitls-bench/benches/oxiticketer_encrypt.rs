//! OxiTicketer encrypt micro-benchmarks.
//!
//! Measures the cost of encrypting session-state blobs of different sizes
//! using `OxiTicketer` (AES-256-GCM backed, pure Rust).
//!
//! Two payload sizes:
//!   - 64 bytes  — typical TLS session state (master secret + metadata)
//!   - 1 KiB     — larger session state with extra extensions
//!
//! Run with: `cargo bench -p oxitls-bench --bench oxiticketer_encrypt`

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use oxitls::OxiTicketer;
use rustls::server::ProducesTickets as _;

// ── Bench: encrypt 64-byte session state ─────────────────────────────────────

fn bench_oxiticketer_encrypt_64b(c: &mut Criterion) {
    let ticketer = OxiTicketer::new().expect("oxiticketer creation");
    let message = vec![0u8; 64];

    c.bench_function("oxiticketer_encrypt_64b", |b| {
        b.iter_batched(
            || message.clone(),
            |msg| ticketer.encrypt(black_box(&msg)),
            BatchSize::SmallInput,
        );
    });
}

// ── Bench: encrypt 1 KiB session state ───────────────────────────────────────

fn bench_oxiticketer_encrypt_1kb(c: &mut Criterion) {
    let ticketer = OxiTicketer::new().expect("oxiticketer creation");
    let message = vec![0u8; 1024];

    c.bench_function("oxiticketer_encrypt_1kb", |b| {
        b.iter_batched(
            || message.clone(),
            |msg| ticketer.encrypt(black_box(&msg)),
            BatchSize::SmallInput,
        );
    });
}

// ── Entry point ───────────────────────────────────────────────────────────────

criterion_group!(
    ticketer_encrypt_benches,
    bench_oxiticketer_encrypt_64b,
    bench_oxiticketer_encrypt_1kb,
);
criterion_main!(ticketer_encrypt_benches);
