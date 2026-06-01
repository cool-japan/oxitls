//! OxiTicketer lifecycle benchmarks.
//!
//! Measures the cost of:
//!   1. Creating a new `OxiTicketer` (OS entropy key generation)
//!   2. Full encrypt + decrypt round-trip (simulating a ticket creation +
//!      server-side verification)
//!   3. Key rotation via `OxiTicketer::rotate()`
//!
//! Run with: `cargo bench -p oxitls-bench --bench oxiticketer_rotation`

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use oxitls::OxiTicketer;
use rustls::server::ProducesTickets as _;

// ── Bench: ticketer construction (OS entropy keygen) ─────────────────────────

fn bench_oxiticketer_new(c: &mut Criterion) {
    c.bench_function("oxiticketer_new", |b| {
        b.iter(|| {
            let t = OxiTicketer::new();
            black_box(t)
        });
    });
}

// ── Bench: encrypt + decrypt round-trip ──────────────────────────────────────

fn bench_oxiticketer_roundtrip(c: &mut Criterion) {
    let ticketer = OxiTicketer::new().expect("oxiticketer creation");
    let msg = b"session-state-data-for-benchmarking-0123456789abcdef";

    c.bench_function("oxiticketer_encrypt_decrypt_roundtrip", |b| {
        b.iter_batched(
            || msg.to_vec(),
            |plain| {
                let encrypted = ticketer
                    .encrypt(black_box(&plain))
                    .expect("encrypt must succeed");
                let decrypted = ticketer.decrypt(black_box(&encrypted));
                black_box(decrypted)
            },
            BatchSize::SmallInput,
        );
    });
}

// ── Bench: key rotation cost ──────────────────────────────────────────────────

fn bench_oxiticketer_rotate(c: &mut Criterion) {
    let ticketer = OxiTicketer::new().expect("oxiticketer creation");

    c.bench_function("oxiticketer_rotate", |b| {
        b.iter(|| ticketer.rotate().expect("rotate must succeed"));
    });
}

// ── Bench: decrypt after rotation (previous-key path) ────────────────────────

fn bench_oxiticketer_decrypt_after_rotation(c: &mut Criterion) {
    let ticketer = OxiTicketer::new().expect("oxiticketer creation");
    let msg = b"ticket-payload-to-test-key-fallback-path";

    // Encrypt under current key, then rotate so the key becomes "previous".
    let encrypted = ticketer
        .encrypt(msg)
        .expect("pre-rotation encrypt must succeed");
    ticketer.rotate().expect("rotate must succeed");

    c.bench_function("oxiticketer_decrypt_after_rotation", |b| {
        b.iter_batched(
            || encrypted.clone(),
            |ticket| {
                let result = ticketer.decrypt(black_box(&ticket));
                black_box(result)
            },
            BatchSize::SmallInput,
        );
    });
}

// ── Entry point ───────────────────────────────────────────────────────────────

criterion_group!(
    ticketer_rotation_benches,
    bench_oxiticketer_new,
    bench_oxiticketer_roundtrip,
    bench_oxiticketer_rotate,
    bench_oxiticketer_decrypt_after_rotation,
);
criterion_main!(ticketer_rotation_benches);
