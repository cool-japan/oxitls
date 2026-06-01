//! Benchmark OxiTicketer encrypt throughput under concurrent access.
//!
//! Creates a single `OxiTicketer` shared across 4 tokio tasks; each task
//! calls `ticketer.encrypt(...)` in a tight loop.  The bench measures total
//! wall time for all tasks to complete 100 encryptions each (400 total) as
//! a proxy for contention on the ticketer's internal mutex.
//!
//! A second variant also triggers an explicit `rotate()` mid-flight to
//! measure the stop-the-world cost of key rotation under concurrent
//! encrypt pressure.
//!
//! Run with: `cargo bench -p oxitls-bench --bench ticketer_rotation_contention`

use std::hint::black_box;
use std::sync::Arc;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use oxitls::OxiTicketer;
use rustls::server::ProducesTickets as _;

// ── Number of parallel tasks and encryptions per task ────────────────────────

const TASKS: usize = 4;
const ENCRYPTS_PER_TASK: usize = 100;

// Payload that roughly mimics a TLS session ticket (~96 bytes).
static TICKET_PAYLOAD: &[u8] = b"session-ticket-state-000000000000000000000000000000000000000000000000000000000000000000000000";

// ── Bench 1: 4 concurrent encrypt tasks, no rotation ─────────────────────────

fn bench_ticketer_4_concurrent_encrypts(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("runtime");

    c.bench_function("ticketer_4_concurrent_encrypts", |b| {
        b.iter_batched(
            || Arc::new(OxiTicketer::new().expect("ticketer")),
            |ticketer| {
                rt.block_on(async move {
                    let mut handles = Vec::with_capacity(TASKS);
                    for _ in 0..TASKS {
                        let t = Arc::clone(&ticketer);
                        handles.push(tokio::spawn(async move {
                            for _ in 0..ENCRYPTS_PER_TASK {
                                let enc = t.encrypt(TICKET_PAYLOAD).expect("encrypt");
                                black_box(enc);
                            }
                        }));
                    }
                    for h in handles {
                        h.await.expect("task");
                    }
                });
            },
            BatchSize::SmallInput,
        );
    });
}

// ── Bench 2: 4 concurrent encrypts + 1 rotation task mid-flight ──────────────

fn bench_ticketer_4_concurrent_with_rotation(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("runtime");

    c.bench_function("ticketer_4_concurrent_with_rotation", |b| {
        b.iter_batched(
            || Arc::new(OxiTicketer::new().expect("ticketer")),
            |ticketer| {
                rt.block_on(async move {
                    let mut handles = Vec::with_capacity(TASKS + 1);

                    // Spawn encrypt tasks.
                    for _ in 0..TASKS {
                        let t = Arc::clone(&ticketer);
                        handles.push(tokio::spawn(async move {
                            for _ in 0..ENCRYPTS_PER_TASK {
                                let enc = t.encrypt(TICKET_PAYLOAD).expect("encrypt");
                                black_box(enc);
                            }
                        }));
                    }

                    // Spawn a single rotate task that fires during the encrypt flood.
                    {
                        let t = Arc::clone(&ticketer);
                        handles.push(tokio::spawn(async move {
                            // Yield once to let some encrypts in flight first.
                            tokio::task::yield_now().await;
                            t.rotate().expect("rotate");
                        }));
                    }

                    for h in handles {
                        h.await.expect("task");
                    }
                });
            },
            BatchSize::SmallInput,
        );
    });
}

// ── Bench 3: single-threaded encrypt baseline (no contention) ────────────────

fn bench_ticketer_single_thread_baseline(c: &mut Criterion) {
    let ticketer = Arc::new(OxiTicketer::new().expect("ticketer"));

    c.bench_function("ticketer_single_thread_400_encrypts", |b| {
        b.iter(|| {
            for _ in 0..(TASKS * ENCRYPTS_PER_TASK) {
                let enc = ticketer.encrypt(TICKET_PAYLOAD).expect("encrypt");
                black_box(enc);
            }
        });
    });
}

// ── Entry point ───────────────────────────────────────────────────────────────

criterion_group!(
    ticketer_contention_benches,
    bench_ticketer_4_concurrent_encrypts,
    bench_ticketer_4_concurrent_with_rotation,
    bench_ticketer_single_thread_baseline,
);
criterion_main!(ticketer_contention_benches);
