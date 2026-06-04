// SPDX-License-Identifier: Apache-2.0
// Copyright COOLJAPAN OU (Team Kitasan)
//! Session-pool micro-benchmarks for `oxitls-adapter-pkcs11`.
//!
//! # What is measured
//!
//! `Pkcs11SessionPool` is backed by a `parking_lot::Mutex`-guarded `VecDeque`
//! plus a `tokio::sync::Semaphore`.  Without a live HSM the real pool cannot be
//! constructed (it opens PKCS#11 sessions eagerly), so this benchmark simulates
//! pool acquire/release semantics:
//!
//! - **`pool_semaphore_acquire/<cap>`** — the `Semaphore::try_acquire_owned` +
//!   release cycle at capacities 1, 4, and 16.  This is the hot path inside
//!   `Pkcs11SessionPool::acquire()`, measurable without hardware.
//!
//! - **`pool_sign_throughput/<cap>`** — fan-out of `cap` concurrent pure-Rust
//!   P-256 sign operations, simulating `cap` pool slots each doing one sign.
//!   Isolates the scheduling overhead from the signing cost.
//!
//! Both groups run without any HSM.
//!
//! When `SOFTHSM2_MODULE` is set **and** the crate is built with
//! `--features pkcs11` a third group (`hsm_pool_acquire/<cap>`) exercises the
//! real `Pkcs11SessionPool::acquire()` / drop cycle.  Its absence is logged
//! explicitly.
//!
//! Run without hardware (default features):
//! ```text
//! cargo bench -p oxitls-adapter-pkcs11 --bench pkcs11_bench
//! ```
//!
//! Run with SoftHSM2:
//! ```text
//! SOFTHSM2_MODULE=... SOFTHSM2_SLOT=0 SOFTHSM2_PIN=1234 \
//!   cargo bench -p oxitls-adapter-pkcs11 --features pkcs11 --bench pkcs11_bench
//! ```

use std::hint::black_box;
use std::sync::Arc;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::SigningKey;
use tokio::sync::Semaphore;

// ─── helper: P-256 key via getrandom (version-safe, no rand_core dep) ─────────

fn make_p256_key() -> SigningKey {
    loop {
        let mut scalar = [0u8; 32];
        getrandom::fill(&mut scalar).expect("getrandom entropy");
        if let Ok(k) = SigningKey::from_bytes((&scalar).into()) {
            return k;
        }
    }
}

// ─── Bench 1: semaphore acquire / release cycle ───────────────────────────────
//
// `Pkcs11SessionPool::acquire()` calls
// `Arc::clone(&self.semaphore).try_acquire_owned()` then pops from the
// VecDeque.  This bench isolates the semaphore half — the dominant cost
// when a session is always available.

fn bench_semaphore_acquire(c: &mut Criterion) {
    let mut group = c.benchmark_group("pool_semaphore_acquire");
    group.sample_size(50);

    eprintln!(
        "[pool_semaphore_acquire] measuring Semaphore::try_acquire_owned \
         latency at capacities 1/4/16 (hardware-free)"
    );

    for &cap in &[1usize, 4, 16] {
        let sem = Arc::new(Semaphore::new(cap));

        group.bench_with_input(BenchmarkId::new("semaphore_acquire", cap), &cap, |b, _| {
            b.iter(|| {
                let permit = Arc::clone(&sem)
                    .try_acquire_owned()
                    .expect("semaphore should have permits");
                black_box(&permit);
                // permit dropped → slot returned
            });
        });
    }

    group.finish();
}

// ─── Bench 2: fan-out sign throughput (simulates pool-slot utilisation) ───────

fn bench_pool_sign_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("pool_sign_throughput");
    group.sample_size(20);

    eprintln!(
        "[pool_sign_throughput] measuring concurrent P-256 sign throughput \
         at capacities 1/4/16 (hardware-free mock)"
    );

    let msg: Arc<[u8]> = Arc::from(b"bench pool sign throughput".as_slice());

    for &cap in &[1usize, 4, 16] {
        // One P-256 key per simulated pool slot.
        let keys: Arc<Vec<SigningKey>> = Arc::new((0..cap).map(|_| make_p256_key()).collect());
        let sem = Arc::new(Semaphore::new(cap));

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .build()
            .expect("build tokio runtime");

        group.bench_with_input(
            BenchmarkId::new("pool_sign_throughput", cap),
            &cap,
            |b, &workers| {
                b.iter(|| {
                    let k = Arc::clone(&keys);
                    let m = Arc::clone(&msg);
                    let s = Arc::clone(&sem);

                    rt.block_on(async move {
                        let mut handles = Vec::with_capacity(workers);
                        for slot in 0..workers {
                            let ki = Arc::clone(&k);
                            let mi = Arc::clone(&m);
                            let si = Arc::clone(&s);
                            let h = tokio::task::spawn_blocking(move || {
                                // Simulate pool acquire: grab a semaphore permit.
                                let permit = si
                                    .try_acquire_owned()
                                    .expect("semaphore permits must be available");
                                let sig: p256::ecdsa::Signature = ki[slot % ki.len()].sign(&mi);
                                black_box(sig);
                                // permit dropped → slot returned to pool
                                drop(permit);
                            });
                            handles.push(h);
                        }
                        for h in handles {
                            h.await.expect("pool sign task panicked");
                        }
                    });
                });
            },
        );
    }

    group.finish();
}

// ─── Bench 3: real HSM pool acquire (pkcs11 feature + SOFTHSM2_MODULE) ────────

fn bench_hsm_pool_acquire(c: &mut Criterion) {
    let mut group = c.benchmark_group("hsm_pool_acquire");
    group.sample_size(20);

    #[cfg(feature = "pkcs11")]
    run_hsm_pool_acquire_benches(&mut group);

    #[cfg(not(feature = "pkcs11"))]
    eprintln!(
        "[hsm_pool_acquire] built without `pkcs11` feature \
         — HSM pool acquire bench omitted (rerun with --features pkcs11)"
    );

    group.finish();
}

#[cfg(feature = "pkcs11")]
fn run_hsm_pool_acquire_benches(
    group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
) {
    match std::env::var("SOFTHSM2_MODULE") {
        Err(_) => {
            eprintln!(
                "[hsm_pool_acquire] SOFTHSM2_MODULE not set \
                 — skipping real HSM pool acquire bench"
            );
        }
        Ok(module_path) => {
            let slot_id: u64 = std::env::var("SOFTHSM2_SLOT")
                .unwrap_or_else(|_| "0".to_string())
                .parse()
                .unwrap_or(0);
            let pin = std::env::var("SOFTHSM2_PIN").unwrap_or_else(|_| "1234".to_string());

            for &cap in &[1usize, 4, 16] {
                match setup_hsm_pool(&module_path, slot_id, &pin, cap) {
                    Err(e) => {
                        eprintln!(
                            "[hsm_pool_acquire] pool setup (cap={cap}) failed \
                             — skipping: {e}"
                        );
                    }
                    Ok(pool) => {
                        let pool = Arc::new(pool);

                        group.bench_with_input(
                            BenchmarkId::new("hsm_pool_acquire", cap),
                            &cap,
                            |b, _| {
                                b.iter(|| {
                                    let pooled = pool.acquire().expect("hsm pool acquire");
                                    black_box(pooled.session());
                                    // pooled dropped → session returned to pool
                                });
                            },
                        );
                    }
                }
            }
        }
    }
}

// ─── HSM pool setup helper (pkcs11 feature only) ─────────────────────────────

#[cfg(feature = "pkcs11")]
fn setup_hsm_pool(
    module_path: &str,
    slot_id: u64,
    pin: &str,
    capacity: usize,
) -> Result<oxitls_adapter_pkcs11::Pkcs11SessionPool, String> {
    use std::num::NonZeroUsize;
    use std::path::PathBuf;

    use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
    use cryptoki::slot::Slot;
    use secrecy::SecretString;

    let module =
        Pkcs11::new(PathBuf::from(module_path)).map_err(|e| format!("Pkcs11::new: {e}"))?;
    module
        .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .map_err(|e| format!("C_Initialize: {e}"))?;
    let module = Arc::new(module);

    let slot = Slot::try_from(slot_id).map_err(|e| format!("Slot::try_from: {e}"))?;
    let cap = NonZeroUsize::new(capacity).ok_or_else(|| "capacity must be > 0".to_string())?;

    oxitls_adapter_pkcs11::Pkcs11SessionPool::new(
        module,
        slot,
        SecretString::from(pin.to_string()),
        cap,
    )
    .map_err(|e| format!("Pkcs11SessionPool::new: {e}"))
}

// ─── Criterion wiring ─────────────────────────────────────────────────────────

criterion_group!(
    pkcs11_benches,
    bench_semaphore_acquire,
    bench_pool_sign_throughput,
    bench_hsm_pool_acquire
);
criterion_main!(pkcs11_benches);
