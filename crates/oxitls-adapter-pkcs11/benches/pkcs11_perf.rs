// SPDX-License-Identifier: Apache-2.0
// Copyright COOLJAPAN OU (Team Kitasan)
//! Performance benchmarks for the PKCS#11 signing adapter.
//!
//! Two criterion groups:
//!
//! 1. **`pkcs11_sign_latency`** — per-sign latency comparison.
//!    - `software_ecdsa_p256`: always-measured pure-Rust ECDSA-P256 baseline.
//!    - `hsm_ecdsa_p256` (feature = "pkcs11"): real SoftHSM2 sign latency when
//!      `SOFTHSM2_MODULE` is set; explicitly logged and skipped otherwise.
//!
//! 2. **`pkcs11_pool_contention`** — concurrent-signer throughput at pool
//!    capacities 1, 4, and 16.
//!    - `mock_concurrent_signs/<cap>`: always-measured pure-Rust simulation.
//!    - `hsm_pool_contention/<cap>` (feature = "pkcs11"): SoftHSM2 pool
//!      contention when `SOFTHSM2_MODULE` is set; explicitly logged and skipped
//!      otherwise.
//!
//! Run without hardware:
//! ```text
//! cargo bench -p oxitls-adapter-pkcs11 --bench pkcs11_perf
//! ```
//!
//! Run with SoftHSM2:
//! ```text
//! SOFTHSM2_MODULE=... SOFTHSM2_SLOT=0 SOFTHSM2_PIN=1234 SOFTHSM2_KEY_LABEL=test-ecdsa \
//!   cargo bench -p oxitls-adapter-pkcs11 --features pkcs11 --bench pkcs11_perf
//! ```

use std::hint::black_box;
use std::sync::Arc;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::SigningKey;

// ─── helper: generate a P-256 signing key via getrandom ──────────────────────
//
// p256 0.14.0-rc.9 uses rand_core 0.10.  Using `rand_core::OsRng` directly
// from a dev-dep would require a matching rand_core dev-dep version.
// Using `getrandom::fill` (same pattern as oxitls-bench/benches/sig.rs)
// is version-safe and avoids the rand_core coupling.

fn make_p256_key() -> SigningKey {
    loop {
        let mut scalar = [0u8; 32];
        getrandom::fill(&mut scalar).expect("getrandom entropy");
        if let Ok(k) = SigningKey::from_bytes((&scalar).into()) {
            return k;
        }
    }
}

// ─── Group 1: sign latency ────────────────────────────────────────────────────

fn bench_sign_latency(c: &mut Criterion) {
    let mut group = c.benchmark_group("pkcs11_sign_latency");

    // Always-measured software ECDSA-P256 baseline — no HSM needed.
    let sw_key = make_p256_key();
    let msg = b"oxitls pkcs11 bench message";

    group.bench_function("software_ecdsa_p256", |b| {
        b.iter(|| {
            let sig: p256::ecdsa::Signature = sw_key.sign(black_box(msg));
            black_box(sig);
        });
    });

    // HSM sign latency — only compiled when the `pkcs11` feature is active.
    #[cfg(feature = "pkcs11")]
    bench_hsm_sign_latency(&mut group, msg);

    #[cfg(not(feature = "pkcs11"))]
    eprintln!(
        "[pkcs11_sign_latency] built without `pkcs11` feature \
         — HSM sign bench omitted (rerun with --features pkcs11)"
    );

    group.finish();
}

#[cfg(feature = "pkcs11")]
fn bench_hsm_sign_latency(
    group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
    msg: &[u8],
) {
    match std::env::var("SOFTHSM2_MODULE") {
        Err(_) => {
            eprintln!(
                "[pkcs11_sign_latency] SOFTHSM2_MODULE not set \
                 — skipping HSM sign bench"
            );
        }
        Ok(module_path) => {
            let slot_id: u64 = std::env::var("SOFTHSM2_SLOT")
                .unwrap_or_else(|_| "0".to_string())
                .parse()
                .unwrap_or(0);
            let pin = std::env::var("SOFTHSM2_PIN").unwrap_or_else(|_| "1234".to_string());
            let key_label =
                std::env::var("SOFTHSM2_KEY_LABEL").unwrap_or_else(|_| "test-ecdsa".to_string());

            match setup_hsm_signer(&module_path, slot_id, &pin, &key_label) {
                Err(e) => {
                    eprintln!(
                        "[pkcs11_sign_latency] HSM setup failed \
                         — skipping HSM bench: {e}"
                    );
                }
                Ok(signer) => {
                    group.bench_function("hsm_ecdsa_p256", |b| {
                        b.iter(|| {
                            let sig = signer.sign(black_box(msg));
                            black_box(sig);
                        });
                    });
                }
            }
        }
    }
}

// ─── Group 2: pool contention ─────────────────────────────────────────────────

fn bench_pool_contention(c: &mut Criterion) {
    let mut group = c.benchmark_group("pkcs11_pool_contention");
    group.sample_size(20);

    let msg: Arc<[u8]> = Arc::from(b"oxitls bench contention".as_slice());

    // Always-measured mock path — pure-Rust P-256, no hardware.
    //
    // We pre-generate `capacity` signing keys (simulating pool slots), then
    // fan out `capacity` concurrent async tasks each picking a key by index.
    // This exercises tokio scheduler overhead and Arc-clone cost at each
    // concurrency level without touching any PKCS#11 code.
    for &capacity in &[1usize, 4, 16] {
        let keys: Arc<Vec<SigningKey>> = Arc::new((0..capacity).map(|_| make_p256_key()).collect());

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .build()
            .expect("build tokio runtime");

        group.bench_with_input(
            BenchmarkId::new("mock_concurrent_signs", capacity),
            &capacity,
            |b, &cap| {
                b.iter(|| {
                    let keys_clone = Arc::clone(&keys);
                    let msg_clone = Arc::clone(&msg);

                    rt.block_on(async move {
                        let mut handles = Vec::with_capacity(cap);
                        for slot in 0..cap {
                            let k = Arc::clone(&keys_clone);
                            let m = Arc::clone(&msg_clone);
                            let h = tokio::task::spawn_blocking(move || {
                                let sig: p256::ecdsa::Signature = k[slot % k.len()].sign(&m);
                                black_box(sig);
                            });
                            handles.push(h);
                        }
                        for h in handles {
                            h.await.expect("mock sign task panicked");
                        }
                    });
                });
            },
        );
    }

    // HSM pool contention path — only compiled when `pkcs11` feature is active.
    #[cfg(feature = "pkcs11")]
    bench_hsm_pool_contention(&mut group);

    #[cfg(not(feature = "pkcs11"))]
    eprintln!(
        "[pkcs11_pool_contention] built without `pkcs11` feature \
         — HSM pool bench omitted (rerun with --features pkcs11)"
    );

    group.finish();
}

#[cfg(feature = "pkcs11")]
fn bench_hsm_pool_contention(
    group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
) {
    match std::env::var("SOFTHSM2_MODULE") {
        Err(_) => {
            eprintln!(
                "[pkcs11_pool_contention] SOFTHSM2_MODULE not set \
                 — skipping HSM pool bench"
            );
        }
        Ok(module_path) => {
            let slot_id: u64 = std::env::var("SOFTHSM2_SLOT")
                .unwrap_or_else(|_| "0".to_string())
                .parse()
                .unwrap_or(0);
            let pin = std::env::var("SOFTHSM2_PIN").unwrap_or_else(|_| "1234".to_string());
            let key_label =
                std::env::var("SOFTHSM2_KEY_LABEL").unwrap_or_else(|_| "test-ecdsa".to_string());

            for &capacity in &[1usize, 4, 16] {
                match setup_hsm_pool(&module_path, slot_id, &pin, capacity) {
                    Err(e) => {
                        eprintln!(
                            "[pkcs11_pool_contention] HSM pool setup (cap={capacity}) \
                             failed — skipping: {e}"
                        );
                    }
                    Ok(pool) => {
                        let pool = Arc::new(pool);
                        let kl = key_label.clone();

                        group.bench_with_input(
                            BenchmarkId::new("hsm_pool_contention", capacity),
                            &capacity,
                            |b, &cap| {
                                use rustls::sign::SigningKey as _;
                                use rustls::SignatureScheme;

                                let signing_key =
                                    match oxitls_adapter_pkcs11::Pkcs11SigningKey::new(
                                        Arc::clone(&pool),
                                        &kl,
                                    ) {
                                        Ok(k) => k,
                                        Err(e) => {
                                            eprintln!(
                                                "[pkcs11_pool_contention] \
                                                 Pkcs11SigningKey::new failed: {e}"
                                            );
                                            return;
                                        }
                                    };
                                let signing_key = Arc::new(signing_key);

                                let rt = tokio::runtime::Builder::new_multi_thread()
                                    .worker_threads(4)
                                    .build()
                                    .expect("build tokio runtime");

                                b.iter(|| {
                                    let sk = Arc::clone(&signing_key);
                                    let m: Arc<[u8]> =
                                        Arc::from(b"hsm contention bench".as_slice());

                                    rt.block_on(async move {
                                        let mut handles = Vec::with_capacity(cap);
                                        for _ in 0..cap {
                                            let sk_c = Arc::clone(&sk);
                                            let m_c = Arc::clone(&m);
                                            let h = tokio::task::spawn_blocking(move || {
                                                let signer = sk_c
                                                    .choose_scheme(&[
                                                        SignatureScheme::ECDSA_NISTP256_SHA256,
                                                    ])
                                                    .expect("choose_scheme");
                                                let sig =
                                                    signer.sign(&m_c).expect("hsm sign");
                                                black_box(sig);
                                            });
                                            handles.push(h);
                                        }
                                        for h in handles {
                                            h.await.expect("hsm sign task panicked");
                                        }
                                    });
                                });
                            },
                        );
                    }
                }
            }
        }
    }
}

// ─── HSM helper types / functions (pkcs11 feature only) ──────────────────────

#[cfg(feature = "pkcs11")]
struct HsmSigner {
    /// Keeps the pool alive for the lifetime of the bench.
    _pool: Arc<oxitls_adapter_pkcs11::Pkcs11SessionPool>,
    signing_key: oxitls_adapter_pkcs11::Pkcs11SigningKey,
}

#[cfg(feature = "pkcs11")]
impl HsmSigner {
    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        use rustls::sign::SigningKey as _;
        use rustls::SignatureScheme;

        let signer = self
            .signing_key
            .choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256])
            .expect("choose_scheme");
        signer.sign(msg).expect("hsm sign")
    }
}

#[cfg(feature = "pkcs11")]
fn setup_hsm_signer(
    module_path: &str,
    slot_id: u64,
    pin: &str,
    key_label: &str,
) -> Result<HsmSigner, String> {
    let pool = Arc::new(setup_hsm_pool(module_path, slot_id, pin, 4)?);
    let signing_key = oxitls_adapter_pkcs11::Pkcs11SigningKey::new(Arc::clone(&pool), key_label)
        .map_err(|e| format!("Pkcs11SigningKey::new: {e}"))?;
    Ok(HsmSigner {
        _pool: pool,
        signing_key,
    })
}

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

criterion_group!(benches, bench_sign_latency, bench_pool_contention);
criterion_main!(benches);
