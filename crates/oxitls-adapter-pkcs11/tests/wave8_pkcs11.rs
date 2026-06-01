// SPDX-License-Identifier: Apache-2.0
// Copyright COOLJAPAN OU (Team Kitasan)
//! Wave 8 PKCS#11 tests: concurrent session-pool safety and login/logout cycle.
//!
//! Hermetic SNI matching tests live in `src/resolver.rs` (inline `#[cfg(test)]`)
//! because `match_sni` is `pub(crate)` and cannot be imported by integration tests.
//!
//! SoftHSM2-gated tests require:
//! - `SOFTHSM2_MODULE` — path to `libsofthsm2.so` / `libsofthsm2.dylib`
//! - `SOFTHSM2_SLOT`   — slot index (default: 0)
//! - `SOFTHSM2_PIN`    — user PIN (default: 1234)

// ---------------------------------------------------------------------------
// SoftHSM2-gated concurrent pool test
// ---------------------------------------------------------------------------

#[cfg(feature = "pkcs11")]
fn softhsm2_available() -> bool {
    std::env::var("SOFTHSM2_MODULE").is_ok()
}

/// Verify that N=4 concurrent signing requests do not deadlock the session pool.
///
/// Each tokio task acquires a session, simulates work, and releases it.  The
/// test times out in 30 s via `tokio::time::timeout` if a deadlock occurs.
#[cfg(feature = "pkcs11")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires SOFTHSM2_MODULE env var pointing to SoftHSM2 .so/.dylib"]
async fn concurrent_signs_no_deadlock() {
    if !softhsm2_available() {
        return;
    }

    use std::num::NonZeroUsize;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;

    use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
    use cryptoki::slot::Slot;
    use secrecy::SecretString;

    use oxitls_adapter_pkcs11::Pkcs11SessionPool;

    let module_path = PathBuf::from(std::env::var("SOFTHSM2_MODULE").unwrap());
    let slot_id: u64 = std::env::var("SOFTHSM2_SLOT")
        .unwrap_or_else(|_| "0".to_string())
        .parse()
        .unwrap_or(0);
    let pin =
        SecretString::from(std::env::var("SOFTHSM2_PIN").unwrap_or_else(|_| "1234".to_string()));

    let module = Pkcs11::new(&module_path).expect("load PKCS#11 module");
    module
        .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .expect("C_Initialize");
    let module = Arc::new(module);

    let slot = Slot::try_from(slot_id).expect("invalid slot");
    let capacity = NonZeroUsize::new(4).expect("capacity must be non-zero");
    let pool = Arc::new(
        Pkcs11SessionPool::new(Arc::clone(&module), slot, pin, capacity).expect("create pool"),
    );

    // Spawn 4 tasks, each acquiring a session and holding it briefly.
    let mut handles = Vec::with_capacity(4);
    for i in 0u32..4 {
        let pool_clone = Arc::clone(&pool);
        let handle = tokio::task::spawn_blocking(move || {
            let pooled = pool_clone.acquire().expect("acquire session");
            // Access the session reference to ensure the acquire actually ran.
            let _ = pooled.session();
            eprintln!("task {i}: acquired and released session");
            // `pooled` dropped here — session returns to pool.
        });
        handles.push(handle);
    }

    // All tasks must complete within 30 seconds; a timeout implies a deadlock.
    let timeout_res = tokio::time::timeout(Duration::from_secs(30), async {
        for handle in handles {
            handle.await.expect("task panicked");
        }
    })
    .await;

    timeout_res.expect("concurrent_signs_no_deadlock timed out — possible deadlock");

    eprintln!("concurrent_signs_no_deadlock: PASSED");
}

/// Verify that repeated session acquire/release cycles do not leak sessions.
///
/// The pool has capacity 2.  If sessions leaked, the pool would exhaust after
/// `capacity` iterations and return errors on subsequent acquires.  Running 16
/// iterations with no error confirms the return-on-drop semantics are correct.
#[cfg(feature = "pkcs11")]
#[tokio::test]
#[ignore = "requires SOFTHSM2_MODULE env var pointing to SoftHSM2 .so/.dylib"]
async fn login_logout_no_leak() {
    if !softhsm2_available() {
        return;
    }

    use std::num::NonZeroUsize;
    use std::path::PathBuf;
    use std::sync::Arc;

    use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
    use cryptoki::slot::Slot;
    use secrecy::SecretString;

    use oxitls_adapter_pkcs11::Pkcs11SessionPool;

    let module_path = PathBuf::from(std::env::var("SOFTHSM2_MODULE").unwrap());
    let slot_id: u64 = std::env::var("SOFTHSM2_SLOT")
        .unwrap_or_else(|_| "0".to_string())
        .parse()
        .unwrap_or(0);
    let pin =
        SecretString::from(std::env::var("SOFTHSM2_PIN").unwrap_or_else(|_| "1234".to_string()));

    let module = Pkcs11::new(&module_path).expect("load PKCS#11 module");
    module
        .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .expect("C_Initialize");
    let module = Arc::new(module);

    let slot = Slot::try_from(slot_id).expect("invalid slot");
    let capacity = NonZeroUsize::new(2).expect("capacity must be non-zero");
    let pool = Arc::new(
        Pkcs11SessionPool::new(Arc::clone(&module), slot, pin, capacity).expect("create pool"),
    );

    // Repeatedly acquire and release sessions.  If sessions leaked the pool
    // would exhaust after `capacity` iterations and panic on the next acquire.
    for i in 0u32..16 {
        let pooled = pool
            .acquire()
            .expect("session should always be available (no leak)");
        // Access the session to prevent elision.
        let _ = pooled.session();
        // `pooled` dropped here — session returns to pool.
        eprintln!("login_logout_no_leak: iteration {i} OK");
    }

    eprintln!("login_logout_no_leak: PASSED — no session leak detected");
}
