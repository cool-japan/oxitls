//! Memory footprint benchmark for `ClientConfig` and `ServerConfig`.
//!
//! Measures:
//! - Time to construct each config (proxy for allocation work).
//! - Stack size of each config via `std::mem::size_of_val` (informational).
//! - Heap allocation count via a lightweight `#[global_allocator]` counter.
//!
//! Edition 2021: inner unsafe blocks inside unsafe fns require no additional
//! wrapping — `unsafe_op_in_unsafe_fn` is allow-by-default in 2021.
//!
//! Run with:
//! `cargo bench -p oxitls-adapter-rustls-rustcrypto --bench memory -- --nocapture`

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use criterion::{criterion_group, criterion_main, Criterion};
use oxitls_adapter_rustls_rustcrypto::{
    RustcryptoClientConfigBuilder, RustcryptoServerConfigBuilder,
};
use oxitls_rcgen::generate_self_signed_ed25519;
use oxitls_webpki_roots::webpki_root_certs;
use rustls::RootCertStore;
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

// ── Counting allocator ────────────────────────────────────────────────────────

/// Global heap-byte counter.  Monotonically increasing — subtract snapshots
/// to measure allocation work during a section.
static ALLOC_BYTES: AtomicUsize = AtomicUsize::new(0);

struct CountingAlloc;

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOC_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOC_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        System.alloc_zeroed(layout)
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if new_size > layout.size() {
            ALLOC_BYTES.fetch_add(new_size - layout.size(), Ordering::Relaxed);
        }
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static GLOBAL: CountingAlloc = CountingAlloc;

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Read the current allocation counter value.
fn alloc_snapshot() -> usize {
    ALLOC_BYTES.load(Ordering::Relaxed)
}

// ── Benchmarks ────────────────────────────────────────────────────────────────

fn bench_client_config_memory(c: &mut Criterion) {
    // Populate a root store once; clone per iteration so construction is the
    // only work timed.
    let roots = webpki_root_certs();

    // Clone the root store *before* the snapshot so the counter only captures
    // the ClientConfig construction, not the ~150-CA store copy.
    let roots_for_sample = roots.clone();
    let before = alloc_snapshot();
    let sample_cfg = RustcryptoClientConfigBuilder::new()
        .with_roots(roots_for_sample)
        .build()
        .expect("client config build");
    let after = alloc_snapshot();

    let heap_bytes = after - before;
    let stack_bytes = std::mem::size_of_val(&sample_cfg);
    println!("\nClientConfig  stack={stack_bytes} B  heap_alloc_during_build~={heap_bytes} B");
    std::hint::black_box(sample_cfg);

    // Criterion timing benchmark.
    c.bench_function("client_config/construct_with_webpki_roots", |b| {
        b.iter(|| {
            RustcryptoClientConfigBuilder::new()
                .with_roots(roots.clone())
                .build()
                .expect("build")
        });
    });

    // Also measure construction with an empty root store (minimal footprint).
    c.bench_function("client_config/construct_empty_roots", |b| {
        b.iter(|| {
            RustcryptoClientConfigBuilder::new()
                .with_roots(RootCertStore::empty())
                .build()
                .expect("build empty roots")
        });
    });
}

fn bench_server_config_memory(c: &mut Criterion) {
    // Generate a self-signed cert once; clone cert/key per iteration.
    let ck = generate_self_signed_ed25519(&["localhost"]).expect("cert gen");
    let cert_der = rustls_pki_types::CertificateDer::from(ck.cert_der.clone());
    let key_der_bytes = ck.pkcs8_der.clone();

    // Clone cert/key bytes before the snapshot so the counter only captures
    // the ServerConfig construction cost.
    let cert_for_sample = cert_der.clone();
    let key_bytes_for_sample = key_der_bytes.clone();
    let before = alloc_snapshot();
    let sample_cfg = RustcryptoServerConfigBuilder::new()
        .with_cert_and_key(
            vec![cert_for_sample],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_bytes_for_sample)),
        )
        .build()
        .expect("server config build");
    let after = alloc_snapshot();

    let heap_bytes = after - before;
    let stack_bytes = std::mem::size_of_val(&sample_cfg);
    println!("\nServerConfig  stack={stack_bytes} B  heap_alloc_during_build~={heap_bytes} B");
    std::hint::black_box(sample_cfg);

    // Criterion timing benchmark.
    c.bench_function("server_config/construct", |b| {
        let cert = cert_der.clone();
        let key_bytes = key_der_bytes.clone();
        b.iter(move || {
            RustcryptoServerConfigBuilder::new()
                .with_cert_and_key(
                    vec![cert.clone()],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_bytes.clone())),
                )
                .build()
                .expect("server config build")
        });
    });
}

criterion_group!(
    memory_benches,
    bench_client_config_memory,
    bench_server_config_memory,
);
criterion_main!(memory_benches);
