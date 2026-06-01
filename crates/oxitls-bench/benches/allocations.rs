//! Heap-allocation profiling benchmarks.
//!
//! Tracks the number of bytes allocated on the heap during construction of the
//! primary builder and ticketer types.  The benchmark prints a "Heap allocated:
//! N bytes" line per group, which is useful for catching regressions in
//! allocator traffic.
//!
//! Gated on `--features dhat-heap` so that the `#[global_allocator]`
//! replacement only activates when opted in.  When the feature is absent the
//! crate compiles to a stub `main` so that `cargo bench --no-run` (without
//! the feature) still produces a valid executable.
//!
//! Run with:
//!   cargo bench -p oxitls-bench --bench allocations --features dhat-heap -- --nocapture

// ── Feature-gated allocator + benchmarks ─────────────────────────────────────

#[cfg(feature = "dhat-heap")]
mod dhat_benches {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use criterion::{criterion_group, BatchSize, Criterion};
    use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    use oxitls::anti_replay::AntiReplayTicketer;
    use oxitls::tls13::{ClientBuilder, ServerBuilder};
    use oxitls::OxiTicketer;
    use oxitls_rcgen::generate_self_signed_ed25519;

    // ── Counting allocator ────────────────────────────────────────────────────

    /// Global heap-byte counter.  Monotonically increasing — subtract snapshots
    /// to measure allocation work during a section.
    static ALLOC_BYTES: AtomicUsize = AtomicUsize::new(0);

    struct CountingAlloc;

    unsafe impl GlobalAlloc for CountingAlloc {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            ALLOC_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
            // SAFETY: delegating to System allocator with the same layout.
            unsafe { System.alloc(layout) }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            // SAFETY: delegating to System allocator with original ptr/layout.
            unsafe { System.dealloc(ptr, layout) }
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            ALLOC_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
            // SAFETY: delegating to System allocator with the same layout.
            unsafe { System.alloc_zeroed(layout) }
        }

        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            if new_size > layout.size() {
                ALLOC_BYTES.fetch_add(new_size - layout.size(), Ordering::Relaxed);
            }
            // SAFETY: delegating to System allocator with original ptr/layout/new_size.
            unsafe { System.realloc(ptr, layout, new_size) }
        }
    }

    #[global_allocator]
    static GLOBAL: CountingAlloc = CountingAlloc;

    // ── Allocation counter snapshot ───────────────────────────────────────────

    fn alloc_snapshot() -> usize {
        ALLOC_BYTES.load(Ordering::Relaxed)
    }

    // ── Shared test fixture ───────────────────────────────────────────────────

    fn cert_fixture() -> (Vec<u8>, Vec<u8>) {
        let ck = generate_self_signed_ed25519(&["localhost"]).expect("bench: cert gen failed");
        (ck.cert_der, ck.pkcs8_der)
    }

    // ── Benchmarks ────────────────────────────────────────────────────────────

    pub fn bench_client_builder_alloc(c: &mut Criterion) {
        let before = alloc_snapshot();
        let sample = ClientBuilder::new()
            .with_webpki_roots()
            .build()
            .expect("client config build");
        let after = alloc_snapshot();
        let delta = after - before;
        println!("\nClientBuilder::build() with webpki roots — heap allocated: {delta} bytes");
        std::hint::black_box(sample);

        c.bench_function("alloc/client_builder_webpki_roots", |b| {
            b.iter_batched(
                || (),
                |()| {
                    let before_iter = alloc_snapshot();
                    let cfg = ClientBuilder::new()
                        .with_webpki_roots()
                        .build()
                        .expect("client config build");
                    let delta_iter = alloc_snapshot() - before_iter;
                    println!("Heap allocated: {delta_iter} bytes");
                    std::hint::black_box(cfg)
                },
                BatchSize::SmallInput,
            );
        });
    }

    pub fn bench_server_builder_alloc(c: &mut Criterion) {
        let (cert_der, key_der) = cert_fixture();

        let cert_sample = CertificateDer::from(cert_der.clone());
        let key_sample = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der.clone()));
        let before = alloc_snapshot();
        let sample = ServerBuilder::new()
            .with_der_cert_and_key(vec![cert_sample], key_sample)
            .build()
            .expect("server config build");
        let after = alloc_snapshot();
        let delta = after - before;
        println!("\nServerBuilder::build() with rcgen cert — heap allocated: {delta} bytes");
        std::hint::black_box(sample);

        c.bench_function("alloc/server_builder_rcgen_cert", |b| {
            b.iter_batched(
                || {
                    (
                        CertificateDer::from(cert_der.clone()),
                        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der.clone())),
                    )
                },
                |(cert, key)| {
                    let before_iter = alloc_snapshot();
                    let cfg = ServerBuilder::new()
                        .with_der_cert_and_key(vec![cert], key)
                        .build()
                        .expect("server config build");
                    let delta_iter = alloc_snapshot() - before_iter;
                    println!("Heap allocated: {delta_iter} bytes");
                    std::hint::black_box(cfg)
                },
                BatchSize::SmallInput,
            );
        });
    }

    pub fn bench_oxi_ticketer_alloc(c: &mut Criterion) {
        let before = alloc_snapshot();
        let sample = OxiTicketer::new().expect("OxiTicketer::new");
        let after = alloc_snapshot();
        let delta = after - before;
        println!("\nOxiTicketer::new() — heap allocated: {delta} bytes");
        std::hint::black_box(sample);

        c.bench_function("alloc/oxi_ticketer_new", |b| {
            b.iter_batched(
                || (),
                |()| {
                    let before_iter = alloc_snapshot();
                    let t = OxiTicketer::new().expect("OxiTicketer::new");
                    let delta_iter = alloc_snapshot() - before_iter;
                    println!("Heap allocated: {delta_iter} bytes");
                    std::hint::black_box(t)
                },
                BatchSize::SmallInput,
            );
        });
    }

    pub fn bench_anti_replay_ticketer_alloc(c: &mut Criterion) {
        let before = alloc_snapshot();
        let sample =
            AntiReplayTicketer::new(OxiTicketer::new().expect("OxiTicketer::new for sample"));
        let after = alloc_snapshot();
        let delta = after - before;
        println!("\nAntiReplayTicketer::new(OxiTicketer) — heap allocated: {delta} bytes");
        std::hint::black_box(sample);

        c.bench_function("alloc/anti_replay_ticketer_new", |b| {
            b.iter_batched(
                || OxiTicketer::new().expect("OxiTicketer::new for setup"),
                |inner| {
                    let before_iter = alloc_snapshot();
                    let t = AntiReplayTicketer::new(inner);
                    let delta_iter = alloc_snapshot() - before_iter;
                    println!("Heap allocated: {delta_iter} bytes");
                    std::hint::black_box(t)
                },
                BatchSize::SmallInput,
            );
        });
    }

    criterion_group!(
        alloc_benches,
        bench_client_builder_alloc,
        bench_server_builder_alloc,
        bench_oxi_ticketer_alloc,
        bench_anti_replay_ticketer_alloc,
    );
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[cfg(feature = "dhat-heap")]
criterion::criterion_main!(dhat_benches::alloc_benches);

#[cfg(not(feature = "dhat-heap"))]
fn main() {}
