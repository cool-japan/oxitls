//! Criterion benchmark: `CertPinVerifier` pin-list lookup latency.
//!
//! Measures how long it takes to perform the SHA-256 fingerprint lookup step
//! inside `CertPinVerifier` as the number of pinned fingerprints grows.
//! The benchmark exercises the hot path: hashing a DER blob and scanning
//! the pinned set (1, 10, and 100 entries).
//!
//! Note: we benchmark the hashing + scan directly rather than going through
//! `verify_server_cert` (which requires a full PKI chain), so we can isolate
//! the pin-lookup cost independently of the base verifier.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use sha2::{Digest, Sha256};

/// A dummy DER blob that represents a server leaf certificate.
const FAKE_CERT_DER: &[u8] = b"fake-certificate-der-bytes-for-benchmarking-only";

/// Generate `n` random-looking pin fingerprints.
/// The last entry is always the fingerprint of `FAKE_CERT_DER` so that
/// "worst-case" (miss) and "found-last" scenarios can be contrasted.
fn make_pins(n: usize, include_match: bool) -> Vec<[u8; 32]> {
    let mut pins: Vec<[u8; 32]> = (0..n.saturating_sub(1))
        .map(|i| {
            let mut fp = [0u8; 32];
            // Fill with a deterministic but distinct value.
            for (j, b) in fp.iter_mut().enumerate() {
                *b = ((i * 31 + j * 7) & 0xFF) as u8;
            }
            fp
        })
        .collect();

    if include_match || n > 0 {
        let digest = Sha256::digest(FAKE_CERT_DER);
        let mut fp = [0u8; 32];
        fp.copy_from_slice(&digest);
        pins.push(fp);
    }

    pins
}

/// Inline the core of CertPinVerifier: hash the DER then scan the list.
fn pin_lookup(cert_der: &[u8], pins: &[[u8; 32]]) -> bool {
    let digest = Sha256::digest(cert_der);
    let mut fp = [0u8; 32];
    fp.copy_from_slice(&digest);
    pins.contains(&fp)
}

fn bench_cert_pin_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("cert_pin_lookup");

    for n_pins in [1usize, 10, 100] {
        // "hit" — the cert's fingerprint IS in the list (at the end).
        let pins_hit = make_pins(n_pins, true);
        group.bench_with_input(BenchmarkId::new("hit", n_pins), &pins_hit, |b, pins| {
            b.iter(|| {
                let found = pin_lookup(FAKE_CERT_DER, pins);
                assert!(found);
            });
        });

        // "miss" — the cert's fingerprint is NOT in the list.
        let mut pins_miss = make_pins(n_pins, false);
        // Replace last entry with something that won't match.
        if let Some(last) = pins_miss.last_mut() {
            last[0] ^= 0xFF;
        }
        group.bench_with_input(BenchmarkId::new("miss", n_pins), &pins_miss, |b, pins| {
            b.iter(|| {
                let found = pin_lookup(FAKE_CERT_DER, pins);
                assert!(!found);
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_cert_pin_lookup);
criterion_main!(benches);
