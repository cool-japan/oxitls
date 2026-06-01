//! Fuzz-style regression test: malformed certificate DER must never panic.
//!
//! Per the "malformed inputs → Err, never panic" invariant established by
//! rustls's own parser (webpki/x509-parser), this test hardens the OxiTLS
//! adapter surface against garbage DER inputs.
//!
//! ## Entry-point selection rationale
//!
//! The client builder accepts a `RootCertStore`, not raw DER bytes directly.
//! `RootCertStore::add(CertificateDer)` is the eager-parse surface: webpki
//! parses the trust anchor immediately and returns `Err` on malformed input —
//! which maps to the `client_config()` call chain.
//!
//! For the server builder, `with_cert_and_key` stores cert bytes opaquely
//! (parsing deferred to handshake), so the private key slot is the reliable
//! eager-parse target: `build()` calls `load_private_key` which parses DER
//! immediately and returns `Err` on garbage.

use rustls::RootCertStore;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// Corpus of malformed DER byte sequences.
const MALFORMED_INPUTS: &[&[u8]] = &[
    b"",                       // empty
    b"\x00",                   // single zero byte
    b"\x30",                   // truncated SEQUENCE tag
    b"\x30\x82\xff\xff",       // SEQUENCE with oversize length
    b"\x30\x01\x00",           // SEQUENCE with wrong interior
    b"THIS IS NOT DER AT ALL", // ASCII garbage
    &[0xff; 128],              // all-0xff bytes
    b"\x30\x82\x00\x01\x99",   // valid outer SEQUENCE, garbage inside
    b"\x02\x01\x00",           // INTEGER primitive, not a cert
    b"\x30\x00",               // empty SEQUENCE (no required fields)
];

/// Helper to extract a human-readable description from a panic payload.
fn panic_msg(payload: &dyn std::any::Any) -> &str {
    if let Some(s) = payload.downcast_ref::<&str>() {
        s
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.as_str()
    } else {
        "<non-string panic>"
    }
}

/// `RootCertStore::add(malformed_der)` must return `Err`, never panic.
///
/// This exercises the trust-anchor DER parse path that feeds into
/// `client_config()` and `RustcryptoClientConfigBuilder::with_roots()`.
#[test]
fn malformed_root_cert_der_never_panics_and_returns_err() {
    for (i, &bad_der) in MALFORMED_INPUTS.iter().enumerate() {
        let result = std::panic::catch_unwind(|| {
            let mut store = RootCertStore::empty();
            store.add(CertificateDer::from(bad_der.to_vec()))
        });

        match result {
            Ok(Ok(_)) => {
                // Unexpected acceptance — flag as a test failure so we can
                // investigate whether rustls changed its parsing behaviour.
                panic!(
                    "Malformed DER input #{i} ({bad_der:?}) was accepted as a \
                     valid trust anchor — expected Err"
                );
            }
            Ok(Err(_)) => {
                // Correct: parser rejected the garbage and returned Err.
            }
            Err(ref e) => {
                panic!(
                    "Malformed DER input #{i} ({bad_der:?}) caused a panic: {}",
                    panic_msg(e.as_ref())
                );
            }
        }
    }
}

/// Feeding malformed DER as a private key into the server builder must return
/// `Err` from `build()`, never panic.
///
/// `PrivatePkcs8KeyDer::from(bytes)` is a plain newtype (no validation) so the
/// garbage bytes reach the internal key parser; `build()` calls
/// `load_private_key` which parses eagerly and must return `Err` on garbage.
#[test]
fn malformed_private_key_der_never_panics_and_returns_err() {
    use oxitls_adapter_rustls_rustcrypto::RustcryptoServerConfigBuilder;

    // Generate the certificate once; only the key path is under test here.
    let ck = oxitls_rcgen::generate_self_signed_ed25519(&["example.com"]).expect("cert gen");
    let cert = CertificateDer::from(ck.cert_der.clone());

    for (i, &bad_der) in MALFORMED_INPUTS.iter().enumerate() {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let bad_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(bad_der.to_vec()));
            RustcryptoServerConfigBuilder::new()
                .with_cert_and_key(vec![cert.clone()], bad_key)
                .build()
        }));

        match result {
            Ok(Ok(_)) => {
                panic!(
                    "Malformed private-key DER input #{i} ({bad_der:?}) was \
                     accepted — expected Err"
                );
            }
            Ok(Err(_)) => {
                // Correct: build() rejected the garbage key.
            }
            Err(ref e) => {
                panic!(
                    "Malformed private-key DER input #{i} ({bad_der:?}) caused a panic: {}",
                    panic_msg(e.as_ref())
                );
            }
        }
    }
}

/// Passing malformed bytes through `client_config()` free function with an
/// initially-malformed root store add must propagate `Err` consistently.
///
/// This exercises the free-function wrapper rather than the builder.
#[test]
fn client_config_with_garbage_root_cert_der_never_panics() {
    use oxitls_adapter_rustls_rustcrypto::client_config;

    for (i, &bad_der) in MALFORMED_INPUTS.iter().enumerate() {
        let result = std::panic::catch_unwind(|| {
            let mut store = RootCertStore::empty();
            // Attempt to add the garbage cert; failure here is expected.
            let add_result = store.add(CertificateDer::from(bad_der.to_vec()));
            // If add fails (expected), the store remains empty.  client_config
            // with an empty root store will fail at the verifier-build step.
            // Either way, no panic is the invariant.
            let _ = add_result;
            client_config(store)
        });

        match result {
            Ok(_) => {
                // Ok(Ok) or Ok(Err) both acceptable — no panic is the invariant.
            }
            Err(ref e) => {
                panic!(
                    "client_config with garbage root DER #{i} ({bad_der:?}) panicked: {}",
                    panic_msg(e.as_ref())
                );
            }
        }
    }
}
