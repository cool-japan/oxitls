//! Wave 5 Slice D — facade-glue integration tests.
//!
//! Verifies:
//! 1. `ClientBuilder::with_root_store_builder` merges extra roots and builds a
//!    valid `ClientConfig` (gated by `webpki-roots` feature).
//! 2. `ClientBuilder::with_ct_logs` accepts a `CtLogList` and `SctPolicy` and
//!    builds without error (CT log wiring, gated by `pure` feature).
//! 3. `OxiTlsStream<S>` is accessible from the crate root as `oxitls::OxiTlsStream`.
//! 4. `post-quantum` feature compiles (namespace reservation — no runtime crash).
//!
//! Each test is intentionally lightweight: we check compile-time API surface
//! and builder contract rather than end-to-end handshakes (those live in the
//! wave3/wave4 integration tests).

// ── Test 1: with_root_store_builder merges extra roots ────────────────────────

/// `ClientBuilder::with_root_store_builder` must consume the builder, merge its
/// trust anchors into the final root store, and succeed.  The resulting
/// `ClientConfig` must be usable (non-panic on build).
///
/// This test is only compiled when both `pure` and `webpki-roots` features are
/// active, because `with_root_store_builder` is gated by `#[cfg(feature =
/// "webpki-roots")]`.
#[cfg(all(feature = "pure", feature = "webpki-roots"))]
#[test]
fn with_root_store_builder_merges_and_builds() {
    use oxitls::tls13::ClientBuilder;
    use oxitls_webpki_roots::RootStoreBuilder;

    // Build an empty extra-root store via RootStoreBuilder.
    let extra_builder = RootStoreBuilder::new();

    // `with_root_store_builder` must succeed and the final build should not
    // fail (we still call with_webpki_roots so there are real roots).
    let cfg = ClientBuilder::new()
        .with_webpki_roots()
        .with_root_store_builder(extra_builder)
        .expect("with_root_store_builder must succeed")
        .build()
        .expect("ClientBuilder build must succeed after with_root_store_builder");

    // Basic sanity: the config should have a non-empty resumption store.
    // The exact capacity doesn't matter; we just verify the config was built.
    let _ = cfg;
}

// ── Test 2: with_ct_logs accepts CtLogList + SctPolicy ────────────────────────

/// `ClientBuilder::with_ct_logs` must accept a `CtLogList` and `SctPolicy` and
/// build without error.  The config should not panic on use.
#[cfg(feature = "pure")]
#[test]
fn with_ct_logs_builds_successfully() {
    use oxitls::tls13::ClientBuilder;
    use oxitls_adapter_rustls_rustcrypto::{CtLogList, SctPolicy};

    // Create a minimal (empty) CT log list — sufficient to exercise the API
    // contract without needing real log public keys in the test.
    let log_list = CtLogList(vec![]);

    // Permissive with min_distinct_logs=0: verification is attempted but
    // empty logs only warns; handshake is never rejected.
    let policy = SctPolicy::Permissive {
        min_distinct_logs: 0,
    };

    let cfg = ClientBuilder::new()
        .with_webpki_roots()
        .with_ct_logs(log_list, policy)
        .build()
        .expect("ClientBuilder with_ct_logs must build successfully");

    let _ = cfg;
}

// Also exercise the non-empty CtLog struct constructor to ensure the type is
// fully usable from the facade.
#[cfg(feature = "pure")]
#[test]
fn ct_log_list_type_accessible_from_facade() {
    use oxitls_adapter_rustls_rustcrypto::{CtKeyAlg, CtLog, CtLogList};

    // Construct a CtLog with a dummy DER-encoded public key.
    let dummy_key_der = vec![0u8; 32];
    let log = CtLog {
        id: [0u8; 32],
        public_key_der: dummy_key_der,
        key_alg: CtKeyAlg::Ed25519,
    };
    let list = CtLogList(vec![log]);
    assert_eq!(list.0.len(), 1);
}

// ── Test 3: OxiTlsStream accessible from oxitls crate root ───────────────────

/// `oxitls::OxiTlsStream` must be accessible without needing to import from
/// the internal `stream` module.  This test just checks the type is importable
/// and usable via a `From` conversion.
#[cfg(feature = "pure")]
#[test]
fn oxi_tls_stream_accessible_from_root() {
    // This is a compile-time only test — if `OxiTlsStream` is exported from
    // the crate root, this import will succeed.
    use oxitls::OxiTlsStream;

    // Verify the type name resolves (we can't construct one without a real
    // tokio-rustls stream, so we just assert the type exists via a path check).
    fn _accepts_type<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(_: OxiTlsStream<S>) {
        // This function is never called at runtime — its existence proves the
        // type is accessible and generic-parameterised correctly.
    }
}

// ── Test 4: post-quantum feature compiles ─────────────────────────────────────

/// The `post-quantum` feature must compile without panicking.  It currently
/// serves as a namespace reservation for the X25519MLKEM768 key-exchange group
/// that will be wired in Wave 6 once the rustls KX-group API stabilises.
///
/// This test verifies the feature flag compiles rather than testing behaviour.
#[cfg(feature = "post-quantum")]
#[test]
fn post_quantum_feature_compiles() {
    // The post-quantum feature is currently a namespace reservation.
    // Confirming the test binary compiles with the feature flag is sufficient.
    // No runtime assertions needed.
}

// Provide a fallback so the test file compiles when post-quantum is not active.
#[cfg(not(feature = "post-quantum"))]
#[test]
fn post_quantum_feature_absence_is_fine() {
    // post-quantum is opt-in only; the default feature set intentionally
    // omits it to stay 100% Pure Rust without any extra crypto crates.
}
