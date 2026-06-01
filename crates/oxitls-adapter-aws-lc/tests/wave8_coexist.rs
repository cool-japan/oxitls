//! Coexistence documentation test: oxitls-adapter-aws-lc + oxicrypto-adapter-aws-lc.
//!
//! ## Status
//!
//! **Empirically verified (2026-05-29)**: both crates share the same `aws-lc-rs 1.17.0`
//! dependency and link cleanly in a single binary with zero symbol conflicts.
//!
//! ## Deferred permanent integration
//!
//! The `oxicrypto-adapter-aws-lc` path dependency cannot be added permanently to this
//! crate's `[dev-dependencies]` because:
//!
//! - `oxicrypto` is a separate, unpublished workspace (`v0.0.0`, no registry release).
//! - A hardcoded `path = "../../../oxicrypto/..."` dep breaks any checkout that does not
//!   have the sibling repo present (CI, fresh clones).
//! - Cargo does not support optional `[dev-dependencies]`, so the dep would be resolved
//!   unconditionally, coupling oxitls's CI/clippy to oxicrypto's local presence.
//!
//! ## Activation instructions (when oxicrypto publishes to a registry)
//!
//! 1. Add to `[dev-dependencies]` in Cargo.toml:
//!    ```toml
//!    oxicrypto-adapter-aws-lc = { version = "X.Y.Z", features = ["aws-lc"] }
//!    oxicrypto-core            = { version = "X.Y.Z" }
//!    ```
//! 2. Remove the `oxicrypto-coexist` feature placeholder from `[features]`.
//! 3. Uncomment the `coexist_real_symbols` test below and remove `coexist_placeholder`.
//!
//! ## Verification transcript
//!
//! ```text
//! $ cargo test -p oxitls-adapter-aws-lc --features aws-lc --test wave8_coexist
//! # With temporary path deps:
//! test both_aws_lc_crates_link_cleanly ... ok   (1 passed)
//! ```
//!
//! The `coexist_placeholder` test below keeps this file from being an empty test binary.

// When oxicrypto publishes, replace the placeholder with:
//
// #[cfg(feature = "aws-lc")]
// use oxicrypto_adapter_aws_lc::aead::AwsLcAead as OxiAead;
// #[cfg(feature = "aws-lc")]
// use oxicrypto_core::Aead as OxiAeadTrait;
//
// /// Verify both aws-lc-rs adapters (oxitls + oxicrypto) link in the same binary.
// ///
// /// Both crates declare `aws-lc-rs = "1.17.0"` — Cargo deduplicates to a single
// /// copy, so there are no duplicate symbols and both initialization paths succeed.
// #[cfg(feature = "aws-lc")]
// #[test]
// fn coexist_real_symbols() {
//     // oxitls side: initialize the rustls CryptoProvider
//     let provider = oxitls_adapter_aws_lc::aws_lc_provider();
//     assert!(!provider.cipher_suites.is_empty(), "oxitls: should have cipher suites");
//
//     // oxicrypto side: use the AEAD adapter
//     let cipher = OxiAead::aes256_gcm();
//     let key = [0x42u8; 32];
//     let nonce = [0x11u8; 12];
//     let pt = b"coexist test";
//     let mut ct = vec![0u8; pt.len() + OxiAeadTrait::tag_len(&cipher)];
//     let written = OxiAeadTrait::seal(&cipher, &key, &nonce, b"", pt, &mut ct)
//         .expect("seal should succeed");
//     assert_eq!(written, pt.len() + 16);
// }

/// Placeholder: this test passes immediately, keeping the file non-empty.
///
/// Replace with `coexist_real_symbols` once oxicrypto publishes to a registry.
#[test]
fn coexist_placeholder() {
    // Coexistence empirically verified on 2026-05-29.
    // Permanent dep deferred until oxicrypto v0.1.0+ is published to crates.io.
}
