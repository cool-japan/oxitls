// SPDX-License-Identifier: Apache-2.0
// Copyright COOLJAPAN OU (Team Kitasan)
#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! `oxitls-adapter-pkcs11` — PKCS#11 HSM/TPM backed rustls `SigningKey`.
//!
//! # Feature flags
//!
//! | Feature   | Effect |
//! |-----------|--------|
//! | `pkcs11`  | Enables the PKCS#11 signing adapter via the `cryptoki` crate. |
//!
//! The **default** set of features is intentionally empty so that taking a
//! dependency on this crate (without opting in) does **not** pull any
//! non-Pure-Rust code into the build closure.
//!
//! # Quick-start: single certificate
//!
//! ```no_run
//! # #[cfg(feature = "pkcs11")]
//! # {
//! use std::path::PathBuf;
//! use std::sync::Arc;
//! use secrecy::SecretString;
//! use oxitls_adapter_pkcs11::Pkcs11TlsProvider;
//!
//! let provider = Pkcs11TlsProvider::new(
//!     PathBuf::from("/usr/lib/softhsm/libsofthsm2.so"),
//!     0,                               // slot index
//!     SecretString::from("1234"),      // user PIN
//! ).expect("init provider");
//!
//! let crypto = Arc::new(rustls_rustcrypto::provider());
//! let _cfg = provider
//!     .server_config("my-cert", "my-key", crypto)
//!     .expect("build ServerConfig");
//! # }
//! ```
//!
//! # SoftHSM2 Setup
//!
//! To run the `#[ignore]`-gated integration tests locally:
//!
//! ```text
//! # 1. Install SoftHSM2
//! brew install softhsm       # macOS
//! apt install softhsm2       # Debian/Ubuntu
//!
//! # 2. Initialise a new token
//! softhsm2-util --init-token --slot 0 --label oxitls-test \
//!               --so-pin 5678 --pin 1234
//!
//! # 3. Generate an EC P-256 key pair and import a self-signed certificate
//! pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --slot 0 \
//!             --login --pin 1234 --keypairgen --key-type EC:prime256v1 \
//!             --label test-ecdsa
//!
//! # 4. Export env vars and run the ignored tests
//! export SOFTHSM2_MODULE=/usr/lib/softhsm/libsofthsm2.so
//! export SOFTHSM2_SLOT=0
//! export SOFTHSM2_PIN=1234
//! export SOFTHSM2_KEY_LABEL=test-ecdsa
//! export SOFTHSM2_CERT_LABEL=test-ecdsa
//! cargo test -p oxitls-adapter-pkcs11 --features pkcs11 -- --include-ignored
//! ```

pub use oxitls_core::TlsError;

/// Error types for the PKCS#11 adapter.
pub mod error;
pub use error::{Pkcs11Error, PkcsSignError};

#[cfg(feature = "pkcs11")]
mod pool;
#[cfg(feature = "pkcs11")]
mod provider;
#[cfg(feature = "pkcs11")]
mod resolver;
#[cfg(feature = "pkcs11")]
mod session;
#[cfg(feature = "pkcs11")]
mod signer;

#[cfg(feature = "pkcs11")]
pub use pool::{Pkcs11SessionPool, PooledSession};
#[cfg(feature = "pkcs11")]
pub use provider::Pkcs11TlsProvider;
#[cfg(feature = "pkcs11")]
pub use resolver::Pkcs11ServerCertResolver;
#[cfg(feature = "pkcs11")]
pub use signer::Pkcs11SigningKey;

// ---------------------------------------------------------------------------
// Public key-info types (non-feature-gated — used for documentation and
// pattern-matching even without a live HSM).
// ---------------------------------------------------------------------------

/// Metadata returned by `Pkcs11TlsProvider::list_keys`.
#[derive(Debug, Clone)]
pub struct Pkcs11KeyInfo {
    /// The PKCS#11 `CKA_LABEL` attribute of the private key object.
    pub label: String,
    /// The algorithm family inferred from the `CKA_KEY_TYPE` attribute.
    pub key_type: Pkcs11KeyType,
    /// The raw `CKA_ID` bytes of the key object.
    pub id: Vec<u8>,
    /// Whether the token reported `CKA_SIGN = CK_TRUE` for this key.
    pub signing_capable: bool,
}

/// Algorithm family of a PKCS#11 private key.
#[derive(Debug, Clone, PartialEq)]
pub enum Pkcs11KeyType {
    /// RSA key (`CKK_RSA`).
    Rsa,
    /// ECDSA P-256 key (`CKK_EC` with P-256 curve OID).
    ///
    /// Currently all `CKK_EC` keys are reported as `EcdsaP256` since
    /// distinguishing P-256 from P-384 requires an additional
    /// `CKA_EC_PARAMS` attribute fetch.
    EcdsaP256,
    /// ECDSA P-384 key.
    EcdsaP384,
    /// Ed25519 key (`CKK_EC_EDWARDS`).
    Ed25519,
    /// Unknown key type with its raw `CKK_*` value.
    Other(u64),
}
