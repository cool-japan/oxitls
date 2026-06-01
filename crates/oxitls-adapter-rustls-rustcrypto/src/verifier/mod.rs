//! Custom server certificate verifier implementations.
//!
//! - `CertPinVerifier` — SHA-256 leaf fingerprint pinning.
//! - `CrlAwareServerVerifier` — CRL-backed revocation checking via
//!   `WebPkiServerVerifier`.
//! - `CustomServerVerifier` — inner verifier + caller-supplied predicate.
//! - `OcspClientVerifier` — client-side OCSP staple verification with
//!   cryptographic signature verification (RFC 6960).
//! - `SctVerifier` — Certificate Transparency SCT verification with
//!   cryptographic signature verification (RFC 6962).
//! - `RawPublicKeyServerVerifier` — RFC 7250 raw-public-key pinning (client
//!   side).
//! - `RawPublicKeyClientVerifier` — RFC 7250 raw-public-key pinning (server
//!   side, mTLS).
//! - `ct_logs` — embedded CT log public keys.
//! - `ocsp_crypto` — OCSP cryptographic verification helpers.

pub mod crl;
pub mod ct_logs;
pub mod custom;
pub mod ocsp_client;
pub mod ocsp_crypto;
pub mod pin;
pub mod raw_public_key;
pub mod sct;

pub use crl::CrlAwareServerVerifier;
pub use custom::CustomServerVerifier;
pub use ocsp_client::{OcspClientPolicy, OcspClientVerifier};
pub use pin::CertPinVerifier;
pub use raw_public_key::{
    client_raw_public_key_resolver, server_raw_public_key_resolver, RawPublicKeyClientVerifier,
    RawPublicKeyServerVerifier,
};
pub use sct::{CtKeyAlg, CtLog, CtLogList, SctPolicy, SctVerifier};
