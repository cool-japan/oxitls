#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! `oxitls-rcgen` — Pure-Rust X.509 certificate generation backed by OxiCrypto
//! signing primitives, no ring/aws-lc-rs in the dependency closure.
//!
//! # Quick start
//!
//! ```no_run
//! use oxitls_rcgen::{generate_self_signed_ed25519, generate_self_signed_p256};
//!
//! # fn main() -> Result<(), oxitls_core::TlsError> {
//! // Ed25519 self-signed cert for localhost
//! let ck = generate_self_signed_ed25519(&["localhost"])?;
//! // ck.cert_der — DER bytes for rustls
//! // ck.pkcs8_der — PKCS#8 DER private key for rustls
//!
//! // P-256 self-signed cert
//! let ck2 = generate_self_signed_p256(&["example.com"])?;
//! # Ok(())
//! # }
//! ```
//!
//! # CA Certificate Generation
//!
//! ```no_run
//! use oxitls_rcgen::{generate_ca, generate_intermediate_ca, generate_ca_signed_leaf, SigningAlgorithm};
//!
//! # fn main() -> Result<(), oxitls_core::TlsError> {
//! // Generate a root CA
//! let root_ca = generate_ca("My Root CA", SigningAlgorithm::Ed25519)?;
//!
//! // Generate an intermediate CA signed by the root
//! let intermediate = generate_intermediate_ca("My Intermediate CA", SigningAlgorithm::Ed25519, &root_ca)?;
//!
//! // Generate a leaf cert signed by the intermediate
//! let leaf = generate_ca_signed_leaf(&["example.com"], SigningAlgorithm::Ed25519, &intermediate)?;
//! # Ok(())
//! # }
//! ```

pub mod cert;
pub mod csr;
pub mod keypair;

pub use cert::{
    generate_ca, generate_ca_signed_client_cert, generate_ca_signed_leaf, generate_intermediate_ca,
    generate_self_signed, generate_self_signed_ed25519, generate_self_signed_p256,
    generate_self_signed_p384, generate_self_signed_rsa2048, generate_self_signed_rsa4096,
    self_signed_from_rsa2048_key, self_signed_from_rsa4096_key, CaCertifiedKey, CertChainBuilder,
    CertificateParamsBuilder, CertifiedKey, SigningAlgorithm,
};
pub use csr::{generate_csr, sign_csr, CsrBytes, SignedCertificate};
pub use keypair::{OxiEcdsaP256Key, OxiEcdsaP384Key, OxiEd25519Key, OxiRsa2048Key, OxiRsa4096Key};
