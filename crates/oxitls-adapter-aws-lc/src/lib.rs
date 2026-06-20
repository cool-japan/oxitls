#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! `oxitls-adapter-aws-lc` — aws-lc-rs backed rustls `CryptoProvider`.
//!
//! # Feature flags
//! | Feature   | Effect |
//! |-----------|--------|
//! | `aws-lc`  | Enables the aws-lc-rs provider via `rustls/aws_lc_rs`. Brings in C/FFI code. |
//!
//! The **default** set of features is intentionally empty so that taking a
//! dependency on this crate (without opting in) does **not** pull any C code
//! into the build closure.
//!
//! # Usage
//! ```no_run
//! # #[cfg(feature = "aws-lc")]
//! # fn example() -> Result<(), String> {
//! use oxitls_adapter_aws_lc::aws_lc_provider;
//! use rustls::ServerConfig;
//!
//! let provider = aws_lc_provider();
//! let _builder = ServerConfig::builder_with_provider(provider)
//!     .with_safe_default_protocol_versions()
//!     .map_err(|e| format!("protocol version error: {e}"))?;
//! # Ok(())
//! # }
//! ```

pub use oxitls_core::TlsError;

mod client;
pub mod error;
mod fips;
mod provider;
mod server;
mod ticketer;

#[cfg(feature = "aws-lc")]
pub mod provider_type;

#[cfg(feature = "aws-lc")]
pub use provider_type::AwsLcTlsProvider;

#[cfg(feature = "aws-lc")]
pub use provider::aws_lc_provider;

#[cfg(feature = "aws-lc")]
pub use client::{aws_lc_client_config, aws_lc_mtls_client_config};

#[cfg(feature = "aws-lc")]
pub use server::aws_lc_server_config;

#[cfg(feature = "aws-lc")]
pub use fips::is_fips_mode;

#[cfg(feature = "aws-lc")]
pub use ticketer::AwsLcTicketRotator;

/// Returns a TLS 1.2-only provider and a slice containing only the TLS 1.2
/// protocol version.
///
/// Useful for tests or deployments that need to verify TLS 1.2-specific behaviour.
#[cfg(feature = "aws-lc")]
pub fn aws_lc_provider_tls12_only() -> (
    std::sync::Arc<rustls::crypto::CryptoProvider>,
    &'static [&'static rustls::SupportedProtocolVersion],
) {
    static TLS12_ONLY: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS12];
    (provider::aws_lc_provider(), TLS12_ONLY)
}

/// Returns a provider restricted to the given cipher suites.
#[cfg(feature = "aws-lc")]
pub fn aws_lc_provider_with_cipher_suites(
    cipher_suites: &[rustls::SupportedCipherSuite],
) -> std::sync::Arc<rustls::crypto::CryptoProvider> {
    let mut p = rustls::crypto::aws_lc_rs::default_provider();
    p.cipher_suites = cipher_suites.to_vec();
    std::sync::Arc::new(p)
}

/// Returns the display names of cipher suites supported by the aws-lc-rs provider.
///
/// The names are derived from the `Debug` representation of each
/// [`rustls::SupportedCipherSuite`] entry in the default provider.
#[cfg(feature = "aws-lc")]
pub fn supported_cipher_suites() -> Vec<String> {
    aws_lc_provider()
        .cipher_suites
        .iter()
        .map(|cs| format!("{cs:?}"))
        .collect()
}

/// Returns the display names of key-exchange groups supported by the aws-lc-rs provider.
///
/// The names are derived from the `Debug` representation of the
/// [`rustls::NamedGroup`] for each entry in the default provider.
#[cfg(feature = "aws-lc")]
pub fn supported_kx_groups() -> Vec<String> {
    aws_lc_provider()
        .kx_groups
        .iter()
        .map(|g| format!("{:?}", g.name()))
        .collect()
}
