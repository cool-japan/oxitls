//! aws-lc-rs backed rustls `CryptoProvider`.
//!
//! The entire module is gated behind `#[cfg(feature = "aws-lc")]` so that the
//! default closure of this crate (and of the `oxitls` facade that re-exports
//! it) stays 100% Pure Rust.

#[cfg(feature = "aws-lc")]
use std::sync::Arc;

/// Returns a `rustls::crypto::CryptoProvider` backed by aws-lc-rs.
///
/// Does **not** call `CryptoProvider::install_default()`.  Always inject the
/// provider per-config via `ServerConfig::builder_with_provider` /
/// `ClientConfig::builder_with_provider`.
///
/// # Example
/// ```no_run
/// # #[cfg(feature = "aws-lc")]
/// # {
/// use oxitls_adapter_aws_lc::aws_lc_provider;
/// use rustls::ServerConfig;
///
/// let provider = aws_lc_provider();
/// let _builder = ServerConfig::builder_with_provider(provider)
///     .with_safe_default_protocol_versions()
///     .unwrap();
/// # }
/// ```
#[cfg(feature = "aws-lc")]
pub fn aws_lc_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}
