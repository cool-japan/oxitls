//! Ergonomic wrapper type over the aws-lc-rs [`CryptoProvider`].
//!
//! All items in this module are gated on `#[cfg(feature = "aws-lc")]`.

use crate::{
    aws_lc_provider, aws_lc_provider_tls12_only, aws_lc_provider_with_cipher_suites, is_fips_mode,
};
use oxitls_core::TlsError;
use rustls::{
    crypto::CryptoProvider, ClientConfig, RootCertStore, ServerConfig, SupportedCipherSuite,
    SupportedProtocolVersion,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;

/// Ergonomic builder-style wrapper around the aws-lc-rs [`CryptoProvider`].
///
/// Wraps the provider with convenience methods for constructing client/server
/// TLS configs without needing to interact with rustls builder APIs directly.
///
/// # Example
/// ```no_run
/// # #[cfg(feature = "aws-lc")]
/// # {
/// use oxitls_adapter_aws_lc::AwsLcTlsProvider;
///
/// let provider = AwsLcTlsProvider::new();
/// println!("FIPS mode: {}", provider.is_fips());
/// println!("Cipher suites: {:?}", provider.cipher_suites());
/// # }
/// ```
#[derive(Clone)]
pub struct AwsLcTlsProvider {
    inner: Arc<CryptoProvider>,
}

impl std::fmt::Debug for AwsLcTlsProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let suites: Vec<String> = self
            .inner
            .cipher_suites
            .iter()
            .map(|cs| format!("{cs:?}"))
            .collect();
        let groups: Vec<String> = self
            .inner
            .kx_groups
            .iter()
            .map(|g| format!("{:?}", g.name()))
            .collect();
        f.debug_struct("AwsLcTlsProvider")
            .field("cipher_suites", &suites)
            .field("kx_groups", &groups)
            .field("fips_mode", &is_fips_mode())
            .finish()
    }
}

impl AwsLcTlsProvider {
    /// Create a new provider with the default aws-lc-rs configuration.
    pub fn new() -> Self {
        Self {
            inner: aws_lc_provider(),
        }
    }

    /// Create a new provider restricted to the given cipher suites.
    pub fn with_cipher_suites(suites: &[SupportedCipherSuite]) -> Self {
        Self {
            inner: aws_lc_provider_with_cipher_suites(suites),
        }
    }

    /// Restrict to TLS 1.2-only protocol versions.
    ///
    /// Returns the provider and the version slice required for
    /// [`ClientConfig`]/[`ServerConfig`] builders.
    pub fn tls12_only(self) -> (Self, &'static [&'static SupportedProtocolVersion]) {
        let (provider, versions) = aws_lc_provider_tls12_only();
        (Self { inner: provider }, versions)
    }

    /// Returns whether this provider is running in FIPS-approved mode.
    pub fn is_fips(&self) -> bool {
        is_fips_mode()
    }

    /// Returns the cipher suite names available in this provider.
    pub fn cipher_suites(&self) -> Vec<String> {
        self.inner
            .cipher_suites
            .iter()
            .map(|cs| format!("{cs:?}"))
            .collect()
    }

    /// Returns the key-exchange group names available in this provider.
    pub fn kx_groups(&self) -> Vec<String> {
        self.inner
            .kx_groups
            .iter()
            .map(|g| format!("{:?}", g.name()))
            .collect()
    }

    /// Construct a TLS client config with the given root certificate store.
    ///
    /// ALPN is disabled; use [`crate::aws_lc_client_config`] to supply ALPN
    /// protocols.
    pub fn client_config(&self, roots: RootCertStore) -> Result<ClientConfig, TlsError> {
        crate::aws_lc_client_config(roots, vec![])
    }

    /// Construct a mutual TLS client config.
    ///
    /// The client presents `cert_chain` (leaf first) with `key` during the
    /// handshake. Server certificates are validated against `roots`.
    pub fn mtls_client_config(
        &self,
        roots: RootCertStore,
        cert_chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<ClientConfig, TlsError> {
        crate::aws_lc_mtls_client_config(roots, cert_chain, key)
    }

    /// Construct a TLS server config with the given certificate chain and private key.
    ///
    /// ALPN is disabled; use [`crate::aws_lc_server_config`] to supply ALPN
    /// protocols.
    pub fn server_config(
        &self,
        cert_chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<ServerConfig, TlsError> {
        crate::aws_lc_server_config(cert_chain, key, vec![])
    }

    /// Access the inner [`CryptoProvider`].
    pub fn as_provider(&self) -> &Arc<CryptoProvider> {
        &self.inner
    }
}

impl Default for AwsLcTlsProvider {
    fn default() -> Self {
        Self::new()
    }
}
