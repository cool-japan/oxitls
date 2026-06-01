//! Fluent builder for [`rustls::ServerConfig`] using the RustCrypto provider.
//!
//! Supports OCSP stapling, mutual TLS (client auth), keylog, ALPN, and
//! custom session ticketers in a single chainable API.

use std::sync::Arc;

use oxitls_core::{KeyLogPolicy, TlsError};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::ProducesTickets;
use rustls::{RootCertStore, ServerConfig};

use crate::keylog_bridge::KeyLogBridge;
use crate::pure_provider;

/// Fluent builder for [`rustls::ServerConfig`] using the RustCrypto provider.
///
/// Call [`RustcryptoServerConfigBuilder::new`], chain configuration methods,
/// and call [`build`](Self::build) to produce a [`ServerConfig`].
///
/// # Example
/// ```no_run
/// use oxitls_adapter_rustls_rustcrypto::RustcryptoServerConfigBuilder;
///
/// # fn example() -> Result<(), oxitls_core::TlsError> {
/// # let certs: Vec<rustls::pki_types::CertificateDer<'static>> = vec![];
/// # let key: rustls::pki_types::PrivateKeyDer<'static> = panic!();
/// let cfg = RustcryptoServerConfigBuilder::new()
///     .with_cert_and_key(certs, key)
///     .with_alpn(vec![b"h2".to_vec()])
///     .build()?;
/// # Ok(())
/// # }
/// ```
pub struct RustcryptoServerConfigBuilder {
    certs: Vec<CertificateDer<'static>>,
    key: Option<PrivateKeyDer<'static>>,
    ocsp_response: Vec<u8>,
    client_auth_required: Option<bool>,
    client_auth_roots: Option<RootCertStore>,
    keylog: KeyLogPolicy,
    alpn_protocols: Vec<Vec<u8>>,
    ticketer: Option<Arc<dyn ProducesTickets>>,
}

impl Default for RustcryptoServerConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl RustcryptoServerConfigBuilder {
    /// Create a new builder with no certificate/key set and no client auth.
    pub fn new() -> Self {
        Self {
            certs: Vec::new(),
            key: None,
            ocsp_response: Vec::new(),
            client_auth_required: None,
            client_auth_roots: None,
            keylog: KeyLogPolicy::Disabled,
            alpn_protocols: Vec::new(),
            ticketer: None,
        }
    }

    /// Set the certificate chain and private key for this server.
    pub fn with_cert_and_key(
        mut self,
        certs: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Self {
        self.certs = certs;
        self.key = Some(key);
        self
    }

    /// Set a DER-encoded OCSP response for stapling.
    ///
    /// If `der` is empty the response is ignored. The response is passed
    /// to rustls's `with_single_cert_with_ocsp` when building the config.
    pub fn with_ocsp_response(mut self, der: Vec<u8>) -> Self {
        self.ocsp_response = der;
        self
    }

    /// Enable mutual TLS client authentication.
    ///
    /// `required` — if `true`, clients that present no certificate are
    /// rejected; if `false`, unauthenticated clients are allowed.
    pub fn with_client_auth(mut self, required: bool, roots: RootCertStore) -> Self {
        self.client_auth_required = Some(required);
        self.client_auth_roots = Some(roots);
        self
    }

    /// Set the key-logging policy for this config.
    pub fn with_keylog(mut self, policy: KeyLogPolicy) -> Self {
        self.keylog = policy;
        self
    }

    /// Set the ALPN protocol list (in preference order).
    pub fn with_alpn(mut self, protos: Vec<Vec<u8>>) -> Self {
        self.alpn_protocols = protos;
        self
    }

    /// Use a custom session ticketer (e.g. for cluster-shared tickets).
    pub fn with_ticketer(mut self, ticketer: Arc<dyn ProducesTickets>) -> Self {
        self.ticketer = Some(ticketer);
        self
    }

    /// Build the [`ServerConfig`].
    ///
    /// # Errors
    ///
    /// Returns [`TlsError`] if:
    /// - No certificate or key has been supplied.
    /// - The certificate or key is invalid.
    /// - Building the client cert verifier fails.
    pub fn build(self) -> Result<ServerConfig, TlsError> {
        let key = self
            .key
            .ok_or_else(|| TlsError::InvalidConfig("no private key provided".into()))?;

        let provider = pure_provider();

        // Choose the client auth verifier.
        let base_builder = ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(|e| TlsError::InvalidConfig(e.to_string()))?;

        let wants_cert = match (self.client_auth_required, self.client_auth_roots) {
            (Some(required), Some(roots)) => {
                let mut builder = rustls::server::WebPkiClientVerifier::builder_with_provider(
                    Arc::new(roots),
                    provider,
                );
                if !required {
                    builder = builder.allow_unauthenticated();
                }
                let verifier = builder
                    .build()
                    .map_err(|e| TlsError::InvalidConfig(format!("client verifier: {e}")))?;
                base_builder.with_client_cert_verifier(verifier)
            }
            _ => base_builder.with_no_client_auth(),
        };

        let mut config = if self.ocsp_response.is_empty() {
            wants_cert
                .with_single_cert(self.certs, key)
                .map_err(|e| TlsError::BadCert(e.to_string()))?
        } else {
            wants_cert
                .with_single_cert_with_ocsp(self.certs, key, self.ocsp_response)
                .map_err(|e| TlsError::BadCert(e.to_string()))?
        };

        if !self.alpn_protocols.is_empty() {
            config.alpn_protocols = self.alpn_protocols;
        }

        if !matches!(self.keylog, KeyLogPolicy::Disabled) {
            config.key_log = Arc::new(KeyLogBridge::new(self.keylog));
        }

        if let Some(ticketer) = self.ticketer {
            config.ticketer = ticketer;
        }

        Ok(config)
    }
}
