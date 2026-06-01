//! Fluent builder for [`rustls::ClientConfig`] using the RustCrypto provider.
//!
//! Supports certificate pinning, CRL-based revocation, keylog, ALPN, and
//! intermediate certificate caching in a single chainable API.

use std::sync::Arc;

use oxitls_core::{KeyLogPolicy, TlsError};
use oxitls_webpki_roots::IntermediateCertCache;
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::CertificateRevocationListDer;
use rustls::{ClientConfig, RootCertStore};

use crate::keylog_bridge::KeyLogBridge;
use crate::pure_provider;
use crate::verifier::crl::CrlAwareServerVerifier;
use crate::verifier::custom::CustomServerVerifier;
use crate::verifier::ocsp_client::{OcspClientPolicy, OcspClientVerifier};
use crate::verifier::pin::CertPinVerifier;
use crate::verifier::sct::{CtLogList, SctPolicy, SctVerifier};

/// Fluent builder for [`rustls::ClientConfig`] using the RustCrypto provider.
///
/// Call [`RustcryptoClientConfigBuilder::new`], chain configuration methods,
/// and call [`build`](Self::build) to produce a [`ClientConfig`].
///
/// # Example
/// ```no_run
/// use oxitls_adapter_rustls_rustcrypto::RustcryptoClientConfigBuilder;
/// use rustls::RootCertStore;
///
/// # fn example() -> Result<(), oxitls_core::TlsError> {
/// let cfg = RustcryptoClientConfigBuilder::new()
///     .with_roots(RootCertStore::empty())
///     .with_alpn(vec![b"h2".to_vec()])
///     .build()?;
/// # Ok(())
/// # }
/// ```
pub struct RustcryptoClientConfigBuilder {
    root_store: RootCertStore,
    pinned_certs: Vec<[u8; 32]>,
    crls: Vec<CertificateRevocationListDer<'static>>,
    keylog: KeyLogPolicy,
    alpn_protocols: Vec<Vec<u8>>,
    intermediate_cache: Option<Arc<IntermediateCertCache>>,
    resumption_disabled: bool,
    ocsp_policy: Option<OcspClientPolicy>,
    sct_policy: Option<(SctPolicy, CtLogList)>,
}

impl Default for RustcryptoClientConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl RustcryptoClientConfigBuilder {
    /// Create a new builder with default settings (empty root store, no pinning,
    /// no CRLs, keylog disabled, no ALPN restriction).
    pub fn new() -> Self {
        Self {
            root_store: RootCertStore::empty(),
            pinned_certs: Vec::new(),
            crls: Vec::new(),
            keylog: KeyLogPolicy::Disabled,
            alpn_protocols: Vec::new(),
            intermediate_cache: None,
            resumption_disabled: false,
            ocsp_policy: None,
            sct_policy: None,
        }
    }

    /// Set the root cert store used to validate server certificates.
    pub fn with_roots(mut self, store: RootCertStore) -> Self {
        self.root_store = store;
        self
    }

    /// Pin acceptable server leaf certificates by their SHA-256 DER
    /// fingerprint. The handshake is rejected if the leaf's fingerprint does
    /// not appear in this list.
    pub fn with_pinned_certs(mut self, fingerprints: Vec<[u8; 32]>) -> Self {
        self.pinned_certs = fingerprints;
        self
    }

    /// Enable CRL-based certificate revocation checking.
    ///
    /// If both `with_pinned_certs` and `with_crl` are called, pinning takes
    /// precedence (the CRL list is ignored when pinning is set).
    pub fn with_crl(mut self, crls: Vec<CertificateRevocationListDer<'static>>) -> Self {
        self.crls = crls;
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

    /// Attach an intermediate certificate cache.
    ///
    /// When set, the verifier wraps the base verifier with a
    /// [`CustomServerVerifier`] that records intermediate DER blobs after each
    /// successful handshake.
    pub fn with_intermediate_cache(mut self, cache: Arc<IntermediateCertCache>) -> Self {
        self.intermediate_cache = Some(cache);
        self
    }

    /// Disable session resumption entirely.
    pub fn with_resumption_disabled(mut self) -> Self {
        self.resumption_disabled = true;
        self
    }

    /// Configure client-side OCSP staple validation.
    ///
    /// When `policy` is not [`OcspClientPolicy::Disabled`], the built config
    /// wraps the inner verifier with [`OcspClientVerifier`] which parses the
    /// OCSP staple sent by the server and rejects `Revoked` certificates.
    ///
    /// Note: cryptographic verification of the OCSP signer is deferred to
    /// Wave-5. See [`OcspClientVerifier`] for details.
    pub fn with_ocsp_policy(mut self, policy: OcspClientPolicy) -> Self {
        self.ocsp_policy = Some(policy);
        self
    }

    /// Configure Certificate Transparency SCT log verification.
    ///
    /// When `policy` is not [`SctPolicy::Disabled`], the built config wraps
    /// the inner verifier with [`SctVerifier`] which checks that the leaf cert
    /// contains an embedded SCT list with entries from the supplied `logs`.
    /// Each SCT signature is cryptographically verified against the log's
    /// public key using the RFC 6962 `precert_entry` signed payload.
    pub fn with_sct_policy(mut self, policy: SctPolicy, logs: CtLogList) -> Self {
        self.sct_policy = Some((policy, logs));
        self
    }

    /// Build the [`ClientConfig`].
    ///
    /// # Errors
    ///
    /// Returns [`TlsError::InvalidConfig`] if the rustls builder rejects the
    /// configuration (e.g. empty root store when building the verifier).
    pub fn build(self) -> Result<ClientConfig, TlsError> {
        let provider = pure_provider();

        // Choose the verifier path: pinning > CRL > plain.
        let base_verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> = {
            if !self.pinned_certs.is_empty() {
                // Build a plain WebPkiServerVerifier as the inner verifier.
                let inner = WebPkiServerVerifier::builder_with_provider(
                    Arc::new(self.root_store.clone()),
                    provider.clone(),
                )
                .build()
                .map_err(|e| TlsError::InvalidConfig(format!("verifier build: {e}")))?;
                Arc::new(CertPinVerifier::new(self.pinned_certs, inner))
            } else if !self.crls.is_empty() {
                Arc::new(CrlAwareServerVerifier::new(
                    self.root_store.clone(),
                    self.crls,
                )?)
            } else {
                WebPkiServerVerifier::builder_with_provider(
                    Arc::new(self.root_store),
                    provider.clone(),
                )
                .build()
                .map_err(|e| TlsError::InvalidConfig(format!("verifier build: {e}")))?
            }
        };

        // Wrap with intermediate cache if requested.
        let cache_verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> =
            if let Some(cache) = self.intermediate_cache {
                let cache_clone = cache.clone();
                Arc::new(CustomServerVerifier::new(
                    base_verifier,
                    Box::new(move |_leaf, intermediates| {
                        for cert in intermediates {
                            // Silently ignore cache errors — don't fail handshake.
                            let owned: rustls::pki_types::CertificateDer<'static> =
                                cert.clone().into_owned();
                            let _ = cache_clone.insert(owned);
                        }
                        Ok(rustls::client::danger::ServerCertVerified::assertion())
                    }),
                ))
            } else {
                base_verifier
            };

        // Wrap with OCSP client verifier if policy is set and not Disabled.
        let ocsp_verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> =
            match self.ocsp_policy {
                Some(policy) if policy != OcspClientPolicy::Disabled => {
                    Arc::new(OcspClientVerifier::new(cache_verifier, policy))
                }
                _ => cache_verifier,
            };

        // Wrap with SCT verifier if policy is set and not Disabled.
        let verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> = match self.sct_policy {
            Some((SctPolicy::Disabled, _)) | None => ocsp_verifier,
            Some((policy, logs)) => Arc::new(SctVerifier::new(ocsp_verifier, policy, logs)),
        };

        let builder = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| TlsError::InvalidConfig(e.to_string()))?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();

        let mut config = builder;

        if !self.alpn_protocols.is_empty() {
            config.alpn_protocols = self.alpn_protocols;
        }

        if !matches!(self.keylog, KeyLogPolicy::Disabled) {
            config.key_log = Arc::new(KeyLogBridge::new(self.keylog));
        }

        if self.resumption_disabled {
            config.resumption = rustls::client::Resumption::disabled();
        }

        Ok(config)
    }
}
