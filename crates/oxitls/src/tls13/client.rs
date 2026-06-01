//! TLS 1.3 (+ optional TLS 1.2 fallback) client configuration builder.
//!
//! Supports:
//! - TLS 1.3-only (default)
//! - TLS 1.2 fallback via `with_tls12_fallback()`
//! - Explicit protocol-version list via `with_protocol_versions()`
//! - ALPN protocol negotiation via `with_alpn_protocols()`
//! - Client certificate authentication via `with_client_cert()`
//! - Client-side session resumption via in-memory session store (always enabled,
//!   capacity configurable via `with_resumption_capacity()`).
//! - Certificate pinning via `with_cert_pinning()`
//! - CRL-based revocation via `with_crl()`
//! - TLS key-log file or custom logger via `with_key_log_file()` / `with_key_log_custom()`
//! - Intermediate certificate caching via `with_intermediate_cache()`
//! - Hostname ignore (danger) via `with_danger_accept_invalid_hostnames()`
//! - 0-RTT early data via `with_early_data()`
//! - QUIC/HTTP-3 namespace reservation via `with_quic_preview()`
//! - Custom root store builder via `with_root_store_builder()`
//! - CT log verification via `with_ct_logs()`

use std::path::PathBuf;
use std::sync::Arc;

use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer};
use rustls::ClientConfig;

use oxitls_core::{KeyLog, KeyLogPolicy, TlsError};

use crate::danger::DangerHostnameIgnoreVerifier;

/// Builder for a Pure-Rust TLS client [`ClientConfig`].
///
/// Defaults:
/// - TLS 1.3 only (use [`with_tls12_fallback`](Self::with_tls12_fallback) or
///   [`with_protocol_versions`](Self::with_protocol_versions) to change)
/// - No client certificate (anonymous client)
/// - Session resumption via 256-entry in-memory session store
/// - No ALPN protocols (use
///   [`with_alpn_protocols`](Self::with_alpn_protocols) to set, e.g. `["h2",
///   "http/1.1"]`)
///
/// # Example
/// ```no_run
/// # fn example() -> Result<(), oxitls_core::TlsError> {
/// use oxitls::tls13::ClientBuilder;
///
/// let config = ClientBuilder::new()
///     .with_tls12_fallback()
///     .with_alpn_protocols(["h2", "http/1.1"])
///     .with_webpki_roots()
///     .build()?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct ClientBuilder {
    /// Explicit protocol versions; `None` means TLS 1.3 only (the safe default).
    protocol_versions: Option<Vec<&'static rustls::SupportedProtocolVersion>>,
    /// DER-encoded trusted CA certs; when empty, only webpki roots are used if
    /// `use_webpki_roots` is true.
    trusted_certs: Vec<CertificateDer<'static>>,
    /// Use the Mozilla CA bundle (webpki-roots) as trusted roots.
    use_webpki_roots: bool,
    /// Session resumption cache capacity (0 = disabled).
    resumption_capacity: usize,
    /// ALPN protocol list; empty means no ALPN extension.
    alpn: Vec<Vec<u8>>,
    /// Client certificate chain + private key for client authentication.
    client_cert: Option<(Vec<CertificateDer<'static>>, Arc<PrivateKeyDer<'static>>)>,
    /// Accept invalid (self-signed, expired, etc.) server certificates. For
    /// testing only.
    danger_accept_invalid_certs: bool,
    /// Accept invalid server hostnames (SAN mismatch). For testing only.
    danger_accept_invalid_hostnames: bool,
    /// Certificate pins: SHA-256 fingerprints of acceptable leaf certs.
    cert_pins: Vec<[u8; 32]>,
    /// CRLs for revocation checking.
    crls: Vec<CertificateRevocationListDer<'static>>,
    /// Key-log policy (file path or custom logger).
    key_log_policy: Option<KeyLogPolicy>,
    /// Intermediate certificate cache for multi-step chain verification.
    #[cfg(feature = "webpki-roots")]
    intermediate_cache: Option<Arc<oxitls_webpki_roots::IntermediateCertCache>>,
    /// Enable 0-RTT early data on TLS 1.3 connections.
    ///
    /// Maps to `rustls::ClientConfig::enable_early_data` (public field in
    /// rustls 0.23).  Note: tokio-rustls 0.26 requires the `early-data` cargo
    /// feature AND `TlsConnector::early_data(true)` in addition to this flag
    /// for the early-data write path to activate.  Setting this field alone
    /// enables the *rustls* layer; wire `TlsConnector::early_data(true)` on
    /// the connector side if you need the tokio async write path.
    enable_early_data: bool,
    /// If true, add `b"h3"` to ALPN protocols (QUIC preview namespace reservation).
    #[cfg(feature = "quic-preview")]
    quic_preview: bool,
    /// Extra root cert store supplied via `with_root_store_builder`.  When
    /// present its trust anchors are merged into whichever root store the
    /// build path constructs.
    #[cfg(feature = "webpki-roots")]
    extra_root_store: Option<rustls::RootCertStore>,
    /// CT log list + SCT policy wired via `with_ct_logs`.
    #[cfg(feature = "pure")]
    ct_logs: Option<(
        oxitls_adapter_rustls_rustcrypto::verifier::CtLogList,
        oxitls_adapter_rustls_rustcrypto::verifier::SctPolicy,
    )>,
    /// Optional injected [`rustls::crypto::CryptoProvider`].
    /// When `None`, defaults to `oxitls_adapter_rustls_rustcrypto::pure_provider()`
    /// (or the post-quantum variant when the `post-quantum` feature is enabled).
    ///
    /// Note: the `use_adapter` path (cert pinning, CRL, CT logs) routes through
    /// `RustcryptoClientConfigBuilder`, which manages its own provider internally;
    /// the injected provider applies to the normal and danger verification paths.
    provider: Option<Arc<rustls::crypto::CryptoProvider>>,
    /// Raw public key pinning (RFC 7250): server must present one of these SPKIs.
    ///
    /// When set, the normal X.509 certificate verification path is bypassed and
    /// the server is expected to present a raw public key instead of a certificate.
    /// The handshake is rejected unless the server's SPKI matches one of the pinned
    /// values.
    #[cfg(feature = "pure")]
    server_raw_public_keys: Option<Vec<rustls::pki_types::SubjectPublicKeyInfoDer<'static>>>,
}

impl ClientBuilder {
    /// Create a new builder with TLS 1.3 only and a 256-entry resumption cache.
    pub fn new() -> Self {
        Self {
            protocol_versions: None,
            trusted_certs: Vec::new(),
            use_webpki_roots: false,
            resumption_capacity: 256,
            alpn: Vec::new(),
            client_cert: None,
            danger_accept_invalid_certs: false,
            danger_accept_invalid_hostnames: false,
            cert_pins: Vec::new(),
            crls: Vec::new(),
            key_log_policy: None,
            #[cfg(feature = "webpki-roots")]
            intermediate_cache: None,
            enable_early_data: false,
            #[cfg(feature = "quic-preview")]
            quic_preview: false,
            #[cfg(feature = "webpki-roots")]
            extra_root_store: None,
            #[cfg(feature = "pure")]
            ct_logs: None,
            provider: None,
            #[cfg(feature = "pure")]
            server_raw_public_keys: None,
        }
    }

    /// Enable TLS 1.2 as a fallback (AEAD-only suites via `rustls-rustcrypto`).
    ///
    /// After calling this the client will try TLS 1.3 first and fall back to
    /// TLS 1.2 if the server does not support 1.3.
    pub fn with_tls12_fallback(mut self) -> Self {
        self.protocol_versions = Some(vec![&rustls::version::TLS13, &rustls::version::TLS12]);
        self
    }

    /// Explicitly set the allowed TLS versions.
    ///
    /// Overrides any previous call to `with_tls12_fallback()`.
    pub fn with_protocol_versions(
        mut self,
        versions: &[&'static rustls::SupportedProtocolVersion],
    ) -> Self {
        self.protocol_versions = Some(versions.to_vec());
        self
    }

    /// Trust a single DER-encoded CA certificate in addition to the system/webpki roots.
    pub fn with_trusted_cert_der(mut self, cert: Vec<u8>) -> Result<Self, TlsError> {
        let der = CertificateDer::from(cert);
        self.trusted_certs.push(der);
        Ok(self)
    }

    /// Trust the Mozilla CA bundle (requires the `webpki-roots` feature on the
    /// `oxitls` crate).
    pub fn with_webpki_roots(mut self) -> Self {
        self.use_webpki_roots = true;
        self
    }

    /// Override the session-resumption cache capacity.
    ///
    /// Default is 256. Pass 0 to disable resumption entirely.
    pub fn with_resumption_capacity(mut self, cap: usize) -> Self {
        self.resumption_capacity = cap;
        self
    }

    /// Announce ALPN protocols the client is willing to negotiate.
    ///
    /// The protocols are tried in the order given; the server picks the first
    /// one it supports.
    ///
    /// # Example
    /// ```no_run
    /// # fn example() -> Result<(), oxitls_core::TlsError> {
    /// use oxitls::tls13::ClientBuilder;
    ///
    /// let config = ClientBuilder::new()
    ///     .with_alpn_protocols(["h2", "http/1.1"])
    ///     .with_webpki_roots()
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_alpn_protocols(
        mut self,
        protocols: impl IntoIterator<Item = impl AsRef<[u8]>>,
    ) -> Self {
        self.alpn = protocols.into_iter().map(|p| p.as_ref().to_vec()).collect();
        self
    }

    /// Authenticate the client with a certificate chain and private key.
    ///
    /// The certificate chain is leaf-first, followed by any intermediates.
    /// The private key must correspond to the leaf certificate.
    ///
    /// # Example
    /// ```no_run
    /// # fn example() -> Result<(), oxitls_core::TlsError> {
    /// # let client_cert_der: Vec<u8> = vec![];
    /// # let client_key_der: Vec<u8> = vec![];
    /// use oxitls::tls13::ClientBuilder;
    /// use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    ///
    /// let cert = CertificateDer::from(client_cert_der);
    /// let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(client_key_der));
    ///
    /// let config = ClientBuilder::new()
    ///     .with_webpki_roots()
    ///     .with_client_cert(vec![cert], key)
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_client_cert(
        mut self,
        certs: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Self {
        self.client_cert = Some((certs, Arc::new(key)));
        self
    }

    /// **DANGER**: Accept any server certificate, including self-signed,
    /// expired, or otherwise invalid certificates.
    ///
    /// This is intended **only** for testing and development. Using this in
    /// production disables all certificate verification.
    pub fn with_danger_accept_invalid_certs(mut self) -> Self {
        self.danger_accept_invalid_certs = true;
        self
    }

    /// **DANGER**: Accept server certificates that do not match the requested
    /// hostname (SAN mismatch). Chain trust validation still applies.
    ///
    /// This is intended **only** for testing and development where the server
    /// certificate was issued for a different name.
    pub fn with_danger_accept_invalid_hostnames(mut self) -> Self {
        self.danger_accept_invalid_hostnames = true;
        self
    }

    /// Pin acceptable server leaf certificates by their SHA-256 DER fingerprint.
    ///
    /// The handshake is rejected if the leaf certificate's fingerprint does not
    /// appear in the supplied list. Delegates to `RustcryptoClientConfigBuilder`
    /// in the adapter crate.
    pub fn with_cert_pinning(mut self, pins: Vec<[u8; 32]>) -> Self {
        self.cert_pins = pins;
        self
    }

    /// Enable CRL-based certificate revocation checking.
    pub fn with_crl(mut self, crls: Vec<CertificateRevocationListDer<'static>>) -> Self {
        self.crls = crls;
        self
    }

    /// Write TLS session secrets to a file in NSS key-log format (SSLKEYLOGFILE).
    ///
    /// The file is created and appended to. Silently ignores I/O errors so a
    /// logging failure never takes down the TLS handshake.
    pub fn with_key_log_file(mut self, path: PathBuf) -> Self {
        self.key_log_policy = Some(KeyLogPolicy::File(path));
        self
    }

    /// Install a custom key-log sink implementing [`KeyLog`].
    pub fn with_key_log_custom(mut self, arc: Arc<dyn KeyLog + Send + Sync>) -> Self {
        self.key_log_policy = Some(KeyLogPolicy::Custom(arc));
        self
    }

    /// Attach an intermediate certificate cache for multi-step chain verification.
    ///
    /// After each successful handshake the verifier records observed intermediate
    /// DER blobs into the cache.
    #[cfg(feature = "webpki-roots")]
    pub fn with_intermediate_cache(
        mut self,
        cache: Arc<oxitls_webpki_roots::IntermediateCertCache>,
    ) -> Self {
        self.intermediate_cache = Some(cache);
        self
    }

    /// Load roots from an [`oxitls_webpki_roots::RootStoreBuilder`].
    ///
    /// Builds the store from the builder and merges its trust anchors into
    /// whichever root store the final `build()` call constructs.  This is
    /// additive: custom roots from the builder are combined with any roots
    /// already configured via `with_webpki_roots()` or `with_trusted_cert_der()`.
    ///
    /// # Errors
    ///
    /// Never returns an error — the builder is always consumed. The `Result`
    /// return type is reserved for future validation.
    #[cfg(feature = "webpki-roots")]
    pub fn with_root_store_builder(
        mut self,
        builder: oxitls_webpki_roots::RootStoreBuilder,
    ) -> Result<Self, TlsError> {
        let store = builder.build();
        self.extra_root_store = Some(store);
        Ok(self)
    }

    /// Wire a CT log list + SCT policy into the client config.
    ///
    /// When set, the TLS client verifies Certificate Transparency SCTs embedded
    /// in the leaf certificate against the supplied log list.
    ///
    /// This uses the `oxitls-adapter-rustls-rustcrypto` SCT verifier path
    /// (which delegates chain validation to the standard WebPKI verifier).
    /// SCT signature verification is active, enforcing both log-ID presence
    /// and cryptographic signature validity per the configured policy.
    ///
    /// Requires the `pure` feature.
    #[cfg(feature = "pure")]
    pub fn with_ct_logs(
        mut self,
        logs: oxitls_adapter_rustls_rustcrypto::verifier::CtLogList,
        policy: oxitls_adapter_rustls_rustcrypto::verifier::SctPolicy,
    ) -> Self {
        self.ct_logs = Some((logs, policy));
        self
    }

    /// Enable 0-RTT (early data) on TLS 1.3 connections.
    ///
    /// Sets `rustls::ClientConfig::enable_early_data = true` on the built
    /// config.  The client will attempt to send application data before the
    /// full handshake completes when a session ticket from a prior connection
    /// is available.
    ///
    /// **Rustls field**: `ClientConfig::enable_early_data` — a public
    /// `bool` field added in rustls 0.23 (confirmed present in 0.23.x).
    ///
    /// **tokio-rustls note**: The tokio-rustls `TlsConnector::early_data(true)`
    /// call is required in addition to this builder flag when using the
    /// `tokio-rustls` async write path; that connector is not managed by
    /// this builder.  See `tokio_rustls::client::TlsConnector::early_data`.
    ///
    /// # Example
    /// ```no_run
    /// # fn example() -> Result<(), oxitls_core::TlsError> {
    /// use oxitls::tls13::ClientBuilder;
    ///
    /// let config = ClientBuilder::new()
    ///     .with_webpki_roots()
    ///     .with_early_data()
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_early_data(mut self) -> Self {
        self.enable_early_data = true;
        self
    }

    /// Reserve the QUIC/HTTP-3 namespace in ALPN (`b"h3"`).
    ///
    /// When `enabled` is `true`, `b"h3"` is added to the ALPN list if not
    /// already present.  This is a **preview** namespace reservation — actual
    /// QUIC transport is handled by `oxiquic-tls`.
    ///
    /// Requires the `quic-preview` feature.
    #[cfg(feature = "quic-preview")]
    pub fn with_quic_preview(mut self, enabled: bool) -> Self {
        self.quic_preview = enabled;
        self
    }

    /// Set the ticketer rotation interval for session ticket resumption.
    ///
    /// This sets a hint for how long session tickets should be considered valid.
    /// Requires a server-side ticketer to be configured; on the client side
    /// this method is a placeholder for symmetry with `ServerBuilder`.
    pub fn with_ticketer_rotation_interval(self, _interval: std::time::Duration) -> Self {
        // Client-side ticketer rotation is controlled by the server.
        // This method is provided for API symmetry and forwards to no-op.
        self
    }

    /// Inject a custom [`rustls::crypto::CryptoProvider`].
    ///
    /// When not called, `build()` defaults to
    /// `oxitls_adapter_rustls_rustcrypto::pure_provider()` (Pure-Rust, no C deps).
    ///
    /// The injected provider applies to the normal and danger verification paths.
    /// The adapter path (cert pinning, CRL, CT logs via
    /// `oxitls_adapter_rustls_rustcrypto::RustcryptoClientConfigBuilder`) manages
    /// its own provider internally and is not affected by this setting.
    ///
    /// # Example
    /// ```no_run
    /// # fn example() -> Result<(), oxitls_core::TlsError> {
    /// use std::sync::Arc;
    /// use oxitls::tls13::ClientBuilder;
    ///
    /// // Use the default Pure-Rust provider explicitly:
    /// let provider = oxitls_adapter_rustls_rustcrypto::pure_provider();
    /// let config = ClientBuilder::new()
    ///     .with_provider(provider)
    ///     .with_danger_accept_invalid_certs()
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_provider(mut self, provider: Arc<rustls::crypto::CryptoProvider>) -> Self {
        self.provider = Some(provider);
        self
    }

    /// Accept a server that presents a raw public key (RFC 7250) instead of an
    /// X.509 certificate.
    ///
    /// The provided SPKI list is pinned — the server must present one of them.
    /// When this option is set the normal X.509 certificate verification path
    /// is bypassed entirely; roots configured via `with_webpki_roots` or
    /// `with_trusted_cert_der` are ignored for server authentication.
    ///
    /// Requires the `pure` feature.
    ///
    /// # Example
    /// ```no_run
    /// # fn example() -> Result<(), oxitls_core::TlsError> {
    /// use oxitls::tls13::ClientBuilder;
    /// use rustls::pki_types::SubjectPublicKeyInfoDer;
    ///
    /// let spki: Vec<u8> = vec![/* DER-encoded SPKI */];
    /// let config = ClientBuilder::new()
    ///     .with_server_raw_public_keys(vec![SubjectPublicKeyInfoDer::from(spki)])
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "pure")]
    pub fn with_server_raw_public_keys(
        mut self,
        spki_list: Vec<rustls::pki_types::SubjectPublicKeyInfoDer<'static>>,
    ) -> Self {
        self.server_raw_public_keys = Some(spki_list);
        self
    }

    /// Build the final [`ClientConfig`].
    ///
    /// # Errors
    /// Returns [`TlsError::InvalidConfig`] when:
    /// - No trust roots are configured and certificate pinning is not active
    ///   (i.e. neither `with_webpki_roots`, `with_trusted_cert_der`, nor
    ///   `with_cert_pinning` was called, and neither danger flag is set).
    /// - The protocol version list is rejected by the cryptographic provider.
    pub fn build(self) -> Result<ClientConfig, TlsError> {
        // Validation: at least one trust anchor, cert pinning, or RPK pinning must be
        // configured, unless a danger flag bypasses certificate verification entirely.
        let has_roots = self.use_webpki_roots || !self.trusted_certs.is_empty() || {
            #[cfg(feature = "webpki-roots")]
            {
                self.extra_root_store
                    .as_ref()
                    .is_some_and(|s| !s.is_empty())
            }
            #[cfg(not(feature = "webpki-roots"))]
            {
                false
            }
        };
        let has_pinning = !self.cert_pins.is_empty();
        let has_rpk = {
            #[cfg(feature = "pure")]
            {
                self.server_raw_public_keys.is_some()
            }
            #[cfg(not(feature = "pure"))]
            {
                false
            }
        };
        let bypasses_verify =
            self.danger_accept_invalid_certs || self.danger_accept_invalid_hostnames;
        if !has_roots && !has_pinning && !has_rpk && !bypasses_verify {
            return Err(TlsError::InvalidConfig(
                "ClientBuilder: at least one root store, cert pinning, or RPK pinning must be configured".into(),
            ));
        }

        // Resolve provider: use the injected one, or fall back to the appropriate
        // default (post-quantum when feature is enabled, otherwise Pure-Rust).
        let provider = if let Some(p) = self.provider {
            p
        } else {
            #[cfg(feature = "post-quantum")]
            {
                oxitls_adapter_rustls_rustcrypto::pure_provider_with_pq()
            }
            #[cfg(not(feature = "post-quantum"))]
            {
                oxitls_adapter_rustls_rustcrypto::pure_provider()
            }
        };

        // Choose allowed versions.
        let versions: &[&rustls::SupportedProtocolVersion] = match self.protocol_versions {
            Some(ref v) => v.as_slice(),
            None => &[&rustls::version::TLS13],
        };

        let builder_mid = ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(versions)
            .map_err(|e| TlsError::InvalidConfig(e.to_string()))?;

        // Helper locals for cfg-gated fields.
        #[cfg(feature = "webpki-roots")]
        let extra_root_store = self.extra_root_store;
        #[cfg(feature = "pure")]
        let ct_logs = self.ct_logs;
        #[cfg(feature = "pure")]
        let server_raw_public_keys = self.server_raw_public_keys;

        // Determine if the adapter path is needed (cert pinning, CRL, or CT logs).
        let use_adapter = !self.cert_pins.is_empty() || !self.crls.is_empty() || {
            #[cfg(feature = "pure")]
            {
                ct_logs.is_some()
            }
            #[cfg(not(feature = "pure"))]
            {
                false
            }
        };

        // Build the config with appropriate verifier.
        // RPK pinning takes precedence over all other verification paths.
        #[cfg(feature = "pure")]
        if let Some(spki_list) = server_raw_public_keys {
            use oxitls_adapter_rustls_rustcrypto::verifier::raw_public_key::RawPublicKeyServerVerifier;
            let rpk_verifier =
                Arc::new(RawPublicKeyServerVerifier::new(spki_list, provider.clone()));
            let with_verifier = builder_mid
                .dangerous()
                .with_custom_certificate_verifier(rpk_verifier);

            let mut config = match self.client_cert {
                Some((certs, key)) => {
                    let key =
                        Arc::try_unwrap(key).unwrap_or_else(|arc| clone_private_key_der(&arc));
                    with_verifier
                        .with_client_auth_cert(certs, key)
                        .map_err(|e| TlsError::InvalidConfig(e.to_string()))?
                }
                None => with_verifier.with_no_client_auth(),
            };

            config.alpn_protocols = self.alpn;
            if let Some(policy) = self.key_log_policy {
                config.key_log = Arc::new(KeyLogBridge::new(policy));
            }
            config.resumption = if self.resumption_capacity == 0 {
                rustls::client::Resumption::disabled()
            } else {
                rustls::client::Resumption::in_memory_sessions(self.resumption_capacity)
            };
            if self.enable_early_data {
                config.enable_early_data = true;
            }
            return Ok(config);
        }

        let mut config = if self.danger_accept_invalid_certs {
            // Dangerous: skip certificate verification entirely.
            let verifier = Arc::new(DangerousNoCertVerifier);
            let with_verifier = builder_mid
                .dangerous()
                .with_custom_certificate_verifier(verifier);

            match self.client_cert {
                Some((certs, key)) => {
                    let key =
                        Arc::try_unwrap(key).unwrap_or_else(|arc| clone_private_key_der(&arc));
                    with_verifier.with_client_cert_resolver(Arc::new(
                        SingleClientCertResolver::new(certs, key)?,
                    ))
                }
                None => with_verifier.with_no_client_auth(),
            }
        } else if self.danger_accept_invalid_hostnames {
            // Danger: accept hostname mismatch, but still validate the chain.
            #[cfg(feature = "webpki-roots")]
            let mut root_store = if self.use_webpki_roots {
                oxitls_webpki_roots::webpki_root_certs()
            } else {
                rustls::RootCertStore::empty()
            };

            #[cfg(not(feature = "webpki-roots"))]
            let mut root_store = rustls::RootCertStore::empty();

            for cert in self.trusted_certs {
                root_store
                    .add(cert)
                    .map_err(|e| TlsError::BadCert(e.to_string()))?;
            }

            // Merge extra roots from with_root_store_builder.
            #[cfg(feature = "webpki-roots")]
            if let Some(extra) = extra_root_store {
                root_store.extend(extra.roots.iter().cloned());
            }

            let inner_verifier =
                WebPkiServerVerifier::builder_with_provider(Arc::new(root_store), provider.clone())
                    .build()
                    .map_err(|e| TlsError::InvalidConfig(format!("verifier build: {e}")))?;

            let hostname_verifier = Arc::new(DangerHostnameIgnoreVerifier::new(inner_verifier));
            let with_verifier = builder_mid
                .dangerous()
                .with_custom_certificate_verifier(hostname_verifier);

            match self.client_cert {
                Some((certs, key)) => {
                    let key =
                        Arc::try_unwrap(key).unwrap_or_else(|arc| clone_private_key_der(&arc));
                    with_verifier
                        .with_client_auth_cert(certs, key)
                        .map_err(|e| TlsError::InvalidConfig(e.to_string()))?
                }
                None => with_verifier.with_no_client_auth(),
            }
        } else if use_adapter {
            // Use the adapter's RustcryptoClientConfigBuilder for advanced features
            // (cert pinning, CRL-based revocation, and/or CT log verification).
            #[cfg(feature = "webpki-roots")]
            let mut root_store = if self.use_webpki_roots {
                oxitls_webpki_roots::webpki_root_certs()
            } else {
                rustls::RootCertStore::empty()
            };

            #[cfg(not(feature = "webpki-roots"))]
            let mut root_store = rustls::RootCertStore::empty();

            // Add explicitly-trusted DER certs to the root store.
            for cert in self.trusted_certs {
                root_store
                    .add(cert)
                    .map_err(|e| TlsError::BadCert(e.to_string()))?;
            }

            // Merge extra roots from with_root_store_builder.
            #[cfg(feature = "webpki-roots")]
            if let Some(extra) = extra_root_store {
                root_store.extend(extra.roots.iter().cloned());
            }

            let mut adapter =
                oxitls_adapter_rustls_rustcrypto::RustcryptoClientConfigBuilder::new()
                    .with_roots(root_store)
                    .with_pinned_certs(self.cert_pins)
                    .with_crl(self.crls)
                    .with_alpn(self.alpn.clone());

            if let Some(policy) = self.key_log_policy.clone() {
                adapter = adapter.with_keylog(policy);
            }
            #[cfg(feature = "webpki-roots")]
            if let Some(cache) = self.intermediate_cache {
                adapter = adapter.with_intermediate_cache(cache);
            }
            // Wire CT log verification if configured.
            #[cfg(feature = "pure")]
            if let Some((logs, sct_policy)) = ct_logs {
                adapter = adapter.with_sct_policy(sct_policy, logs);
            }

            let mut cfg = adapter.build()?;
            cfg.resumption = if self.resumption_capacity == 0 {
                rustls::client::Resumption::disabled()
            } else {
                rustls::client::Resumption::in_memory_sessions(self.resumption_capacity)
            };

            if self.enable_early_data {
                cfg.enable_early_data = true;
            }

            // ALPN already set by adapter; return early for adapter paths.
            return Ok(cfg);
        } else {
            // Normal path: build root store.
            #[cfg(feature = "webpki-roots")]
            let mut root_store = if self.use_webpki_roots {
                oxitls_webpki_roots::webpki_root_certs()
            } else {
                rustls::RootCertStore::empty()
            };

            #[cfg(not(feature = "webpki-roots"))]
            let mut root_store = rustls::RootCertStore::empty();

            for cert in self.trusted_certs {
                root_store
                    .add(cert)
                    .map_err(|e| TlsError::BadCert(e.to_string()))?;
            }

            // Merge extra roots from with_root_store_builder.
            #[cfg(feature = "webpki-roots")]
            if let Some(extra) = extra_root_store {
                root_store.extend(extra.roots.iter().cloned());
            }

            let with_roots = builder_mid.with_root_certificates(root_store);

            match self.client_cert {
                Some((certs, key)) => {
                    let key =
                        Arc::try_unwrap(key).unwrap_or_else(|arc| clone_private_key_der(&arc));
                    with_roots
                        .with_client_auth_cert(certs, key)
                        .map_err(|e| TlsError::InvalidConfig(e.to_string()))?
                }
                None => with_roots.with_no_client_auth(),
            }
        };

        // ALPN protocols.
        config.alpn_protocols = self.alpn;

        // QUIC preview: inject `h3` into ALPN if not already present.
        #[cfg(feature = "quic-preview")]
        if self.quic_preview && !config.alpn_protocols.contains(&b"h3".to_vec()) {
            config.alpn_protocols.push(b"h3".to_vec());
        }

        // Key log.
        if let Some(policy) = self.key_log_policy {
            config.key_log = Arc::new(KeyLogBridge::new(policy));
        }

        // Build resumption strategy.
        config.resumption = if self.resumption_capacity == 0 {
            rustls::client::Resumption::disabled()
        } else {
            rustls::client::Resumption::in_memory_sessions(self.resumption_capacity)
        };

        // 0-RTT early data (TLS 1.3 only).
        // `ClientConfig::enable_early_data` is a public bool field in rustls 0.23.
        if self.enable_early_data {
            config.enable_early_data = true;
        }

        Ok(config)
    }
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ── KeyLog bridge (inline, for the facade — avoids re-exporting crate-private) ─

use std::io::Write as _;

/// Inline key-log bridge: wraps a [`KeyLogPolicy`] and implements [`rustls::KeyLog`].
struct KeyLogBridge {
    policy: KeyLogPolicy,
}

impl KeyLogBridge {
    fn new(policy: KeyLogPolicy) -> Self {
        Self { policy }
    }
}

impl std::fmt::Debug for KeyLogBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeyLogBridge({:?})", self.policy)
    }
}

impl rustls::KeyLog for KeyLogBridge {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        match &self.policy {
            KeyLogPolicy::Disabled => {}
            KeyLogPolicy::File(path) => {
                if let Ok(mut file) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                {
                    let line = format!(
                        "{label} {cr} {s}\n",
                        cr = hex_bytes(client_random),
                        s = hex_bytes(secret),
                    );
                    let _ = file.write_all(line.as_bytes());
                }
            }
            KeyLogPolicy::Custom(arc) => {
                arc.log(label, client_random, secret);
            }
        }
    }

    fn will_log(&self, _label: &str) -> bool {
        !matches!(self.policy, KeyLogPolicy::Disabled)
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut acc, b| {
        use std::fmt::Write as _;
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

// ── PrivateKeyDer clone helper ────────────────────────────────────────────────

/// Clone a [`PrivateKeyDer`] (not natively Clone in rustls-pki-types).
fn clone_private_key_der(key: &PrivateKeyDer<'static>) -> PrivateKeyDer<'static> {
    match key {
        PrivateKeyDer::Pkcs1(k) => PrivateKeyDer::Pkcs1(k.secret_pkcs1_der().to_vec().into()),
        PrivateKeyDer::Sec1(k) => PrivateKeyDer::Sec1(k.secret_sec1_der().to_vec().into()),
        PrivateKeyDer::Pkcs8(k) => PrivateKeyDer::Pkcs8(k.secret_pkcs8_der().to_vec().into()),
        _ => panic!("unsupported PrivateKeyDer variant for cloning"),
    }
}

// ── Dangerous no-verify certificate verifier (testing only) ──────────────────

/// A certificate verifier that accepts all server certificates without
/// verification. **For testing only.**
#[derive(Debug)]
struct DangerousNoCertVerifier;

impl rustls::client::danger::ServerCertVerifier for DangerousNoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        oxitls_adapter_rustls_rustcrypto::pure_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ── Single client cert resolver ──────────────────────────────────────────────

/// A client cert resolver that always returns the same certificate chain and
/// private key. Used for `with_client_cert()` in the danger path.
struct SingleClientCertResolver {
    certified_key: Arc<rustls::sign::CertifiedKey>,
}

impl SingleClientCertResolver {
    fn new(
        certs: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<Self, TlsError> {
        let provider = oxitls_adapter_rustls_rustcrypto::pure_provider();
        let signing_key = provider
            .key_provider
            .load_private_key(key)
            .map_err(|e| TlsError::InvalidConfig(format!("failed to load client key: {e}")))?;
        let certified_key = Arc::new(rustls::sign::CertifiedKey::new(certs, signing_key));
        Ok(Self { certified_key })
    }
}

impl std::fmt::Debug for SingleClientCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SingleClientCertResolver")
            .finish_non_exhaustive()
    }
}

impl rustls::client::ResolvesClientCert for SingleClientCertResolver {
    fn resolve(
        &self,
        _acceptable_issuers: &[&[u8]],
        _sigschemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(Arc::clone(&self.certified_key))
    }

    fn has_certs(&self) -> bool {
        true
    }
}
