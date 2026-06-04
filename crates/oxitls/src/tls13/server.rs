//! TLS 1.3 server configuration builder.
//!
//! Supports single-cert, mTLS (client certificate verification), ALPN protocol
//! negotiation, and SNI-aware multi-cert dispatch — all via the Pure-Rust
//! `rustls-rustcrypto` provider, never calling `install_default()`.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rustls::{
    server::{ProducesTickets, ResolvesServerCertUsingSni},
    sign::CertifiedKey,
    ServerConfig,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

use oxitls_core::{KeyLog, KeyLogPolicy, TlsError};

// ── OCSP Response Resolver ────────────────────────────────────────────────────

/// A trait for providing OCSP responses for TLS stapling.
///
/// Implement this trait to provide dynamic OCSP responses to the TLS handshake.
/// See [`StaticOcspResolver`] for a simple static implementation.
pub trait OcspResponseResolver: Send + Sync {
    /// Return the current OCSP response DER bytes, or `None` if no response
    /// is available for stapling.
    fn ocsp_response(&self) -> Option<Vec<u8>>;
}

/// A simple static OCSP response resolver.
///
/// Always returns the same pre-computed OCSP response bytes.
///
/// # Example
/// ```no_run
/// use oxitls::StaticOcspResolver;
/// use oxitls::tls13::ServerBuilder;
/// use std::sync::Arc;
///
/// let ocsp_bytes: Vec<u8> = vec![0x30, 0x03, 0x0a, 0x01, 0x00];
/// let cfg = ServerBuilder::new()
///     .with_ocsp_response_resolver(Arc::new(StaticOcspResolver(ocsp_bytes)));
/// ```
pub struct StaticOcspResolver(pub Vec<u8>);

impl OcspResponseResolver for StaticOcspResolver {
    fn ocsp_response(&self) -> Option<Vec<u8>> {
        Some(self.0.clone())
    }
}

/// Builder for a Pure-Rust TLS server [`ServerConfig`].
///
/// Supports:
/// - Single cert/key pair (PEM or DER)
/// - mTLS: require client certificates verified against a CA root store
/// - ALPN protocol negotiation
/// - SNI-aware multi-cert dispatch
/// - Explicit TLS version selection via [`Self::with_protocol_versions`]
/// - Custom [`rustls::crypto::CryptoProvider`] via [`Self::with_provider`]
///
/// Default protocol: TLS 1.3 only. Use `with_protocol_versions` to allow TLS 1.2 as well.
/// Default provider: Pure-Rust `rustls-rustcrypto`. Use `with_provider` to inject an
/// alternative (e.g. `aws_lc_provider()` from `oxitls::aws_lc`).
///
/// # Example
/// ```no_run
/// # async fn example() -> Result<(), oxitls_core::TlsError> {
/// use oxitls::tls13::ServerBuilder;
///
/// let config = ServerBuilder::new()
///     .with_pem_cert_and_key(CERT_PEM, KEY_PEM)?
///     .with_alpn_protocols(["h2", "http/1.1"])
///     .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
///     .build()?;
/// # Ok(())
/// # }
/// # const CERT_PEM: &[u8] = b"";
/// # const KEY_PEM: &[u8] = b"";
/// ```
pub struct ServerBuilder {
    /// PEM or DER cert chain + private key loaded via `with_pem_cert_and_key` or `with_der_cert_and_key`.
    certs: Option<Vec<CertificateDer<'static>>>,
    key: Option<PrivateKeyDer<'static>>,
    /// mTLS: CA root store for client certificate verification (deferred to `build()`).
    /// When set, mutual TLS is required.
    client_verifier_roots: Option<rustls::RootCertStore>,
    /// ALPN protocol list; empty means no ALPN extension.
    alpn: Vec<Vec<u8>>,
    /// SNI name → certified key map; when non-empty the SNI resolver is used.
    sni_map: Vec<(String, CertifiedKey)>,
    /// Explicit TLS protocol versions; `None` → TLS 1.3 only.
    protocol_versions: Option<Vec<&'static rustls::SupportedProtocolVersion>>,
    /// Optional session-ticket encryptor/decryptor (server-side resumption).
    ticketer: Option<Arc<dyn ProducesTickets>>,
    /// Optional auto-rotating ticketer: a concrete [`OxiTicketer`] paired with
    /// the rotation interval.  When set, `build()` installs the ticketer as
    /// `config.ticketer` **and** spawns a background tokio task that calls
    /// `OxiTicketer::rotate()` on each interval tick.
    ///
    /// Setting this field clears `ticketer`; setting `ticketer` clears this
    /// field (last-write-wins mutual exclusion).
    ///
    /// [`OxiTicketer`]: crate::ticketer::OxiTicketer
    rotation_ticketer: Option<(Arc<crate::ticketer::OxiTicketer>, Duration)>,
    /// Optional OCSP response to staple to the handshake.
    ocsp_response: Option<Vec<u8>>,
    /// Optional maximum TLS record fragment size (bytes).
    max_fragment_size: Option<usize>,
    /// Optional maximum early data (0-RTT) size in bytes.
    max_early_data_size: Option<u32>,
    /// Optional injected [`rustls::crypto::CryptoProvider`].
    /// When `None`, defaults to `oxitls_adapter_rustls_rustcrypto::pure_provider()`
    /// (or the post-quantum variant when the `post-quantum` feature is enabled).
    provider: Option<Arc<rustls::crypto::CryptoProvider>>,
    /// Raw public key to present to clients (RFC 7250) instead of an X.509 cert chain.
    ///
    /// When set, the normal single-cert / SNI-cert resolver is bypassed and the server
    /// advertises raw public key support, presenting this key material.  Takes precedence
    /// over `certs`/`key` and `sni_map` when configured.
    server_raw_public_key: Option<Arc<rustls::sign::CertifiedKey>>,
    /// Trusted client SPKIs for raw-public-key mutual TLS (RFC 7250 mTLS analogue).
    ///
    /// When set, clients must authenticate by presenting a raw public key whose SPKI
    /// matches one of the entries in this list.  Overrides the standard
    /// `client_verifier_roots`-based WebPKI client verifier.
    client_raw_public_keys: Option<Vec<rustls::pki_types::SubjectPublicKeyInfoDer<'static>>>,
    /// Optional key-log policy for TLS session secret export (SSLKEYLOGFILE).
    key_log_policy: Option<KeyLogPolicy>,
    /// Enable RFC 8879 TLS certificate compression (zlib, OxiARC).
    ///
    /// When `true`, `build()` installs the OxiARC zlib compressor/decompressor
    /// on the produced `ServerConfig`.  Requires the `cert-compression` feature.
    #[cfg(feature = "cert-compression")]
    enable_cert_compression: bool,
}

impl ServerBuilder {
    /// Create a new, empty builder.
    pub fn new() -> Self {
        Self {
            certs: None,
            key: None,
            client_verifier_roots: None,
            alpn: Vec::new(),
            sni_map: Vec::new(),
            protocol_versions: None,
            ticketer: None,
            rotation_ticketer: None,
            ocsp_response: None,
            max_fragment_size: None,
            max_early_data_size: None,
            provider: None,
            server_raw_public_key: None,
            client_raw_public_keys: None,
            key_log_policy: None,
            #[cfg(feature = "cert-compression")]
            enable_cert_compression: false,
        }
    }

    /// Load the certificate chain and private key from PEM-encoded bytes.
    ///
    /// The cert PEM may contain a full chain; only the first valid private key
    /// in `key_pem` is used.
    pub fn with_pem_cert_and_key(
        mut self,
        cert_pem: &[u8],
        key_pem: &[u8],
    ) -> Result<Self, TlsError> {
        let certs: Vec<CertificateDer<'static>> =
            rustls_pemfile::certs(&mut std::io::BufReader::new(cert_pem))
                .map(|r| r.map_err(|e| TlsError::BadCert(e.to_string())))
                .collect::<Result<_, _>>()?;
        if certs.is_empty() {
            return Err(TlsError::BadCert("no certificates found in PEM".into()));
        }

        let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(key_pem))
            .map_err(|e| TlsError::InvalidConfig(e.to_string()))?
            .ok_or_else(|| TlsError::BadCert("no private key found in PEM".into()))?;

        self.certs = Some(certs);
        self.key = Some(key);
        Ok(self)
    }

    /// Load the certificate chain and private key from DER-encoded bytes.
    ///
    /// Useful in tests where rcgen produces DER directly.
    pub fn with_der_cert_and_key(
        mut self,
        cert_chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Self {
        self.certs = Some(cert_chain);
        self.key = Some(key);
        self
    }

    /// Enable mTLS: require client certificates verified by the given CA roots.
    ///
    /// Uses [`rustls::server::WebPkiClientVerifier`] with the configured provider
    /// (defaulting to the Pure-Rust provider when none is set via
    /// [`with_provider`](Self::with_provider)) — never calls `install_default()`.
    ///
    /// Verifier construction is deferred to [`build()`](Self::build) so that
    /// the provider injected via `with_provider` is consistently applied to both
    /// the verifier and the server config, regardless of call order.
    pub fn with_client_cert_verifier(mut self, roots: rustls::RootCertStore) -> Self {
        self.client_verifier_roots = Some(roots);
        self
    }

    /// Inject a custom [`rustls::crypto::CryptoProvider`].
    ///
    /// When not called, `build()` defaults to
    /// `oxitls_adapter_rustls_rustcrypto::pure_provider()` (Pure-Rust, no C deps).
    ///
    /// Call this **before** or **after** other builder methods — the provider is
    /// resolved once at `build()` time and applied uniformly to the server config
    /// and any client-cert verifier.
    ///
    /// # Example
    /// ```no_run
    /// # fn example() -> Result<(), oxitls_core::TlsError> {
    /// use std::sync::Arc;
    /// use oxitls::tls13::ServerBuilder;
    ///
    /// // Use the default Pure-Rust provider explicitly:
    /// let provider = oxitls_adapter_rustls_rustcrypto::pure_provider();
    /// let config = ServerBuilder::new()
    ///     .with_provider(provider)
    ///     // ... cert/key ...
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_provider(mut self, provider: Arc<rustls::crypto::CryptoProvider>) -> Self {
        self.provider = Some(provider);
        self
    }

    /// Announce ALPN protocols the server is willing to negotiate.
    ///
    /// Call with, e.g., `["h2", "http/1.1"]`.
    pub fn with_alpn_protocols(
        mut self,
        protocols: impl IntoIterator<Item = impl AsRef<[u8]>>,
    ) -> Self {
        self.alpn = protocols.into_iter().map(|p| p.as_ref().to_vec()).collect();
        self
    }

    /// Register a named (`CertifiedKey`) for SNI-based dispatch.
    ///
    /// When at least one SNI cert is registered the server will use
    /// [`ResolvesServerCertUsingSni`] instead of the single-cert fallback.
    /// The `server_name` must match a SAN in the `key`'s certificate.
    pub fn with_sni_cert(mut self, server_name: impl Into<String>, key: CertifiedKey) -> Self {
        self.sni_map.push((server_name.into(), key));
        self
    }

    /// Explicitly set the allowed TLS versions for this server.
    ///
    /// By default only TLS 1.3 is offered. Pass
    /// `&[&rustls::version::TLS13, &rustls::version::TLS12]` to allow TLS 1.2
    /// as a fallback.
    pub fn with_protocol_versions(
        mut self,
        versions: &[&'static rustls::SupportedProtocolVersion],
    ) -> Self {
        self.protocol_versions = Some(versions.to_vec());
        self
    }

    /// Install a session-ticket encryptor for server-side session resumption.
    ///
    /// Pass an `Arc<dyn ProducesTickets>` — typically an [`OxiTicketer`]:
    ///
    /// ```no_run
    /// # use std::sync::Arc;
    /// # use oxitls::ticketer::OxiTicketer;
    /// # use oxitls::tls13::ServerBuilder;
    /// # fn example() -> Result<(), oxitls_core::TlsError> {
    /// let ticketer = Arc::new(OxiTicketer::new()?);
    /// let config = ServerBuilder::new()
    ///     // ... cert/key ...
    ///     .with_ticketer(ticketer)
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Without calling this method the server sends no session tickets and
    /// resumption falls back to client-side session IDs (or none).
    ///
    /// Calling this method clears any rotation ticketer previously set with
    /// [`with_ticketer_rotation_interval`](Self::with_ticketer_rotation_interval)
    /// (last-write-wins semantics).
    ///
    /// [`OxiTicketer`]: crate::ticketer::OxiTicketer
    pub fn with_ticketer(mut self, ticketer: Arc<dyn ProducesTickets>) -> Self {
        self.ticketer = Some(ticketer);
        // Clear any pending rotation ticketer — last-write-wins.
        self.rotation_ticketer = None;
        self
    }

    /// Wrap the configured ticketer (or a default [`OxiTicketer`][crate::ticketer::OxiTicketer]) with RFC 8446
    /// §8 single-use replay protection to guard 0-RTT early data.
    ///
    /// See [`AntiReplayTicketer`][crate::anti_replay::AntiReplayTicketer] for
    /// details on the protection mechanism.
    ///
    /// # Errors
    ///
    /// Returns an error only if no ticketer is configured AND `OxiTicketer::new()`
    /// fails (OS RNG unavailable).
    #[cfg(feature = "pure")]
    pub fn with_anti_replay(mut self) -> Result<Self, crate::TlsError> {
        use crate::anti_replay::{AntiReplayTicketer, ArcTicketer};

        let ticketer: Arc<dyn ProducesTickets> = match self.ticketer.take() {
            Some(t) => t,
            None => Arc::new(crate::ticketer::OxiTicketer::new()?),
        };
        self.ticketer = Some(Arc::new(AntiReplayTicketer::new(ArcTicketer(ticketer))));
        Ok(self)
    }

    /// Set a static OCSP response to staple to the TLS handshake.
    ///
    /// The bytes are attached to the server's `CertifiedKey` so that rustls
    /// sends them in the `CertificateStatus` message during the handshake.
    pub fn with_ocsp_response(mut self, ocsp_der: Vec<u8>) -> Self {
        self.ocsp_response = Some(ocsp_der);
        self
    }

    /// Set an `OcspResponseResolver` for dynamic OCSP stapling.
    ///
    /// The resolver is called before each handshake to obtain the current OCSP
    /// response. If `None` is returned, no staple is sent.
    ///
    /// See [`crate::StaticOcspResolver`] for a simple static implementation.
    pub fn with_ocsp_response_resolver(mut self, resolver: Arc<dyn OcspResponseResolver>) -> Self {
        // For a static resolver, use its response as the staple.
        if let Some(bytes) = resolver.ocsp_response() {
            self.ocsp_response = Some(bytes);
        }
        self
    }

    /// Set the maximum TLS record fragment size (bytes).
    ///
    /// This maps to `rustls::ServerConfig::max_fragment_size`. Values outside
    /// the range [64, 16384] may be rejected by rustls.
    pub fn with_max_fragment_size(mut self, size: Option<usize>) -> Self {
        self.max_fragment_size = size;
        self
    }

    /// Set the maximum 0-RTT early data size in bytes.
    ///
    /// Maps to `rustls::ServerConfig::max_early_data_size`. A value of 0
    /// (the default) disables early data.
    pub fn with_max_early_data_size(mut self, size: u32) -> Self {
        self.max_early_data_size = Some(size);
        self
    }

    /// Present a raw public key (RFC 7250) to clients instead of an X.509 certificate chain.
    ///
    /// When set, the server uses a raw-public-key resolver built from the given
    /// `CertifiedKey`, bypassing the normal X.509 certificate chain.  Clients must
    /// negotiate raw public key support and pin the expected SPKI.
    ///
    /// Takes precedence over certs/key loaded via `with_pem_cert_and_key`,
    /// `with_der_cert_and_key`, or the SNI map configured with `with_sni_cert`.
    pub fn with_server_raw_public_key(
        mut self,
        certified_key: Arc<rustls::sign::CertifiedKey>,
    ) -> Self {
        self.server_raw_public_key = Some(certified_key);
        self
    }

    /// Require clients to authenticate with a raw public key (RFC 7250 mTLS equivalent).
    ///
    /// When set, the client verifier is replaced with a raw-public-key verifier that
    /// accepts only clients presenting one of the supplied SPKIs.  Overrides any
    /// roots configured via [`with_client_cert_verifier`](Self::with_client_cert_verifier).
    pub fn with_client_raw_public_keys(
        mut self,
        trusted_spki: Vec<rustls::pki_types::SubjectPublicKeyInfoDer<'static>>,
    ) -> Self {
        self.client_raw_public_keys = Some(trusted_spki);
        self
    }

    /// Install an [`OxiTicketer`] with automatic key rotation on the given interval.
    ///
    /// Creates a fresh [`OxiTicketer`] (AES-256-GCM, 32-byte keys from OS entropy)
    /// and arranges for its keys to be rotated every `interval` by a detached
    /// background tokio task.  The rotation task holds a **weak** reference to the
    /// ticketer; it exits automatically when the last strong reference (held by the
    /// produced `ServerConfig`) is dropped, so no manual cancellation is needed.
    ///
    /// # Key rotation semantics
    ///
    /// On each tick the old *current* key becomes the *previous* key (kept for one
    /// cycle so in-flight tickets remain decryptable) and a fresh random key becomes
    /// the new *current* key.  See [`OxiTicketer::rotate`] for details.
    ///
    /// # Tokio runtime requirement
    ///
    /// [`build()`](Self::build) spawns the rotation task via `tokio::spawn`.  It
    /// must therefore be called from within a tokio async context.  If no runtime
    /// is present the spawn will panic; use [`with_ticketer`](Self::with_ticketer)
    /// directly for non-async build contexts.
    ///
    /// # Minimum interval
    ///
    /// Intervals shorter than 1 second are clamped to 1 second to prevent
    /// accidental busy-loops.
    ///
    /// # Errors from the background task
    ///
    /// Rotation failures (OS RNG unavailable) are logged at `WARN` level via
    /// `tracing` and do not stop the loop — the server continues to use its
    /// current key set.
    ///
    /// # Mutual exclusion with `with_ticketer`
    ///
    /// Calling this method clears any ticketer previously set with
    /// [`with_ticketer`](Self::with_ticketer) (last-write-wins semantics).
    /// Calling `with_ticketer` after this method clears the rotation ticketer.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), oxitls_core::TlsError> {
    /// use std::time::Duration;
    /// use oxitls::tls13::ServerBuilder;
    ///
    /// let config = ServerBuilder::new()
    ///     // ... cert/key ...
    ///     .with_ticketer_rotation_interval(Duration::from_secs(3600))
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// [`OxiTicketer`]: crate::ticketer::OxiTicketer
    /// [`OxiTicketer::rotate`]: crate::ticketer::OxiTicketer::rotate
    pub fn with_ticketer_rotation_interval(mut self, interval: Duration) -> Self {
        match crate::ticketer::OxiTicketer::new() {
            Ok(ticketer) => {
                let arc = Arc::new(ticketer);
                self.rotation_ticketer = Some((arc, interval));
                // Clear any plain ticketer — last-write-wins.
                self.ticketer = None;
            }
            Err(_) => {
                // OS RNG unavailable: skip ticketer installation entirely.
                // Callers that need explicit error handling should use
                // `OxiTicketer::new()` + `with_ticketer()` directly.
            }
        }
        self
    }

    /// Alias for [`with_pem_cert_and_key`](Self::with_pem_cert_and_key).
    ///
    /// The name `with_pem_cert_chain_and_key` is provided for API symmetry
    /// with tooling that generates full PEM chains.
    pub fn with_pem_cert_chain_and_key(
        self,
        cert_pem: impl AsRef<[u8]>,
        key_pem: impl AsRef<[u8]>,
    ) -> Result<Self, TlsError> {
        self.with_pem_cert_and_key(cert_pem.as_ref(), key_pem.as_ref())
    }

    /// Write TLS session secrets to a file in NSS key-log format (SSLKEYLOGFILE).
    ///
    /// The file is created and appended to on each handshake. Silently ignores
    /// I/O errors so a logging failure never takes down the TLS handshake.
    ///
    /// This is useful for decrypting TLS traffic in Wireshark or mitmproxy
    /// during development and debugging.
    pub fn with_key_log_file(mut self, path: PathBuf) -> Self {
        self.key_log_policy = Some(KeyLogPolicy::File(path));
        self
    }

    /// Install a custom key-log sink implementing [`KeyLog`].
    ///
    /// Use this to forward session secrets to a custom destination (e.g. an
    /// in-memory buffer for testing or a structured logger).
    pub fn with_key_log_custom(mut self, arc: Arc<dyn KeyLog + Send + Sync>) -> Self {
        self.key_log_policy = Some(KeyLogPolicy::Custom(arc));
        self
    }

    /// Enable RFC 8879 TLS certificate compression using OxiARC pure-Rust zlib.
    ///
    /// When enabled, the produced `ServerConfig` will have its `cert_compressors`
    /// and `cert_decompressors` set to the OxiARC zlib implementations.
    /// Cert compression only applies to TLS 1.3; rustls ignores it for TLS 1.2.
    ///
    /// Requires the `cert-compression` feature.
    #[cfg(feature = "cert-compression")]
    pub fn with_cert_compression(mut self) -> Self {
        self.enable_cert_compression = true;
        self
    }

    /// Build the final [`ServerConfig`].
    ///
    /// # Errors
    /// Returns [`TlsError::InvalidConfig`] or [`TlsError::BadCert`] on
    /// misconfiguration.
    pub fn build(self) -> Result<ServerConfig, TlsError> {
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

        // Wire protocol versions: default = TLS 1.3 only.
        let versions: &[&rustls::SupportedProtocolVersion] = match self.protocol_versions {
            Some(ref v) => v.as_slice(),
            None => &[&rustls::version::TLS13],
        };
        let builder_base = ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(versions)
            .map_err(|e| TlsError::InvalidConfig(e.to_string()))?;

        // Wire client-auth verifier.
        // RPK client verifier takes precedence over the standard WebPKI client verifier.
        // The verifier is built here (deferred from with_client_cert_verifier) so
        // the same resolved provider is applied to both the verifier and the config.
        let with_verifier = if let Some(spki_list) = self.client_raw_public_keys {
            use oxitls_adapter_rustls_rustcrypto::verifier::raw_public_key::RawPublicKeyClientVerifier;
            let verifier = Arc::new(RawPublicKeyClientVerifier::new(spki_list, provider.clone()));
            builder_base.with_client_cert_verifier(verifier)
        } else {
            match self.client_verifier_roots {
                Some(roots) => {
                    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
                        Arc::new(roots),
                        provider.clone(),
                    )
                    .build()
                    .map_err(|e| TlsError::InvalidConfig(e.to_string()))?;
                    builder_base.with_client_cert_verifier(verifier)
                }
                None => builder_base.with_no_client_auth(),
            }
        };

        // Wire certs: RPK resolver takes precedence over SNI multi-cert and single-cert.
        let mut config = if let Some(rpk_key) = self.server_raw_public_key {
            use oxitls_adapter_rustls_rustcrypto::verifier::raw_public_key::server_raw_public_key_resolver;
            let resolver = server_raw_public_key_resolver(rpk_key);
            with_verifier.with_cert_resolver(resolver)
        } else if !self.sni_map.is_empty() {
            let mut resolver = ResolvesServerCertUsingSni::new();
            for (name, ck) in self.sni_map {
                resolver
                    .add(&name, ck)
                    .map_err(|e| TlsError::InvalidConfig(e.to_string()))?;
            }
            with_verifier.with_cert_resolver(Arc::new(resolver))
        } else {
            let certs = self
                .certs
                .ok_or_else(|| TlsError::InvalidConfig("no certificate configured".into()))?;
            let key = self
                .key
                .ok_or_else(|| TlsError::InvalidConfig("no private key configured".into()))?;
            if let Some(ocsp) = self.ocsp_response {
                with_verifier
                    .with_single_cert_with_ocsp(certs, key, ocsp)
                    .map_err(|e| TlsError::BadCert(e.to_string()))?
            } else {
                with_verifier
                    .with_single_cert(certs, key)
                    .map_err(|e| TlsError::BadCert(e.to_string()))?
            }
        };

        config.alpn_protocols = self.alpn;

        // Install ticketer: rotation_ticketer takes priority (last-write-wins semantics
        // are enforced by the builder methods; at this point at most one is Some).
        if let Some((ticketer_arc, interval)) = self.rotation_ticketer {
            // Clamp to a 1-second minimum to prevent accidental busy-loops.
            let effective_interval = interval.max(Duration::from_secs(1));

            // Install the concrete ticketer as the config's dyn ProducesTickets.
            config.ticketer = Arc::clone(&ticketer_arc) as Arc<dyn ProducesTickets>;

            // Spawn the rotation background task.  We use a Weak reference so
            // the task exits automatically once the ServerConfig (and all its
            // clones) are dropped — preventing a permanent key-material leak.
            let weak = Arc::downgrade(&ticketer_arc);
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(effective_interval);
                // Skip the first (immediate) tick — no rotation needed at t=0.
                ticker.tick().await;
                loop {
                    ticker.tick().await;
                    match weak.upgrade() {
                        None => {
                            // All ServerConfig clones have been dropped; stop.
                            break;
                        }
                        Some(strong) => {
                            if let Err(e) = strong.rotate() {
                                tracing::warn!("OxiTicketer rotation failed (OS RNG error): {}", e);
                                // Continue looping — will retry on next tick.
                            }
                        }
                    }
                }
            });
        } else if let Some(ticketer) = self.ticketer {
            config.ticketer = ticketer;
        }

        if let Some(size) = self.max_fragment_size {
            config.max_fragment_size = Some(size);
        }
        if let Some(size) = self.max_early_data_size {
            config.max_early_data_size = size;
        }
        if let Some(policy) = self.key_log_policy {
            config.key_log = Arc::new(ServerKeyLogBridge::new(policy));
        }

        // RFC 8879 certificate compression (TLS 1.3 only).
        #[cfg(feature = "cert-compression")]
        if self.enable_cert_compression {
            oxitls_adapter_rustls_rustcrypto::install_cert_compression_server(&mut config);
        }

        Ok(config)
    }
}

impl Default for ServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ── Clone helper (PrivateKeyDer is not natively Clone in rustls-pki-types) ────

fn clone_private_key_der(key: &PrivateKeyDer<'static>) -> PrivateKeyDer<'static> {
    match key {
        PrivateKeyDer::Pkcs1(k) => PrivateKeyDer::Pkcs1(k.secret_pkcs1_der().to_vec().into()),
        PrivateKeyDer::Sec1(k) => PrivateKeyDer::Sec1(k.secret_sec1_der().to_vec().into()),
        PrivateKeyDer::Pkcs8(k) => PrivateKeyDer::Pkcs8(k.secret_pkcs8_der().to_vec().into()),
        _ => {
            // Future-proofing: non-exhaustive pattern. Fall back to PKCS#8 empty key
            // rather than panic — a build error will surface the misconfiguration.
            PrivateKeyDer::Pkcs8(vec![].into())
        }
    }
}

impl Clone for ServerBuilder {
    fn clone(&self) -> Self {
        Self {
            certs: self.certs.clone(),
            key: self.key.as_ref().map(clone_private_key_der),
            client_verifier_roots: self.client_verifier_roots.clone(),
            alpn: self.alpn.clone(),
            sni_map: self.sni_map.clone(),
            protocol_versions: self.protocol_versions.clone(),
            ticketer: self.ticketer.clone(),
            rotation_ticketer: self.rotation_ticketer.clone(),
            ocsp_response: self.ocsp_response.clone(),
            max_fragment_size: self.max_fragment_size,
            max_early_data_size: self.max_early_data_size,
            provider: self.provider.clone(),
            server_raw_public_key: self.server_raw_public_key.clone(),
            client_raw_public_keys: self.client_raw_public_keys.clone(),
            key_log_policy: self.key_log_policy.clone(),
            #[cfg(feature = "cert-compression")]
            enable_cert_compression: self.enable_cert_compression,
        }
    }
}

/// Wrap a [`ServerConfig`] in a [`tokio_rustls::TlsAcceptor`].
///
/// Convenience shorthand for `tokio_rustls::TlsAcceptor::from(Arc::new(config))`.
pub fn tokio_acceptor(config: ServerConfig) -> tokio_rustls::TlsAcceptor {
    tokio_rustls::TlsAcceptor::from(Arc::new(config))
}

// ── ServerKeyLog bridge ─────────────────────────────────────────────────────

/// Inline key-log bridge for the server: wraps a [`KeyLogPolicy`] and implements
/// [`rustls::KeyLog`].
struct ServerKeyLogBridge {
    policy: KeyLogPolicy,
}

impl ServerKeyLogBridge {
    fn new(policy: KeyLogPolicy) -> Self {
        Self { policy }
    }
}

impl std::fmt::Debug for ServerKeyLogBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ServerKeyLogBridge({:?})", self.policy)
    }
}

impl rustls::KeyLog for ServerKeyLogBridge {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        match &self.policy {
            KeyLogPolicy::Disabled => {}
            KeyLogPolicy::File(path) => {
                use std::io::Write;
                let line = format!(
                    "{label} {cr} {s}\n",
                    cr = server_hex_bytes(client_random),
                    s = server_hex_bytes(secret),
                );
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                {
                    let _ = f.write_all(line.as_bytes());
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

fn server_hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut acc, b| {
        use std::fmt::Write as _;
        let _ = write!(acc, "{b:02x}");
        acc
    })
}
