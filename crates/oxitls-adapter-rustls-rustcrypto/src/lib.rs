#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! Pure-Rust TLS via rustls + RustCrypto CryptoProvider.
//!
//! Never calls `CryptoProvider::install_default()`. Always injects the provider
//! per-config via `builder_with_provider`.

use std::io;
use std::sync::Arc;

pub use rustls::{ClientConfig, RootCertStore, ServerConfig};
pub use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};

pub use oxitls_core::TlsError;

// ── Modules ───────────────────────────────────────────────────────────────────

pub(crate) mod keylog_bridge;

/// Post-quantum hybrid key exchange (X25519MLKEM768).
///
/// Only compiled when the `post-quantum` feature is enabled.
#[cfg(feature = "post-quantum")]
pub mod kx;

/// HPKE (RFC 9180) base-mode provider for Encrypted Client Hello.
///
/// Only compiled when the `ech` feature is enabled.
#[cfg(feature = "ech")]
pub mod hpke;

/// RFC 8879 TLS certificate compression backed by OxiARC pure-Rust zlib.
///
/// Only compiled when the `cert-compression` feature is enabled.
#[cfg(feature = "cert-compression")]
pub mod cert_compression;

#[cfg(feature = "cert-compression")]
pub use cert_compression::{
    install_cert_compression_client, install_cert_compression_server, OXIARC_ZLIB_COMPRESSOR,
    OXIARC_ZLIB_DECOMPRESSOR,
};

/// Fluent builders for `ClientConfig` and `ServerConfig`.
pub mod client_builder;
pub mod server_builder;

/// Custom server-certificate verifier implementations.
pub mod verifier;

pub use client_builder::RustcryptoClientConfigBuilder;
pub use server_builder::RustcryptoServerConfigBuilder;

#[cfg(feature = "post-quantum")]
pub use kx::X25519MLKEM768;

#[cfg(feature = "ech")]
pub use hpke::pure_hpke_suites;

#[cfg(feature = "ech")]
pub use hpke::{
    AeadAes128Gcm, AeadChacha20, HpkeOpenerCtx, HpkeSealerCtx, KemP256, KemX25519,
    HPKE_P256_HKDF_SHA256_AES128GCM, HPKE_P256_HKDF_SHA256_CHACHA20,
    HPKE_X25519_HKDF_SHA256_AES128GCM, HPKE_X25519_HKDF_SHA256_CHACHA20,
};

#[cfg(feature = "ech")]
pub use hpke::ech_config::{generate_ech_config_list, GeneratedEchConfig};

// ── Verifier re-exports ───────────────────────────────────────────────────────

pub use verifier::ct_logs::known_ct_logs;
pub use verifier::ocsp_client::OcspClientPolicy;
pub use verifier::sct::{CtKeyAlg, CtLog, CtLogList, SctPolicy};

// ── Provider ─────────────────────────────────────────────────────────────────

/// Returns the Pure-Rust rustls `CryptoProvider` backed by rustls-rustcrypto.
///
/// Does not call `install_default()` — for per-config injection only.
pub fn pure_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls_rustcrypto::provider())
}

/// Returns the Pure-Rust rustls `CryptoProvider` with X25519MLKEM768 prepended.
///
/// X25519MLKEM768 is inserted at index 0 so it is offered first in TLS 1.3
/// `ClientHello` key-share messages.  Plain X25519 (and other classical groups)
/// remain available via the standard `SupportedKxGroup` list, allowing
/// interoperability with servers that do not support hybrid PQ.
///
/// Does not call `install_default()` — for per-config injection only.
#[cfg(feature = "post-quantum")]
pub fn pure_provider_with_pq() -> Arc<rustls::crypto::CryptoProvider> {
    let mut provider = rustls_rustcrypto::provider();
    provider.kx_groups.insert(0, kx::X25519MLKEM768);
    Arc::new(provider)
}

// ── Config builders ──────────────────────────────────────────────────────────

/// Build a rustls `ClientConfig` using the RustCrypto provider.
///
/// Does not call `install_default()` — the provider is injected per-config.
pub fn client_config(root_store: RootCertStore) -> Result<Arc<ClientConfig>, TlsError> {
    let provider = pure_provider();
    let cfg = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| TlsError::InvalidConfig(e.to_string()))?
        .with_root_certificates(root_store)
        .with_no_client_auth();
    Ok(Arc::new(cfg))
}

/// Build a rustls `ServerConfig` from a certificate chain and private key.
///
/// Does not call `install_default()` — the provider is injected per-config.
pub fn server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<ServerConfig>, TlsError> {
    let provider = pure_provider();
    let cfg = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| TlsError::InvalidConfig(e.to_string()))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| TlsError::BadCert(e.to_string()))?;
    Ok(Arc::new(cfg))
}

// ── Introspection ────────────────────────────────────────────────────────────

/// Return the list of cipher suites supported by the Pure-Rust provider.
///
/// Each entry is the human-readable name of a `rustls::SupportedCipherSuite`.
pub fn supported_cipher_suites() -> Vec<&'static str> {
    let provider = rustls_rustcrypto::provider();
    provider
        .cipher_suites
        .iter()
        .map(|cs| cs.suite().as_str().unwrap_or("unknown"))
        .collect()
}

/// Return the list of TLS protocol versions supported by the Pure-Rust
/// provider.
///
/// Typically `["TLSv1_3", "TLSv1_2"]` for rustls-rustcrypto with `tls12`
/// feature enabled.
pub fn supported_versions() -> Vec<String> {
    let versions = rustls::ALL_VERSIONS;
    versions
        .iter()
        .map(|v| format!("{:?}", v.version))
        .collect()
}

/// Extract [`oxitls_core::ConnectionInfo`] from a completed rustls
/// `CommonState`.
///
/// This is typically called after a TLS handshake completes, passing the
/// session state from `tls_stream.get_ref().1`.
pub fn connection_info_from_state(state: &rustls::CommonState) -> oxitls_core::ConnectionInfo {
    let version = state.protocol_version().and_then(|pv| match pv {
        rustls::ProtocolVersion::TLSv1_2 => Some(oxitls_core::TlsVersion::Tls12),
        rustls::ProtocolVersion::TLSv1_3 => Some(oxitls_core::TlsVersion::Tls13),
        _ => None,
    });

    let cipher_suite = state
        .negotiated_cipher_suite()
        .and_then(|cs| map_cipher_suite(cs.suite()));

    let alpn = state.alpn_protocol().map(|p| p.to_vec());

    let mut info = oxitls_core::ConnectionInfo::new();
    if let Some(v) = version {
        info = info.with_version(v);
    }
    if let Some(cs) = cipher_suite {
        info = info.with_cipher_suite(cs);
    }
    if let Some(a) = alpn {
        info = info.with_alpn_protocol(a);
    }
    // Peer certificates and SNI require the server-side `ServerConnection` or
    // `ClientConnection` respectively; CommonState does not expose them directly.
    // Adapter callers can extend ConnectionInfo after this call.
    info
}

/// Map a rustls `CipherSuite` identifier to our `oxitls_core::CipherSuite`.
fn map_cipher_suite(suite: rustls::CipherSuite) -> Option<oxitls_core::CipherSuite> {
    use rustls::CipherSuite as Rcs;
    match suite {
        Rcs::TLS13_AES_128_GCM_SHA256 => Some(oxitls_core::CipherSuite::Tls13Aes128GcmSha256),
        Rcs::TLS13_AES_256_GCM_SHA384 => Some(oxitls_core::CipherSuite::Tls13Aes256GcmSha384),
        Rcs::TLS13_CHACHA20_POLY1305_SHA256 => {
            Some(oxitls_core::CipherSuite::Tls13Chacha20Poly1305Sha256)
        }
        Rcs::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => {
            Some(oxitls_core::CipherSuite::Tls12EcdheEcdsaAes128GcmSha256)
        }
        Rcs::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => {
            Some(oxitls_core::CipherSuite::Tls12EcdheEcdsaAes256GcmSha384)
        }
        Rcs::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => {
            Some(oxitls_core::CipherSuite::Tls12EcdheRsaAes128GcmSha256)
        }
        Rcs::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => {
            Some(oxitls_core::CipherSuite::Tls12EcdheRsaAes256GcmSha384)
        }
        Rcs::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => {
            Some(oxitls_core::CipherSuite::Tls12EcdheEcdsaChacha20Poly1305Sha256)
        }
        Rcs::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => {
            Some(oxitls_core::CipherSuite::Tls12EcdheRsaChacha20Poly1305Sha256)
        }
        _ => None,
    }
}

// ── Connector / Acceptor ─────────────────────────────────────────────────────

/// TLS connector wrapping `tokio-rustls`.
pub struct RustcryptoConnector {
    inner: tokio_rustls::TlsConnector,
}

impl RustcryptoConnector {
    /// Create a connector from a `ClientConfig`.
    pub fn new(cfg: Arc<ClientConfig>) -> Self {
        Self {
            inner: tokio_rustls::TlsConnector::from(cfg),
        }
    }

    /// Connect to `stream` using the given server name.
    pub async fn connect<S>(
        &self,
        server_name: ServerName<'static>,
        stream: S,
    ) -> Result<tokio_rustls::client::TlsStream<S>, io::Error>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        self.inner.connect(server_name, stream).await
    }

    /// Convenience: connect to a TCP stream using a hostname string as SNI.
    ///
    /// Parses `host` into a [`ServerName`], performs the TLS handshake, and
    /// returns a [`RustcryptoClientStream`] with [`oxitls_core::ConnectionInfo`]
    /// pre-populated.
    pub async fn connect_tcp(
        &self,
        host: &str,
        stream: tokio::net::TcpStream,
    ) -> Result<RustcryptoClientStream, TlsError> {
        let sni = ServerName::try_from(host.to_string())
            .map_err(|e| TlsError::InvalidConfig(format!("invalid SNI: {e}")))?;
        let tls = self
            .inner
            .connect(sni, stream)
            .await
            .map_err(|e| TlsError::Handshake(e.to_string()))?;
        let info = connection_info_from_state(tls.get_ref().1);
        Ok(RustcryptoClientStream { inner: tls, info })
    }
}

impl oxitls_core::TlsConnector for RustcryptoConnector {
    fn connect(
        &self,
        stream: oxitls_core::TlsStream,
        server_name: rustls_pki_types::ServerName<'static>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<oxitls_core::TlsStream, TlsError>> + Send + '_>,
    > {
        Box::pin(async move {
            let tls = self
                .inner
                .connect(server_name, stream)
                .await
                .map_err(|e| TlsError::Handshake(e.to_string()))?;
            Ok(Box::new(tls) as oxitls_core::TlsStream)
        })
    }
}

/// A TLS client stream with cached [`oxitls_core::ConnectionInfo`].
///
/// Returned by [`RustcryptoConnector::connect_tcp`] and
/// [`connect_with_alpn`]. Implements [`oxitls_core::TlsStreamInfo`] by
/// eagerly extracting the connection metadata after the handshake.
pub struct RustcryptoClientStream {
    inner: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    info: oxitls_core::ConnectionInfo,
}

impl oxitls_core::TlsStreamInfo for RustcryptoClientStream {
    fn connection_info(&self) -> Option<&oxitls_core::ConnectionInfo> {
        Some(&self.info)
    }
}

impl tokio::io::AsyncRead for RustcryptoClientStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for RustcryptoClientStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// TLS acceptor wrapping `tokio-rustls`.
pub struct RustcryptoAcceptor {
    inner: tokio_rustls::TlsAcceptor,
}

impl RustcryptoAcceptor {
    /// Create an acceptor from a `ServerConfig`.
    pub fn new(cfg: Arc<ServerConfig>) -> Self {
        Self {
            inner: tokio_rustls::TlsAcceptor::from(cfg),
        }
    }

    /// Accept a TLS handshake on `stream`.
    pub async fn accept<S>(
        &self,
        stream: S,
    ) -> Result<tokio_rustls::server::TlsStream<S>, io::Error>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        self.inner.accept(stream).await
    }

    /// Convenience: accept a TLS handshake on a raw TCP stream.
    ///
    /// Delegates to [`Self::accept`] with the TCP stream type fixed.
    pub async fn accept_tcp(
        &self,
        stream: tokio::net::TcpStream,
    ) -> Result<tokio_rustls::server::TlsStream<tokio::net::TcpStream>, TlsError> {
        self.inner
            .accept(stream)
            .await
            .map_err(|e| TlsError::Handshake(e.to_string()))
    }
}

// ── Convenience free functions ────────────────────────────────────────────────

/// Connect with ALPN negotiation in a single call.
///
/// Builds a [`ClientConfig`] with the given ALPN protocols and root certificates,
/// then performs a TLS handshake to `stream` with the given `host` as SNI.
///
/// Returns a [`RustcryptoClientStream`] with [`oxitls_core::ConnectionInfo`]
/// pre-populated (ALPN negotiation result accessible via `connection_info()`).
pub async fn connect_with_alpn(
    stream: tokio::net::TcpStream,
    host: &str,
    alpn: Vec<Vec<u8>>,
    roots: RootCertStore,
) -> Result<RustcryptoClientStream, TlsError> {
    let provider = pure_provider();
    let cfg = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| TlsError::InvalidConfig(e.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut cfg = cfg;
    cfg.alpn_protocols = alpn;
    let connector = RustcryptoConnector::new(Arc::new(cfg));
    connector.connect_tcp(host, stream).await
}

/// Accept a TLS handshake with a wall-clock timeout.
///
/// Wraps [`RustcryptoAcceptor::accept_tcp`] with [`tokio::time::timeout`].
/// Returns `Err(TlsError::Other("timed out"))` if the handshake does not
/// complete within `timeout`.
pub async fn accept_with_timeout(
    acceptor: &RustcryptoAcceptor,
    stream: tokio::net::TcpStream,
    timeout: std::time::Duration,
) -> Result<tokio_rustls::server::TlsStream<tokio::net::TcpStream>, TlsError> {
    tokio::time::timeout(timeout, acceptor.accept_tcp(stream))
        .await
        .map_err(|_| TlsError::Other("TLS handshake timed out".to_string()))?
}

/// Connect using an existing `Arc<ClientConfig>` and a string SNI.
///
/// This is a convenience wrapper for callers that already hold a built config
/// and want to pass a hostname string directly.
pub async fn from_config_with_sni(
    stream: tokio::net::TcpStream,
    config: Arc<ClientConfig>,
    sni: &str,
) -> Result<RustcryptoClientStream, TlsError> {
    let connector = RustcryptoConnector::new(config);
    connector.connect_tcp(sni, stream).await
}

impl oxitls_core::TlsAcceptor for RustcryptoAcceptor {
    fn accept(
        &self,
        stream: oxitls_core::TlsStream,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<oxitls_core::TlsStream, TlsError>> + Send + '_>,
    > {
        Box::pin(async move {
            let tls = self
                .inner
                .accept(stream)
                .await
                .map_err(|e| TlsError::Handshake(e.to_string()))?;
            Ok(Box::new(tls) as oxitls_core::TlsStream)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_cipher_suites_non_empty() {
        let suites = supported_cipher_suites();
        assert!(
            !suites.is_empty(),
            "pure provider should support at least one cipher suite"
        );
    }

    #[test]
    fn supported_versions_non_empty() {
        let versions = supported_versions();
        assert!(
            !versions.is_empty(),
            "should support at least one TLS version"
        );
    }
}
