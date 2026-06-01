#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! `oxitls` — Pure-Rust TLS facade.
//!
//! Default: `features = ["pure", "webpki-roots"]` wires rustls + rustls-rustcrypto.
//! Never calls `CryptoProvider::install_default()`.
//!
//! Optional features:
//! - `h2`: HTTP/2 via `oxitls-h2`
//! - `rcgen`: Pure cert-gen via `oxitls-rcgen` (no ring)

pub use oxitls_core::TlsError;

// Re-export core types.
pub use oxitls_core::{CipherSuite, ConnectionInfo, TlsVersion};

// Re-export extended core types (key-log, alerts, stream trait).
pub use oxitls_core::{AlertDescription, KeyLog, KeyLogPolicy, TlsStreamInfo};

#[cfg(feature = "pure")]
pub use oxitls_adapter_rustls_rustcrypto::{
    client_config, connection_info_from_state, pure_provider, server_config,
    supported_cipher_suites, supported_versions, RustcryptoAcceptor, RustcryptoConnector,
};
#[cfg(feature = "pure")]
pub use oxitls_adapter_rustls_rustcrypto::{ClientConfig, RootCertStore, ServerConfig, ServerName};

#[cfg(feature = "webpki-roots")]
pub use oxitls_webpki_roots::webpki_root_certs;

/// Dangerous certificate verifiers for testing and development only.
#[cfg(feature = "pure")]
mod danger;

/// Unified TLS stream wrapper providing `early_data()`, `export_keying_material()`,
/// and `connection_info()` across client and server streams.
#[cfg(feature = "pure")]
pub mod stream;
#[cfg(feature = "pure")]
pub use stream::OxiTlsStream;

/// TLS builders and helpers (client, server, mTLS, ALPN, SNI, TLS 1.2 fallback).
#[cfg(feature = "pure")]
pub mod tls13;

#[cfg(feature = "pure")]
pub use tls13::{client::ClientBuilder, server::tokio_acceptor, ServerBuilder};

/// Future returned by [`tokio_rustls::TlsConnector::connect`].
///
/// Alias for ergonomics: import `oxitls::ConnectFuture` instead of the
/// tokio-rustls path.
#[cfg(feature = "pure")]
pub type ConnectFuture<IO> = tokio_rustls::client::Connect<IO>;

/// Future returned by [`tokio_rustls::TlsAcceptor::accept`].
///
/// Alias for ergonomics: import `oxitls::AcceptFuture` instead of the
/// tokio-rustls path.
#[cfg(feature = "pure")]
pub type AcceptFuture<IO> = tokio_rustls::server::Accept<IO>;

/// Re-export of [`rustls::ProtocolVersion`] for ergonomics.
#[cfg(feature = "pure")]
pub use rustls::ProtocolVersion;

/// Re-export of [`rustls::SupportedProtocolVersion`] for ergonomics.
#[cfg(feature = "pure")]
pub use rustls::SupportedProtocolVersion;

/// Re-export `SubjectPublicKeyInfoDer` for raw-public-key (RFC 7250) ergonomics.
#[cfg(feature = "pure")]
pub use rustls::pki_types::SubjectPublicKeyInfoDer;

#[cfg(feature = "pure")]
pub use tls13::server::{OcspResponseResolver, StaticOcspResolver};

#[cfg(feature = "h2")]
pub mod h2 {
    //! HTTP/2 over TLS (oxitls-h2 re-export).
    pub use oxitls_h2::*;
}

/// Pure-Rust certificate generation (rcgen bridge, no ring).
///
/// Enable with `features = ["rcgen"]`.
///
/// Re-exports from `oxitls_rcgen`.
#[cfg(feature = "rcgen")]
pub mod rcgen_bridge {
    pub use oxitls_rcgen::*;
}

/// Session-ticket resumption backed by AES-256-GCM (no ring).
///
/// Implements [`rustls::server::ProducesTickets`].  Wire into a server
/// config via [`tls13::ServerBuilder::with_ticketer`].
#[cfg(feature = "pure")]
pub mod ticketer;
#[cfg(feature = "pure")]
pub use ticketer::OxiTicketer;

/// RFC 8446 §8 single-use-ticket anti-replay protection for 0-RTT early data.
///
/// Wraps any [`rustls::server::ProducesTickets`] implementation with a
/// time-windowed replay guard. Install via
/// [`tls13::ServerBuilder::with_anti_replay`].
#[cfg(feature = "pure")]
pub mod anti_replay;

/// Convenience: build a `RustcryptoConnector` trusting the Mozilla CA bundle.
#[cfg(all(feature = "pure", feature = "webpki-roots"))]
pub fn connector_with_webpki_roots() -> Result<RustcryptoConnector, TlsError> {
    let root_store = webpki_root_certs();
    let cfg = client_config(root_store)?;
    Ok(RustcryptoConnector::new(cfg))
}

/// aws-lc-rs backed `CryptoProvider` and provider type.
///
/// Enable with `features = ["aws-lc"]`.  The default feature set does **not**
/// include this module — the default closure is 100% Pure Rust.
///
/// # Example
/// ```no_run
/// # #[cfg(feature = "aws-lc")]
/// # {
/// use oxitls::aws_lc::{aws_lc_provider, AwsLcTlsProvider};
/// let provider = aws_lc_provider();
/// # }
/// ```
#[cfg(feature = "aws-lc")]
pub mod aws_lc {
    pub use oxitls_adapter_aws_lc::{aws_lc_provider, AwsLcTlsProvider};

    /// Convenience alias: the aws-lc-rs backed provider.
    pub fn provider() -> std::sync::Arc<rustls::crypto::CryptoProvider> {
        aws_lc_provider()
    }
}

/// Re-export `h2::Reason` as `H2Reason` for ergonomic error handling.
#[cfg(feature = "h2")]
pub use oxitls_h2::Reason as H2Reason;
/// Re-exports from `oxitls-h2` for convenient access at the crate root.
///
/// Enable with `features = ["h2"]`.
#[cfg(feature = "h2")]
pub use oxitls_h2::{H2Error, H2Settings};

/// Utilities for using oxitls as a Pure-Rust TLS layer in QUIC handshakes.
///
/// Enable with `features = ["quic-preview"]`. Provides a pre-configured
/// Pure-Rust [`CryptoProvider`][rustls::crypto::CryptoProvider] re-export for
/// use by QUIC implementations.
#[cfg(feature = "quic-preview")]
pub mod quic_preview {
    use std::sync::Arc;

    /// The Pure-Rust CryptoProvider suitable for QUIC handshakes.
    ///
    /// Identical to [`crate::pure_provider()`] — re-exported here so QUIC
    /// crates can depend only on `oxitls` with `quic-preview` rather than
    /// importing the adapter crate directly.
    pub fn pure_quic_provider() -> Arc<rustls::crypto::CryptoProvider> {
        crate::pure_provider()
    }
}

// ── GenericTlsConnector / GenericTlsAcceptor impls ───────────────────────────

#[cfg(all(feature = "pure", feature = "generic-transport"))]
mod generic_impls {
    use std::sync::Arc;

    use oxitls_core::{GenericTlsAcceptor, GenericTlsConnector, GenericTlsFuture};
    use tokio::io::{AsyncRead, AsyncWrite};

    use crate::tls13::{ClientBuilder, ServerBuilder};
    use crate::OxiTlsStream;

    impl GenericTlsConnector for ClientBuilder {
        type Stream<S>
            = OxiTlsStream<S>
        where
            S: AsyncRead + AsyncWrite + Unpin + Send + 'static;

        fn connect<S>(
            &self,
            stream: S,
            server_name: rustls::pki_types::ServerName<'static>,
        ) -> GenericTlsFuture<'_, Self::Stream<S>>
        where
            S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        {
            let cfg = match self.clone().build() {
                Ok(c) => c,
                Err(e) => return Box::pin(async move { Err(e) }),
            };
            Box::pin(async move {
                let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
                let tls_stream = connector
                    .connect(server_name, stream)
                    .await
                    .map_err(|e| oxitls_core::TlsError::Other(e.to_string()))?;
                Ok(OxiTlsStream::from_client(tls_stream, None))
            })
        }
    }

    impl GenericTlsAcceptor for ServerBuilder {
        type Stream<S>
            = OxiTlsStream<S>
        where
            S: AsyncRead + AsyncWrite + Unpin + Send + 'static;

        fn accept<S>(&self, stream: S) -> GenericTlsFuture<'_, Self::Stream<S>>
        where
            S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        {
            let cfg = match self.clone().build() {
                Ok(c) => c,
                Err(e) => return Box::pin(async move { Err(e) }),
            };
            Box::pin(async move {
                let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
                let tls_stream = acceptor
                    .accept(stream)
                    .await
                    .map_err(|e| oxitls_core::TlsError::Other(e.to_string()))?;
                Ok(OxiTlsStream::from_server(tls_stream, None))
            })
        }
    }
}

// ── TLS Connection Extension trait ───────────────────────────────────────────

/// Extension trait for extracting TLS connection information from a completed
/// handshake.
///
/// Implemented for `tokio_rustls::client::TlsStream<S>` and
/// `tokio_rustls::server::TlsStream<S>`.
#[cfg(feature = "pure")]
pub trait TlsConnectionExt {
    /// Extract connection information (version, cipher suite, ALPN, etc.) from
    /// the completed TLS session.
    fn tls_connection_info(&self) -> ConnectionInfo;
}

#[cfg(feature = "pure")]
impl<S> TlsConnectionExt for tokio_rustls::client::TlsStream<S> {
    fn tls_connection_info(&self) -> ConnectionInfo {
        let (_, session) = self.get_ref();
        let mut info = connection_info_from_state(session);

        // Extract peer certificates from the client session.
        if let Some(certs) = session.peer_certificates() {
            info = info.with_peer_certificates(certs.iter().map(|c| c.to_vec()).collect());
        }

        info
    }
}

#[cfg(feature = "pure")]
impl<S> TlsConnectionExt for tokio_rustls::server::TlsStream<S> {
    fn tls_connection_info(&self) -> ConnectionInfo {
        let (_, session) = self.get_ref();
        let mut info = connection_info_from_state(session);

        // Extract peer certificates from the server session (mTLS).
        if let Some(certs) = session.peer_certificates() {
            info = info.with_peer_certificates(certs.iter().map(|c| c.to_vec()).collect());
        }

        // Extract SNI from the server session.
        if let Some(sni) = session.server_name() {
            info = info.with_sni(sni.to_string());
        }

        info
    }
}
