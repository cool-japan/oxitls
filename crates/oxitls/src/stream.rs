//! `OxiTlsStream<S>` — a unified async TLS stream wrapper.
//!
//! Bundles a `tokio_rustls` client or server TLS stream with optional
//! [`ConnectionInfo`] metadata populated after the handshake completes.
//! Also provides [`export_keying_material`](OxiTlsStream::export_keying_material)
//! for RFC 5705 / RFC 8446 §7.5 keying material export.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::rustls::ConnectionCommon;

use oxitls_core::{ConnectionInfo, TlsError, TlsStreamInfo};

// ── Inner enum ────────────────────────────────────────────────────────────────

enum Inner<S> {
    Client(tokio_rustls::client::TlsStream<S>),
    Server(tokio_rustls::server::TlsStream<S>),
}

// ── OxiTlsStream ─────────────────────────────────────────────────────────────

/// A unified TLS stream wrapper that holds either a client or server TLS
/// stream together with optional [`ConnectionInfo`] metadata.
///
/// Implements [`AsyncRead`] and [`AsyncWrite`] by delegating to the inner
/// `tokio_rustls` stream. Also implements [`TlsStreamInfo`] so callers can
/// inspect the negotiated protocol version, cipher suite, and ALPN protocol
/// after the handshake.
///
/// # Example
/// ```no_run
/// # async fn example<S>()
/// # where
/// #     S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
/// # {
/// use oxitls::OxiTlsStream;
/// use tokio::io::{AsyncReadExt, AsyncWriteExt};
///
/// // Assume `stream` was created by a connector or acceptor.
/// # let stream: OxiTlsStream<S> = todo!();
/// if let Some(info) = stream.connection_info() {
///     println!("TLS version: {:?}", info.version);
/// }
/// # }
/// ```
pub struct OxiTlsStream<S> {
    inner: Inner<S>,
    info: Option<ConnectionInfo>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> OxiTlsStream<S> {
    /// Returns a writer for 0-RTT early data, if the session has a resumption
    /// ticket and the server indicated willingness to accept early data.
    ///
    /// Only available on **client**-side streams. Returns `None` for server
    /// streams, and also returns `None` before a valid resumption ticket has
    /// been stored from a prior session.
    ///
    /// # Security warning
    ///
    /// Early data is **not** protected against replay attacks — see RFC 8446 §8.
    /// Never send non-idempotent requests as early data (e.g. POST bodies or
    /// state-changing API calls). Safe uses include read-only GETs, cache
    /// probes, or data the server is explicitly prepared to de-duplicate.
    ///
    /// # Notes
    ///
    /// The returned [`rustls::client::WriteEarlyData`] implements [`std::io::Write`]
    /// but **not** `tokio::io::AsyncWrite`. All writes through this accessor
    /// are synchronous. The tokio-rustls 0-RTT async write path (via
    /// `TlsConnector::early_data(true)`) is the recommended route for
    /// fully-async usage; this method exposes the underlying rustls object for
    /// lower-level control.
    pub fn early_data(&mut self) -> Option<rustls::client::WriteEarlyData<'_>> {
        match &mut self.inner {
            Inner::Client(s) => {
                let (_, session) = s.get_mut();
                session.early_data()
            }
            Inner::Server(_) => None,
        }
    }

    /// Wrap a client-side TLS stream with optional connection metadata.
    pub fn from_client(
        stream: tokio_rustls::client::TlsStream<S>,
        info: Option<ConnectionInfo>,
    ) -> Self {
        Self {
            inner: Inner::Client(stream),
            info,
        }
    }

    /// Wrap a server-side TLS stream with optional connection metadata.
    pub fn from_server(
        stream: tokio_rustls::server::TlsStream<S>,
        info: Option<ConnectionInfo>,
    ) -> Self {
        Self {
            inner: Inner::Server(stream),
            info,
        }
    }

    /// Return the connection metadata, if available.
    ///
    /// Returns `None` if the handshake has not yet completed or metadata was
    /// not provided at construction time.
    pub fn connection_info(&self) -> Option<&ConnectionInfo> {
        self.info.as_ref()
    }

    /// Borrow the underlying transport stream.
    pub fn get_ref(&self) -> &S {
        match &self.inner {
            Inner::Client(s) => s.get_ref().0,
            Inner::Server(s) => s.get_ref().0,
        }
    }

    /// Consume the wrapper, returning the underlying transport stream.
    ///
    /// Any buffered TLS data is discarded.
    pub fn into_inner(self) -> S {
        match self.inner {
            Inner::Client(s) => s.into_inner().0,
            Inner::Server(s) => s.into_inner().0,
        }
    }
}

impl<S> OxiTlsStream<S> {
    /// Export keying material from the completed TLS session (RFC 5705 /
    /// RFC 8446 §7.5).
    ///
    /// Fills `output` with `output.len()` bytes derived from the session key
    /// material using the given `label` and optional `context`.
    ///
    /// # Errors
    /// Returns [`TlsError::Other`] if the handshake has not yet completed, if
    /// `output` is empty, or if the underlying provider does not support the
    /// export.
    pub fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: Option<&[u8]>,
    ) -> Result<(), TlsError> {
        match &self.inner {
            Inner::Client(stream) => {
                let (_, session) = stream.get_ref();
                let conn: &ConnectionCommon<_> = session;
                conn.export_keying_material(output, label, context)
                    .map(|_| ())
                    .map_err(|e| TlsError::Other(e.to_string()))
            }
            Inner::Server(stream) => {
                let (_, session) = stream.get_ref();
                let conn: &ConnectionCommon<_> = session;
                conn.export_keying_material(output, label, context)
                    .map(|_| ())
                    .map_err(|e| TlsError::Other(e.to_string()))
            }
        }
    }
}

// ── From conversions ──────────────────────────────────────────────────────────

impl<S> From<tokio_rustls::client::TlsStream<S>> for OxiTlsStream<S> {
    fn from(stream: tokio_rustls::client::TlsStream<S>) -> Self {
        Self {
            inner: Inner::Client(stream),
            info: None,
        }
    }
}

impl<S> From<tokio_rustls::server::TlsStream<S>> for OxiTlsStream<S> {
    fn from(stream: tokio_rustls::server::TlsStream<S>) -> Self {
        Self {
            inner: Inner::Server(stream),
            info: None,
        }
    }
}

// ── TlsStreamInfo ─────────────────────────────────────────────────────────────

impl<S: AsyncRead + AsyncWrite + Unpin> TlsStreamInfo for OxiTlsStream<S> {
    fn connection_info(&self) -> Option<&ConnectionInfo> {
        self.info.as_ref()
    }
}

// ── AsyncRead ─────────────────────────────────────────────────────────────────

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for OxiTlsStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut self.get_mut().inner {
            Inner::Client(s) => Pin::new(s).poll_read(cx, buf),
            Inner::Server(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

// ── AsyncWrite ───────────────────────────────────────────────────────────────

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for OxiTlsStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut self.get_mut().inner {
            Inner::Client(s) => Pin::new(s).poll_write(cx, buf),
            Inner::Server(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().inner {
            Inner::Client(s) => Pin::new(s).poll_flush(cx),
            Inner::Server(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().inner {
            Inner::Client(s) => Pin::new(s).poll_shutdown(cx),
            Inner::Server(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}
