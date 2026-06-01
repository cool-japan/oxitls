#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! `oxitls-h2` — HTTP/2 over TLS streams.
//!
//! Provides ALPN-checked HTTP/2 handshake helpers that wrap the [`h2`] crate.
//! The handshake functions verify that the `h2` ALPN protocol was negotiated
//! before handing the stream to the h2 framing layer, preventing silent
//! protocol mismatches.
//!
//! All handshake functions are generic over the transport type (`S`), so they
//! work with `TcpStream`, Unix sockets, in-memory pipes, or any other
//! `AsyncRead + AsyncWrite + Unpin + Send` type.
//!
//! # Usage
//! ```no_run
//! # async fn doc() -> Result<(), oxitls_h2::H2Error> {
//! use tokio::net::TcpStream;
//! use tokio_rustls::client::TlsStream;
//! use oxitls_h2::h2_client_handshake;
//!
//! // Assume `tls` is a connected client TLS stream with ALPN "h2" negotiated.
//! # let tls: TlsStream<TcpStream> = panic!();
//! let (mut send_req, conn) = h2_client_handshake(tls).await?;
//! // Drive the connection in a background task.
//! tokio::spawn(async move { let _ = conn.await; });
//! # Ok(())
//! # }
//! ```

use tokio::io::{AsyncRead, AsyncWrite};

// ── Sub-modules ───────────────────────────────────────────────────────────────

mod builder;
mod connection;
mod flow_control;
mod priority;
mod server_push;

/// HTTP/2 vs HTTP/3 feature comparison and migration guide.
pub mod comparison;

// ── Re-exports ────────────────────────────────────────────────────────────────

pub use builder::{H2ClientBuilder, H2ServerBuilder};
pub use connection::{H2Connection, H2ServerConn, StreamCounter};
pub use flow_control::OxiFlowControl;
pub use h2::Reason;
pub use priority::StreamPriority;
pub use server_push::{H2PushedStream, H2ServerPush};

// ── H2 Settings ──────────────────────────────────────────────────────────────

/// Configurable HTTP/2 settings for handshake tuning.
///
/// All fields are optional; `None` values cause the h2 crate to use its
/// defaults.
///
/// # Example
/// ```
/// use oxitls_h2::H2Settings;
///
/// let settings = H2Settings::new()
///     .with_initial_window_size(1 << 20)     // 1 MiB
///     .with_max_frame_size(1 << 14)          // 16 KiB
///     .with_max_concurrent_streams(100)
///     .with_max_header_list_size(16384);
/// ```
#[derive(Debug, Clone, Default)]
pub struct H2Settings {
    /// Initial flow-control window size for new streams (bytes).
    pub initial_window_size: Option<u32>,
    /// Maximum HTTP/2 frame payload size (bytes). Must be in [16384, 16777215].
    pub max_frame_size: Option<u32>,
    /// Maximum number of concurrent streams per connection.
    pub max_concurrent_streams: Option<u32>,
    /// Maximum size of the header list (bytes).
    pub max_header_list_size: Option<u32>,
    /// HPACK encoder dynamic table size (bytes).
    pub header_table_size: Option<u32>,
    /// Initial connection-level window size (bytes).
    pub initial_connection_window_size: Option<u32>,
}

impl H2Settings {
    /// Create a new `H2Settings` with all fields unset (h2 defaults).
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the initial flow-control window size.
    pub fn with_initial_window_size(mut self, size: u32) -> Self {
        self.initial_window_size = Some(size);
        self
    }

    /// Set the maximum frame payload size.
    pub fn with_max_frame_size(mut self, size: u32) -> Self {
        self.max_frame_size = Some(size);
        self
    }

    /// Set the maximum number of concurrent streams.
    pub fn with_max_concurrent_streams(mut self, max: u32) -> Self {
        self.max_concurrent_streams = Some(max);
        self
    }

    /// Set the maximum header list size.
    pub fn with_max_header_list_size(mut self, size: u32) -> Self {
        self.max_header_list_size = Some(size);
        self
    }

    /// Set the HPACK dynamic table size.
    pub fn with_header_table_size(mut self, size: u32) -> Self {
        self.header_table_size = Some(size);
        self
    }

    /// Set the initial connection-level window size.
    pub fn with_initial_connection_window_size(mut self, size: u32) -> Self {
        self.initial_connection_window_size = Some(size);
        self
    }
}

// ── Type aliases ─────────────────────────────────────────────────────────────

/// Type alias for the result of an HTTP/2 client handshake.
pub type H2ClientHandshake<S> = (
    h2::client::SendRequest<bytes::Bytes>,
    h2::client::Connection<S, bytes::Bytes>,
);

/// Type alias for a server-side HTTP/2 connection.
pub type H2ServerConnection<S> = h2::server::Connection<S, bytes::Bytes>;

// ── Concrete TcpStream type aliases for backward compat ──────────────────────

/// Convenience alias: client handshake result over a `TcpStream`-backed client
/// TLS stream.
pub type TcpH2ClientHandshake =
    H2ClientHandshake<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>;

/// Convenience alias: server connection over a `TcpStream`-backed server TLS
/// stream.
pub type TcpH2ServerConnection =
    H2ServerConnection<tokio_rustls::server::TlsStream<tokio::net::TcpStream>>;

// ---------------------------------------------------------------------------
// ALPN helpers
// ---------------------------------------------------------------------------

/// Verify that a client TLS stream negotiated the `h2` ALPN protocol.
fn verify_client_alpn<S>(tls: &tokio_rustls::client::TlsStream<S>) -> Result<(), H2Error> {
    let (_, session) = tls.get_ref();
    match session.alpn_protocol() {
        Some(b"h2") => Ok(()),
        other => Err(H2Error::AlpnNotH2(format!("{other:?}"))),
    }
}

/// Verify that a server TLS stream negotiated the `h2` ALPN protocol.
fn verify_server_alpn<S>(tls: &tokio_rustls::server::TlsStream<S>) -> Result<(), H2Error> {
    let (_, session) = tls.get_ref();
    match session.alpn_protocol() {
        Some(b"h2") => Ok(()),
        other => Err(H2Error::AlpnNotH2(format!("{other:?}"))),
    }
}

// ---------------------------------------------------------------------------
// Public API — generic handshake functions
// ---------------------------------------------------------------------------

/// Perform an HTTP/2 client handshake over an already-established TLS stream.
///
/// # ALPN requirement
/// The TLS stream **must** have negotiated the `h2` ALPN protocol. If the
/// negotiated protocol is anything else (including `None`), the function
/// returns [`H2Error::AlpnNotH2`] immediately.
///
/// # Type parameter
/// `S` is the underlying transport (e.g. `TcpStream`, `UnixStream`, or any
/// `AsyncRead + AsyncWrite + Unpin + Send` type).
pub async fn h2_client_handshake<S>(
    tls: tokio_rustls::client::TlsStream<S>,
) -> Result<H2ClientHandshake<tokio_rustls::client::TlsStream<S>>, H2Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    verify_client_alpn(&tls)?;
    h2::client::handshake(tls).await.map_err(H2Error::H2)
}

/// Perform an HTTP/2 server handshake over an already-established TLS stream.
///
/// # ALPN requirement
/// The TLS stream **must** have negotiated the `h2` ALPN protocol. If the
/// negotiated protocol is anything else (including `None`), the function
/// returns [`H2Error::AlpnNotH2`] immediately.
pub async fn h2_server_handshake<S>(
    tls: tokio_rustls::server::TlsStream<S>,
) -> Result<H2ServerConnection<tokio_rustls::server::TlsStream<S>>, H2Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    verify_server_alpn(&tls)?;
    h2::server::handshake(tls).await.map_err(H2Error::H2)
}

/// Perform an HTTP/2 client handshake with custom settings.
///
/// Like [`h2_client_handshake`] but applies the given [`H2Settings`] to the
/// h2 client builder before performing the handshake.
pub async fn h2_client_handshake_with_settings<S>(
    tls: tokio_rustls::client::TlsStream<S>,
    settings: &H2Settings,
) -> Result<H2ClientHandshake<tokio_rustls::client::TlsStream<S>>, H2Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    verify_client_alpn(&tls)?;

    let mut builder = h2::client::Builder::new();
    if let Some(v) = settings.initial_window_size {
        builder.initial_window_size(v);
    }
    if let Some(v) = settings.max_frame_size {
        builder.max_frame_size(v);
    }
    if let Some(v) = settings.max_header_list_size {
        builder.max_header_list_size(v);
    }
    if let Some(v) = settings.header_table_size {
        builder.header_table_size(v);
    }
    if let Some(v) = settings.initial_connection_window_size {
        builder.initial_connection_window_size(v);
    }

    builder.handshake(tls).await.map_err(H2Error::H2)
}

/// Perform an HTTP/2 server handshake with custom settings.
///
/// Like [`h2_server_handshake`] but applies the given [`H2Settings`] to the
/// h2 server builder before performing the handshake.
pub async fn h2_server_handshake_with_settings<S>(
    tls: tokio_rustls::server::TlsStream<S>,
    settings: &H2Settings,
) -> Result<H2ServerConnection<tokio_rustls::server::TlsStream<S>>, H2Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    verify_server_alpn(&tls)?;

    let mut builder = h2::server::Builder::new();
    if let Some(v) = settings.initial_window_size {
        builder.initial_window_size(v);
    }
    if let Some(v) = settings.max_frame_size {
        builder.max_frame_size(v);
    }
    if let Some(v) = settings.max_concurrent_streams {
        builder.max_concurrent_streams(v);
    }
    if let Some(v) = settings.max_header_list_size {
        builder.max_header_list_size(v);
    }
    if let Some(v) = settings.header_table_size {
        builder.header_table_size(v);
    }
    if let Some(v) = settings.initial_connection_window_size {
        builder.initial_connection_window_size(v);
    }

    builder.handshake(tls).await.map_err(H2Error::H2)
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur during an HTTP/2-over-TLS operation.
#[derive(Debug)]
pub enum H2Error {
    /// The TLS stream did not negotiate the `h2` ALPN protocol.
    AlpnNotH2(String),
    /// An error returned by the [`h2`] crate.
    H2(h2::Error),
    /// An I/O error.
    Io(std::io::Error),
    /// Graceful shutdown timed out before the connection drained.
    GracefulShutdownTimeout,
    /// A settings or configuration error (e.g., invalid parameter).
    Settings(String),
    /// The stream was reset by the peer with the given reason code.
    StreamReset(h2::Reason),
    /// A ping or keepalive operation timed out.
    Timeout,
}

impl H2Error {
    /// Returns `true` if this is an ALPN mismatch error.
    pub fn is_alpn_not_h2(&self) -> bool {
        matches!(self, H2Error::AlpnNotH2(_))
    }

    /// Returns `true` if this is an h2 protocol error.
    pub fn is_h2(&self) -> bool {
        matches!(self, H2Error::H2(_))
    }

    /// Returns `true` if this is an I/O error.
    pub fn is_io(&self) -> bool {
        matches!(self, H2Error::Io(_))
    }

    /// Returns `true` if this is a graceful shutdown timeout.
    pub fn is_graceful_shutdown_timeout(&self) -> bool {
        matches!(self, H2Error::GracefulShutdownTimeout)
    }

    /// Returns `true` if this is a stream reset error.
    pub fn is_stream_reset(&self) -> bool {
        matches!(self, H2Error::StreamReset(_))
    }

    /// Returns `true` if this is any kind of timeout error.
    pub fn is_timeout(&self) -> bool {
        matches!(self, H2Error::Timeout | H2Error::GracefulShutdownTimeout)
    }
}

impl std::fmt::Display for H2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            H2Error::AlpnNotH2(got) => write!(f, "ALPN protocol is not \"h2\" (got {got})"),
            H2Error::H2(e) => write!(f, "h2 error: {e}"),
            H2Error::Io(e) => write!(f, "I/O error: {e}"),
            H2Error::GracefulShutdownTimeout => write!(f, "graceful shutdown timed out"),
            H2Error::Settings(s) => write!(f, "settings error: {s}"),
            H2Error::StreamReset(r) => write!(f, "H2 stream reset: {r:?}"),
            H2Error::Timeout => write!(f, "operation timed out"),
        }
    }
}

impl std::error::Error for H2Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            H2Error::H2(e) => Some(e),
            H2Error::Io(e) => Some(e),
            H2Error::AlpnNotH2(_)
            | H2Error::GracefulShutdownTimeout
            | H2Error::Settings(_)
            | H2Error::StreamReset(_)
            | H2Error::Timeout => None,
        }
    }
}

impl From<h2::Error> for H2Error {
    fn from(e: h2::Error) -> Self {
        if e.is_reset() {
            if let Some(reason) = e.reason() {
                return H2Error::StreamReset(reason);
            }
        }
        H2Error::H2(e)
    }
}

impl From<std::io::Error> for H2Error {
    fn from(e: std::io::Error) -> Self {
        H2Error::Io(e)
    }
}

impl From<H2Error> for oxitls_core::TlsError {
    fn from(e: H2Error) -> Self {
        match e {
            H2Error::AlpnNotH2(s) => oxitls_core::TlsError::Handshake(format!("ALPN not h2: {s}")),
            H2Error::H2(e) => oxitls_core::TlsError::Other(format!("h2: {e}")),
            H2Error::Io(e) => oxitls_core::TlsError::Io(e.kind()),
            H2Error::GracefulShutdownTimeout => {
                oxitls_core::TlsError::Other("graceful shutdown timed out".to_string())
            }
            H2Error::Settings(s) => oxitls_core::TlsError::InvalidConfig(s),
            H2Error::StreamReset(r) => {
                oxitls_core::TlsError::Other(format!("H2 stream reset: {r:?}"))
            }
            H2Error::Timeout => oxitls_core::TlsError::Other("h2 operation timed out".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn h2_settings_builder() {
        let settings = H2Settings::new()
            .with_initial_window_size(1 << 20)
            .with_max_frame_size(1 << 14)
            .with_max_concurrent_streams(100)
            .with_max_header_list_size(16384)
            .with_header_table_size(4096)
            .with_initial_connection_window_size(1 << 24);

        assert_eq!(settings.initial_window_size, Some(1 << 20));
        assert_eq!(settings.max_frame_size, Some(1 << 14));
        assert_eq!(settings.max_concurrent_streams, Some(100));
        assert_eq!(settings.max_header_list_size, Some(16384));
        assert_eq!(settings.header_table_size, Some(4096));
        assert_eq!(settings.initial_connection_window_size, Some(1 << 24));
    }

    #[test]
    fn h2_settings_default_all_none() {
        let settings = H2Settings::default();
        assert!(settings.initial_window_size.is_none());
        assert!(settings.max_frame_size.is_none());
        assert!(settings.max_concurrent_streams.is_none());
        assert!(settings.max_header_list_size.is_none());
        assert!(settings.header_table_size.is_none());
        assert!(settings.initial_connection_window_size.is_none());
    }

    #[test]
    fn h2_error_predicates() {
        let alpn_err = H2Error::AlpnNotH2("test".into());
        assert!(alpn_err.is_alpn_not_h2());
        assert!(!alpn_err.is_h2());
        assert!(!alpn_err.is_io());
    }

    #[test]
    fn h2_error_to_tls_error_conversion() {
        let alpn_err = H2Error::AlpnNotH2("none".into());
        let tls_err: oxitls_core::TlsError = alpn_err.into();
        assert!(tls_err.is_handshake());

        let io_err = H2Error::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "reset",
        ));
        let tls_err: oxitls_core::TlsError = io_err.into();
        assert!(tls_err.is_io());
    }

    #[test]
    fn h2_error_graceful_shutdown_timeout() {
        let e = H2Error::GracefulShutdownTimeout;
        assert!(e.is_graceful_shutdown_timeout());
        assert!(!e.is_h2());
    }
}
