//! Error types for `oxitls-h2`.

/// Re-export of h2's `Reason` type for RST_STREAM codes.
pub use h2::Reason;

/// Errors that can occur during HTTP/2-over-TLS operations.
#[derive(Debug)]
pub enum H2Error {
    /// The TLS stream did not negotiate the `h2` ALPN protocol.
    AlpnNotH2(String),
    /// An error returned by the [`h2`] crate.
    H2(h2::Error),
    /// An I/O error.
    Io(std::io::Error),
    /// A settings / configuration error upstream of h2.
    Settings(String),
    /// The stream was reset by the peer with the given reason.
    StreamReset(h2::Reason),
    /// A ping or keepalive operation timed out.
    Timeout,
    /// The graceful-shutdown deadline was exceeded.
    GracefulShutdownTimeout,
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

    /// Returns `true` if this is a stream-reset error.
    pub fn is_stream_reset(&self) -> bool {
        matches!(self, H2Error::StreamReset(_))
    }

    /// Returns `true` if this is a timeout error.
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
            H2Error::Settings(s) => write!(f, "settings error: {s}"),
            H2Error::StreamReset(r) => write!(f, "stream reset: {r:?}"),
            H2Error::Timeout => write!(f, "operation timed out"),
            H2Error::GracefulShutdownTimeout => write!(f, "graceful shutdown timed out"),
        }
    }
}

impl std::error::Error for H2Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            H2Error::H2(e) => Some(e),
            H2Error::Io(e) => Some(e),
            H2Error::AlpnNotH2(_)
            | H2Error::Settings(_)
            | H2Error::StreamReset(_)
            | H2Error::Timeout
            | H2Error::GracefulShutdownTimeout => None,
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
            H2Error::Settings(s) => oxitls_core::TlsError::Other(format!("h2 settings: {s}")),
            H2Error::StreamReset(r) => oxitls_core::TlsError::Other(format!("stream reset: {r:?}")),
            H2Error::Timeout => oxitls_core::TlsError::Other("h2 timeout".to_string()),
            H2Error::GracefulShutdownTimeout => {
                oxitls_core::TlsError::Other("h2 graceful shutdown timeout".to_string())
            }
        }
    }
}
