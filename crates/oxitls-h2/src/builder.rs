//! Production-grade HTTP/2 client and server builders.

use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{H2Connection, H2Error, H2ServerConn};

// ---------------------------------------------------------------------------
// H2ClientBuilder
// ---------------------------------------------------------------------------

/// Builder for an HTTP/2 client connection.
///
/// Configures h2 client settings before performing the HTTP/2 handshake.
///
/// # Example
/// ```no_run
/// # use std::time::Duration;
/// # async fn doc() -> Result<(), oxitls_h2::H2Error> {
/// use tokio::io::duplex;
/// use oxitls_h2::H2ClientBuilder;
///
/// let (client_io, _server_io) = duplex(65536);
/// let (_send_req, _conn) = H2ClientBuilder::new()
///     .with_max_concurrent_streams(100)
///     .with_initial_window_size(1 << 20)
///     .with_keepalive(Duration::from_secs(30))
///     .handshake(client_io)
///     .await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct H2ClientBuilder {
    max_concurrent_streams: Option<u32>,
    initial_window_size: Option<u32>,
    max_header_list_size: Option<u32>,
    hpack_table_size: Option<u32>,
    max_send_buffer_size: Option<usize>,
    keepalive: Option<Duration>,
}

impl H2ClientBuilder {
    /// Create a new `H2ClientBuilder` with all settings at h2 defaults.
    pub fn new() -> Self {
        Self {
            max_concurrent_streams: None,
            initial_window_size: None,
            max_header_list_size: None,
            hpack_table_size: None,
            max_send_buffer_size: None,
            keepalive: None,
        }
    }

    /// Set the maximum number of concurrent streams this client will advertise.
    pub fn with_max_concurrent_streams(mut self, n: u32) -> Self {
        self.max_concurrent_streams = Some(n);
        self
    }

    /// Set the initial window size for stream-level flow control.
    pub fn with_initial_window_size(mut self, n: u32) -> Self {
        self.initial_window_size = Some(n);
        self
    }

    /// Set the maximum size of received header lists.
    pub fn with_max_header_list_size(mut self, n: u32) -> Self {
        self.max_header_list_size = Some(n);
        self
    }

    /// Set the HPACK dynamic table size.
    pub fn with_hpack_table_size(mut self, n: u32) -> Self {
        self.hpack_table_size = Some(n);
        self
    }

    /// Set the maximum send buffer size per stream.
    pub fn with_max_send_buffer_size(mut self, n: usize) -> Self {
        self.max_send_buffer_size = Some(n);
        self
    }

    /// Enable keepalive pings at the given interval.
    pub fn with_keepalive(mut self, d: Duration) -> Self {
        self.keepalive = Some(d);
        self
    }

    /// Perform the HTTP/2 handshake over `io`.
    ///
    /// Returns a `(SendRequest, H2Connection)` pair.  The `H2Connection`
    /// drives the connection in a background task; the `SendRequest` is used
    /// to open streams.
    ///
    /// # Errors
    ///
    /// Returns `H2Error` if the h2 handshake fails.
    pub async fn handshake<IO>(
        self,
        io: IO,
    ) -> Result<(h2::client::SendRequest<Bytes>, H2Connection<IO>), H2Error>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mut builder = h2::client::Builder::new();

        if let Some(v) = self.max_concurrent_streams {
            builder.max_concurrent_streams(v);
        }
        if let Some(v) = self.initial_window_size {
            builder.initial_window_size(v);
        }
        if let Some(v) = self.max_header_list_size {
            builder.max_header_list_size(v);
        }
        if let Some(v) = self.hpack_table_size {
            builder.header_table_size(v);
        }
        if let Some(v) = self.max_send_buffer_size {
            builder.max_send_buffer_size(v);
        }

        let (send_request, conn) = builder.handshake(io).await.map_err(H2Error::from)?;
        let h2_conn = H2Connection::new(conn, send_request.clone(), self.keepalive);
        Ok((send_request, h2_conn))
    }
}

impl Default for H2ClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// H2ServerBuilder
// ---------------------------------------------------------------------------

/// Builder for an HTTP/2 server connection.
///
/// Configures h2 server settings before performing the HTTP/2 handshake.
///
/// # Example
/// ```no_run
/// # async fn doc() -> Result<(), oxitls_h2::H2Error> {
/// use tokio::io::duplex;
/// use oxitls_h2::H2ServerBuilder;
///
/// let (_client_io, server_io) = duplex(65536);
/// let _server_conn = H2ServerBuilder::new()
///     .with_max_concurrent_streams(100)
///     .accept(server_io)
///     .await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct H2ServerBuilder {
    max_concurrent_streams: Option<u32>,
    initial_window_size: Option<u32>,
    max_header_list_size: Option<u32>,
    hpack_table_size: Option<u32>,
    max_send_buffer_size: Option<usize>,
    push_enabled: Option<bool>,
    keepalive: Option<Duration>,
}

impl H2ServerBuilder {
    /// Create a new `H2ServerBuilder` with all settings at h2 defaults.
    pub fn new() -> Self {
        Self {
            max_concurrent_streams: None,
            initial_window_size: None,
            max_header_list_size: None,
            hpack_table_size: None,
            max_send_buffer_size: None,
            push_enabled: None,
            keepalive: None,
        }
    }

    /// Set the maximum number of concurrent streams this server will allow.
    pub fn with_max_concurrent_streams(mut self, n: u32) -> Self {
        self.max_concurrent_streams = Some(n);
        self
    }

    /// Set the initial window size for stream-level flow control.
    pub fn with_initial_window_size(mut self, n: u32) -> Self {
        self.initial_window_size = Some(n);
        self
    }

    /// Set the maximum size of received header lists.
    pub fn with_max_header_list_size(mut self, n: u32) -> Self {
        self.max_header_list_size = Some(n);
        self
    }

    /// Set the HPACK dynamic table size.
    pub fn with_hpack_table_size(mut self, n: u32) -> Self {
        self.hpack_table_size = Some(n);
        self
    }

    /// Set the maximum send buffer size per stream.
    pub fn with_max_send_buffer_size(mut self, n: usize) -> Self {
        self.max_send_buffer_size = Some(n);
        self
    }

    /// Enable or disable server push.
    ///
    /// Note: h2 0.4 server push support is determined by the client's
    /// `SETTINGS_ENABLE_PUSH` value; this flag is stored for informational
    /// purposes but the h2 server builder has no direct `enable_push` method.
    pub fn with_push_enabled(mut self, b: bool) -> Self {
        self.push_enabled = Some(b);
        self
    }

    /// Enable keepalive pings at the given interval.
    ///
    /// Note: h2 server keepalive is stored but not automatically driven;
    /// callers can use [`H2ServerConn`](crate::H2ServerConn) methods to
    /// ping manually.
    pub fn with_keepalive(mut self, d: Duration) -> Self {
        self.keepalive = Some(d);
        self
    }

    /// Perform the HTTP/2 server handshake over `io`.
    ///
    /// Returns an [`H2ServerConn`] ready to accept incoming requests.
    ///
    /// # Errors
    ///
    /// Returns `H2Error` if the h2 handshake fails.
    pub async fn accept<IO>(self, io: IO) -> Result<H2ServerConn<IO>, H2Error>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mut builder = h2::server::Builder::new();

        if let Some(v) = self.max_concurrent_streams {
            builder.max_concurrent_streams(v);
        }
        if let Some(v) = self.initial_window_size {
            builder.initial_window_size(v);
        }
        if let Some(v) = self.max_header_list_size {
            builder.max_header_list_size(v);
        }
        if let Some(v) = self.hpack_table_size {
            builder.header_table_size(v);
        }
        if let Some(v) = self.max_send_buffer_size {
            builder.max_send_buffer_size(v);
        }

        let conn = builder
            .handshake::<IO, Bytes>(io)
            .await
            .map_err(H2Error::from)?;

        Ok(H2ServerConn::new(conn))
    }
}

impl Default for H2ServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}
