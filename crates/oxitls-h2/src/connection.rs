//! HTTP/2 connection lifecycle wrappers.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::Mutex;

use crate::H2Error;

// ---------------------------------------------------------------------------
// H2Connection — client-side connection driver
// ---------------------------------------------------------------------------

/// A managed HTTP/2 client connection.
///
/// `H2Connection` wraps the raw [`h2::client::Connection`] future, spawning a
/// background driver task.  It also optionally runs a keepalive task that
/// periodically pings the server.
///
/// # Notes on graceful shutdown
///
/// HTTP/2 client connections have no explicit GOAWAY-sending API (unlike
/// servers).  The conventional approach is to drop the `SendRequest` clones so
/// that no new streams can be opened, then wait for all in-flight streams to
/// complete.  [`graceful_shutdown`](H2Connection::graceful_shutdown) does
/// exactly this by awaiting the driver task with a timeout.
pub struct H2Connection<IO> {
    /// Background driver task handle.
    driver_handle: tokio::task::JoinHandle<()>,
    /// Optional keepalive task handle.
    keepalive_handle: Option<tokio::task::JoinHandle<()>>,
    /// Mutex-wrapped PingPong handle for RTT measurement.
    ///
    /// Wrapped in `Option` because `ping_pong()` may return `None` if it was
    /// already taken, and also in `Mutex` so `ping()` can take `&self`.
    ping_pong: Arc<Mutex<Option<h2::PingPong>>>,
    /// A clone of the `SendRequest` handle, used solely for stream count queries.
    ///
    /// `h2::client::SendRequest` exposes `num_active_streams()` which gives
    /// the number of currently open streams without requiring mutable access.
    send_request: h2::client::SendRequest<Bytes>,
    /// Phantom for the IO type.
    _io: std::marker::PhantomData<IO>,
}

impl<IO> H2Connection<IO>
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    /// Create a new `H2Connection` by spawning a driver task for `conn`.
    ///
    /// `send_request` is a clone of the handshake's `SendRequest`, stored so
    /// that [`stream_count`](Self::stream_count) can query active streams
    /// without requiring mutable access.
    ///
    /// If `keepalive` is `Some(d)`, a task is spawned that pings the server
    /// every `d`.
    pub(crate) fn new(
        mut conn: h2::client::Connection<IO, Bytes>,
        send_request: h2::client::SendRequest<Bytes>,
        keepalive: Option<Duration>,
    ) -> Self {
        // Extract ping_pong BEFORE spawning the driver task.
        let ping_pong_raw: Option<h2::PingPong> = conn.ping_pong();
        let ping_pong = Arc::new(Mutex::new(ping_pong_raw));

        // Spawn the driver task.
        let driver_handle = tokio::spawn(async move {
            let _ = conn.await;
        });

        // Optionally spawn a keepalive task.
        let keepalive_handle = if let Some(interval) = keepalive {
            let pp_clone = Arc::clone(&ping_pong);
            Some(tokio::spawn(async move {
                let mut ticker = tokio::time::interval(interval);
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    ticker.tick().await;
                    let mut guard = pp_clone.lock().await;
                    let some_pp = match guard.as_mut() {
                        Some(pp) => pp,
                        None => break,
                    };
                    // If the ping fails the connection is gone; stop the task.
                    if some_pp.ping(h2::Ping::opaque()).await.is_err() {
                        break;
                    }
                }
            }))
        } else {
            None
        };

        Self {
            driver_handle,
            keepalive_handle,
            ping_pong,
            send_request,
            _io: std::marker::PhantomData,
        }
    }

    /// Measure round-trip time by sending a PING frame.
    ///
    /// Returns the RTT [`Duration`].  Returns [`H2Error::Timeout`] if the
    /// underlying connection has closed and the `PingPong` handle is gone.
    pub async fn ping(&self) -> Result<Duration, H2Error> {
        let mut guard = self.ping_pong.lock().await;
        let pp = guard
            .as_mut()
            .ok_or_else(|| H2Error::Settings("PingPong handle already consumed".to_string()))?;
        let start = std::time::Instant::now();
        pp.ping(h2::Ping::opaque()).await.map_err(H2Error::from)?;
        Ok(start.elapsed())
    }

    /// Return the number of currently active (open) streams on this connection.
    ///
    /// Delegates to [`h2::client::SendRequest::num_active_streams`].
    ///
    /// # Stability note
    ///
    /// This method relies on `h2`'s `unstable` feature flag (enabled workspace-wide
    /// in `Cargo.toml`) which exposes `SendRequest::num_active_streams()`.  The
    /// `h2` crate reserves the right to change or remove `unstable` APIs across
    /// minor versions.  If `h2` removes this in a future patch, the workaround is
    /// to track the count externally via `Arc<AtomicUsize>`.
    pub fn stream_count(&self) -> usize {
        self.send_request.num_active_streams()
    }

    /// Return `true` if there are no active streams on this connection.
    pub fn is_idle(&self) -> bool {
        self.stream_count() == 0
    }

    /// Wait for the connection to drain all in-flight streams, with a timeout.
    ///
    /// Because the HTTP/2 client has no GOAWAY send API, graceful shutdown is
    /// achieved by waiting for the driver task to complete.  The caller should
    /// have already dropped (or finished) all `SendRequest` clones so that
    /// the driver can exit once in-flight streams complete.
    ///
    /// # Errors
    ///
    /// Returns [`H2Error::GracefulShutdownTimeout`] if the driver has not
    /// finished within `timeout`.
    pub async fn graceful_shutdown(mut self, timeout: Duration) -> Result<(), H2Error> {
        // Abort keepalive (it's not needed during shutdown).
        if let Some(h) = self.keepalive_handle.take() {
            h.abort();
        }

        // Take the driver handle to await it; set to a no-op to prevent Drop abort.
        // SAFETY: we're in a consuming method so no double-abort can occur.
        let driver = self.driver_handle.abort_handle();
        // We cannot move driver_handle out because of Drop, so we await a
        // cancellable version instead.
        match tokio::time::timeout(timeout, &mut self.driver_handle).await {
            Ok(join_result) => {
                // JoinHandle can fail if the task panicked; treat as success.
                let _ = join_result;
                Ok(())
            }
            Err(_elapsed) => {
                driver.abort();
                Err(H2Error::GracefulShutdownTimeout)
            }
        }
    }

    /// Abort the connection and any keepalive tasks immediately.
    pub fn abort(mut self) {
        self.driver_handle.abort();
        if let Some(h) = self.keepalive_handle.take() {
            h.abort();
        }
    }
}

// Note: We deliberately do NOT implement Drop with abort() here.
// Aborting the driver on drop would kill in-flight streams when the
// H2Connection handle goes out of scope before responses arrive.
// The driver task is owned by the Tokio runtime and will be cleaned up
// naturally once all SendRequest clones are dropped and streams complete.
// Use `abort()` explicitly when you want immediate cancellation.

impl<IO> std::fmt::Debug for H2Connection<IO> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H2Connection").finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// H2ServerConn — server-side connection wrapper
// ---------------------------------------------------------------------------

/// A managed HTTP/2 server connection.
///
/// Wraps [`h2::server::Connection`] and exposes an `async fn accept_request()`
/// method for receiving incoming requests one by one.
pub struct H2ServerConn<IO> {
    inner: h2::server::Connection<IO, Bytes>,
}

impl<IO> H2ServerConn<IO>
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + 'static,
{
    /// Create a new `H2ServerConn` from a raw h2 server connection.
    pub(crate) fn new(conn: h2::server::Connection<IO, Bytes>) -> Self {
        Self { inner: conn }
    }

    /// Accept the next incoming HTTP/2 request.
    ///
    /// Returns `None` when the connection has been closed cleanly.
    pub async fn accept_request(
        &mut self,
    ) -> Option<
        Result<
            (
                http::Request<h2::RecvStream>,
                h2::server::SendResponse<Bytes>,
            ),
            H2Error,
        >,
    > {
        use std::future::poll_fn;
        poll_fn(|cx| self.inner.poll_accept(cx))
            .await
            .map(|r| r.map_err(H2Error::from))
    }

    /// Initiate graceful shutdown of the server connection.
    ///
    /// Sends a GOAWAY frame to the client.  The connection is fully shut down
    /// when [`accept_request`](Self::accept_request) returns `None`.
    pub fn graceful_shutdown(&mut self) {
        self.inner.graceful_shutdown();
    }

    /// Returns `true` if there are active streams on this connection.
    pub fn has_streams(&self) -> bool {
        self.inner.has_streams()
    }
}

impl<IO> std::fmt::Debug for H2ServerConn<IO> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H2ServerConn").finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Stream count helper (shared with tests)
// ---------------------------------------------------------------------------

/// An `Arc<AtomicUsize>`-backed stream counter, useful for tests.
#[derive(Clone, Debug, Default)]
pub struct StreamCounter(Arc<AtomicUsize>);

impl StreamCounter {
    /// Create a new counter starting at zero.
    pub fn new() -> Self {
        Self(Arc::new(AtomicUsize::new(0)))
    }

    /// Increment the count.
    pub fn increment(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement the count.
    pub fn decrement(&self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }

    /// Return the current count.
    pub fn get(&self) -> usize {
        self.0.load(Ordering::Relaxed)
    }
}
