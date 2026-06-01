//! Flow-control helpers wrapping h2's [`FlowControl`](h2::FlowControl).

use crate::H2Error;

/// A thin wrapper around [`h2::FlowControl`] that uses `H2Error` for errors.
///
/// `FlowControl` manages the receive-side window for an HTTP/2 stream. After
/// consuming data received from a stream, callers must call
/// [`release_capacity`](OxiFlowControl::release_capacity) to allow the remote
/// to send more data.
pub struct OxiFlowControl {
    inner: h2::FlowControl,
}

impl OxiFlowControl {
    /// Wrap an existing [`h2::FlowControl`] handle.
    pub fn new(inner: h2::FlowControl) -> Self {
        Self { inner }
    }

    /// Returns the current available receive window capacity in bytes.
    ///
    /// This value may be negative if the remote has sent more data than the
    /// window allows (protocol error). A non-negative value indicates how many
    /// bytes the remote is currently allowed to send.
    pub fn available_capacity(&self) -> isize {
        self.inner.available_capacity()
    }

    /// Returns the amount of capacity currently used (received bytes not yet
    /// released back).
    pub fn used_capacity(&self) -> usize {
        self.inner.used_capacity()
    }

    /// Release previously consumed receive capacity back to the remote,
    /// allowing it to send `n` more bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if `n` exceeds the amount of data that has been
    /// received (i.e., the caller cannot release more than was received).
    pub fn release_capacity(&mut self, n: usize) -> Result<(), H2Error> {
        self.inner.release_capacity(n).map_err(H2Error::from)
    }
}

impl std::fmt::Debug for OxiFlowControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OxiFlowControl")
            .field("available_capacity", &self.inner.available_capacity())
            .finish()
    }
}
