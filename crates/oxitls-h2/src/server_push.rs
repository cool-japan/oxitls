//! HTTP/2 server push helpers.

use bytes::Bytes;

use crate::H2Error;

/// A wrapper around [`h2::server::SendResponse`] that exposes server push.
///
/// Obtain one by calling
/// [`accept_request`](crate::H2ServerConn::accept_request) on an
/// [`H2ServerConn`](crate::H2ServerConn).
pub struct H2ServerPush {
    send_response: h2::server::SendResponse<Bytes>,
}

/// A handle to send the actual response for a previously pushed stream.
pub struct H2PushedStream {
    inner: h2::server::SendPushedResponse<Bytes>,
}

impl H2ServerPush {
    /// Wrap a raw [`h2::server::SendResponse`] handle.
    pub fn new(send_response: h2::server::SendResponse<Bytes>) -> Self {
        Self { send_response }
    }

    /// Send a push promise to the client, returning a handle to send the
    /// pushed response.
    ///
    /// `request` must use a safe, cacheable method (GET or HEAD).
    ///
    /// # Errors
    ///
    /// Returns an error if the connection does not support server push, or if
    /// the method is not safe/cacheable.
    pub fn push(&mut self, request: http::Request<()>) -> Result<H2PushedStream, H2Error> {
        self.send_response
            .push_request(request)
            .map(|inner| H2PushedStream { inner })
            .map_err(H2Error::from)
    }

    /// Access the underlying [`h2::server::SendResponse`] to send the actual
    /// response for the original request.
    pub fn into_inner(self) -> h2::server::SendResponse<Bytes> {
        self.send_response
    }
}

impl H2PushedStream {
    /// Send the headers for the pushed stream, returning a
    /// [`h2::SendStream`] for streaming the body.
    ///
    /// If `end_of_stream` is `true`, no body will be sent.
    pub fn send_response(
        mut self,
        response: http::Response<()>,
        end_of_stream: bool,
    ) -> Result<h2::SendStream<Bytes>, H2Error> {
        self.inner
            .send_response(response, end_of_stream)
            .map_err(H2Error::from)
    }
}

impl std::fmt::Debug for H2ServerPush {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H2ServerPush").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for H2PushedStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H2PushedStream").finish_non_exhaustive()
    }
}
