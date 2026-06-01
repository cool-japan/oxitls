//! Wave 8 integration tests for the `generic-transport` feature.
//!
//! These tests exercise `GenericTlsConnector`, `GenericTlsAcceptor`, and the
//! `#[non_exhaustive]` attribute on `TlsError` from *outside* the defining
//! crate (the exhaustiveness rules that matter for downstream crates).
#![cfg(feature = "generic-transport")]

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use oxitls_core::{
    GenericTlsAcceptor, GenericTlsConnector, GenericTlsFuture, TlsError, TlsStreamInfo,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

// ── Passthrough newtype ───────────────────────────────────────────────────────
//
// `type Stream<S> = S` alone would require `S: TlsStreamInfo` on every call
// site (no blanket impl is possible from the test crate due to orphan rules).
// A local newtype satisfies the GAT bound via a local `TlsStreamInfo` impl.

/// Transparent wrapper that forwards `AsyncRead`/`AsyncWrite` to `S` and
/// implements `TlsStreamInfo` via the default (returns `None`) impl.
struct Passthrough<S> {
    inner: S,
}

impl<S: AsyncRead + Unpin> AsyncRead for Passthrough<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Passthrough<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

// Local type — orphan rule is satisfied; TlsStreamInfo::connection_info returns
// `None` by default, which is correct for a passthrough shim.
impl<S> TlsStreamInfo for Passthrough<S> {}

// ── Toy connector (no actual TLS) ─────────────────────────────────────────────

struct PassthroughConnector;

impl GenericTlsConnector for PassthroughConnector {
    type Stream<S>
        = Passthrough<S>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    fn connect<S>(
        &self,
        stream: S,
        _server_name: rustls::pki_types::ServerName<'static>,
    ) -> GenericTlsFuture<'_, Self::Stream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Box::pin(async move { Ok(Passthrough { inner: stream }) })
    }
}

// ── Toy acceptor ─────────────────────────────────────────────────────────────

struct PassthroughAcceptor;

impl GenericTlsAcceptor for PassthroughAcceptor {
    type Stream<S>
        = Passthrough<S>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    fn accept<S>(&self, stream: S) -> GenericTlsFuture<'_, Self::Stream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Box::pin(async move { Ok(Passthrough { inner: stream }) })
    }
}

// ── (b) Compile-time check: trait bound on generic function ──────────────────

/// Verifies that `GenericTlsConnector` can be used as a monomorphised bound.
/// This function is never called at runtime; its existence is the test.
#[allow(dead_code)]
fn uses_generic_connector<C: GenericTlsConnector>(_c: &C) {}

/// Verifies that `GenericTlsAcceptor` can be used as a monomorphised bound.
#[allow(dead_code)]
fn uses_generic_acceptor<A: GenericTlsAcceptor>(_a: &A) {}

// ── (c) Compile-time check: non_exhaustive outside the crate ─────────────────

/// Matching a `TlsError` from outside the defining crate requires a wildcard
/// because `#[non_exhaustive]` is in effect here.  If the attribute were
/// removed, this function would still compile (the wildcard is merely
/// unreachable), but the *absence* of a compile error when the wildcard is
/// removed would be the failure.  The meaningful assertion is that adding a
/// new variant to `TlsError` in the future will NOT break this match.
#[allow(dead_code)]
fn non_exhaustive_tls_error_match(e: &TlsError) {
    match e {
        TlsError::Io(_) => {}
        TlsError::Handshake(_) => {}
        TlsError::BadCert(_) => {}
        TlsError::InvalidConfig(_) => {}
        TlsError::CertRevoked(_) => {}
        TlsError::CertInvalid(_) => {}
        TlsError::ProtocolViolation(_) => {}
        TlsError::AlertReceived(_) => {}
        TlsError::Other(_) => {}
        _ => {}
    }
}

// ── (a) Runtime test: connect returns the correct concrete type ───────────────

#[tokio::test]
async fn passthrough_connector_returns_concrete_passthrough_type() {
    use tokio::io::duplex;

    let (client_half, _server_half) = duplex(1024);

    let connector = PassthroughConnector;
    let server_name: rustls::pki_types::ServerName<'static> =
        rustls::pki_types::ServerName::try_from("localhost")
            .expect("valid ServerName")
            .to_owned();

    // The returned value is `Passthrough<DuplexStream>` — proved by type
    // inference: if the types did not match the assignment would fail to compile.
    let wrapped: Passthrough<tokio::io::DuplexStream> = connector
        .connect(client_half, server_name)
        .await
        .expect("connect ok");

    // connection_info() returns None (default impl on Passthrough<S>)
    assert!(wrapped.connection_info().is_none());
}

#[tokio::test]
async fn passthrough_acceptor_returns_concrete_passthrough_type() {
    use tokio::io::duplex;

    let (_client_half, server_half) = duplex(1024);

    let acceptor = PassthroughAcceptor;
    let wrapped: Passthrough<tokio::io::DuplexStream> =
        acceptor.accept(server_half).await.expect("accept ok");

    assert!(wrapped.connection_info().is_none());
}

#[tokio::test]
async fn generic_connector_trait_bound_compiles() {
    // Invoke the compile-time helper to ensure monomorphisation works.
    uses_generic_connector(&PassthroughConnector);
    uses_generic_acceptor(&PassthroughAcceptor);
}
