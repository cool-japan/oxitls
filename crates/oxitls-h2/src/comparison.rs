//! HTTP/2 vs HTTP/3 feature comparison and migration path.
//!
//! # When to use HTTP/2 (this crate)
//!
//! Choose `oxitls-h2` when:
//! - You need broad reverse-proxy compatibility (nginx, HAProxy, Caddy all support H2)
//! - Your deployment uses TCP and TLS 1.3 (no QUIC/UDP needed)
//! - You need HTTP push ([`crate::H2ServerPush`], [`crate::H2PushedStream`])
//! - You target environments where UDP is firewalled (enterprise networks)
//!
//! # When to use HTTP/3 (oxiquic-h3)
//!
//! Choose HTTP/3 when:
//! - You need connection migration (mobile clients changing IP/network)
//! - You need 0-RTT request resumption (QUIC's built-in 0-RTT)
//! - You experience head-of-line blocking on lossy networks (QUIC has per-stream loss recovery)
//! - Your server runs on a QUIC-enabled load balancer
//!
//! # Feature comparison
//!
//! | Feature | HTTP/2 (`oxitls-h2`) | HTTP/3 (`oxiquic-h3`) |
//! |---------|---------------------|----------------------|
//! | Transport | TLS 1.3 over TCP | QUIC over UDP |
//! | Multiplexing | Yes (streams over single conn) | Yes (independent streams) |
//! | Header compression | HPACK | QPACK |
//! | Head-of-line blocking | TCP-level (single stream blocks) | None (per-stream) |
//! | Connection migration | No | Yes (QUIC CID) |
//! | Server push | Yes ([`crate::H2ServerPush`]) | Limited (H3 deprecated push) |
//! | 0-RTT | Via TLS session resumption | Native QUIC 0-RTT |
//! | Proxy support | Broad (decade of deployments) | Growing (2024+) |
//! | UDP firewall traversal | N/A (TCP) | Required (UDP 443) |
//!
//! # API symmetry
//!
//! The APIs are intentionally symmetric to ease migration:
//!
//! ```rust,ignore
//! // HTTP/2 client (oxitls-h2)
//! let h2 = H2ClientBuilder::new()
//!     .with_initial_window_size(1 << 20)
//!     .connect(tls_stream).await?;
//!
//! // HTTP/3 client (oxiquic-h3 — drop-in for many use cases)
//! let h3 = H3ClientBuilder::new()
//!     .connect(quic_connection).await?;
//! ```
//!
//! Key API mapping:
//!
//! | `oxitls-h2` | `oxiquic-h3` |
//! |-------------|-------------|
//! | [`crate::H2ClientBuilder`] | `H3ClientBuilder` |
//! | [`crate::H2ServerBuilder`] | `H3ServerBuilder` |
//! | [`crate::H2Settings`] | `H3Settings` |
//! | [`crate::H2Error`] | `H3Error` |
//! | [`crate::H2Connection`] | `H3Connection` |
//!
//! # Migration checklist
//!
//! 1. Replace `oxitls-h2` with `oxiquic-h3` in `Cargo.toml`.
//! 2. Replace `TlsStream` transport with a `quic_connection` from `oxiquic`.
//! 3. Replace `H2ClientBuilder` with `H3ClientBuilder` (same builder pattern).
//! 4. Replace [`crate::H2Settings`] with `H3Settings` (field names differ; see each type's docs).
//! 5. Remove any [`crate::H2ServerPush`] usage (H3 deprecated push).
//! 6. Update ALPN: `b"h2"` → `b"h3"` (or use the `alpn_protocols()` builder method).

/// A type alias for [`crate::H2ClientBuilder`] to emphasise the H2-vs-H3 mapping.
///
/// In HTTP/3 codebases this corresponds to `oxiquic_h3::H3ClientBuilder`.
pub type H2Builder = crate::H2ClientBuilder;
