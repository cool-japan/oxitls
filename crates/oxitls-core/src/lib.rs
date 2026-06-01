#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! `oxitls-core` — Pure-Rust TLS transport primitives.
//!
//! This crate provides the foundational types used across the OxiTLS ecosystem:
//! error types, TLS version and cipher suite enumerations, connection
//! information, and trait definitions for TLS connectors/acceptors.

use std::fmt;
use std::future::Future;
use std::io;
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncWrite};

// ── Sub-modules ───────────────────────────────────────────────────────────────

/// OS-entropy CSPRNG adapter implementing the `rand_core` 0.6 traits required
/// by `rsa`/`ed25519-dalek`/`x25519-dalek` (decoupled from the workspace
/// `rand`/`rand_core` 0.10).
pub mod os_rng;

/// Key-logging policy for TLS session secret export.
pub mod keylog;

/// TLS alert description codes (RFC 8446 §6).
pub mod alert;

/// Generic TLS configuration introspection trait.
pub mod config;

/// Helpers for extracting [`ConnectionInfo`] from a rustls connection state.
pub mod stream_info;

// Re-export top-level for backward compatibility.
pub use alert::AlertDescription;
pub use keylog::{KeyLog, KeyLogPolicy};
pub use os_rng::OsRng;
pub use stream_info::connection_info_from;

// ── TLS Version ──────────────────────────────────────────────────────────────

/// TLS protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsVersion {
    /// TLS 1.2 (RFC 5246)
    Tls12,
    /// TLS 1.3 (RFC 8446)
    Tls13,
}

impl TlsVersion {
    /// All known TLS versions, in ascending order.
    pub const ALL: &'static [TlsVersion] = &[TlsVersion::Tls12, TlsVersion::Tls13];
}

impl fmt::Display for TlsVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlsVersion::Tls12 => write!(f, "TLS 1.2"),
            TlsVersion::Tls13 => write!(f, "TLS 1.3"),
        }
    }
}

impl std::str::FromStr for TlsVersion {
    type Err = TlsError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "TLS 1.2" | "tls1.2" | "TLSv1.2" | "1.2" => Ok(TlsVersion::Tls12),
            "TLS 1.3" | "tls1.3" | "TLSv1.3" | "1.3" => Ok(TlsVersion::Tls13),
            _ => Err(TlsError::Other(format!("unknown TLS version: {s}"))),
        }
    }
}

// ── Cipher Suite ─────────────────────────────────────────────────────────────

/// TLS cipher suite identifiers covering TLS 1.3 mandatory suites and
/// commonly-used TLS 1.2 AEAD suites.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CipherSuite {
    // ── TLS 1.3 (RFC 8446, Section 9.1) ──
    /// TLS_AES_128_GCM_SHA256 (0x13,0x01)
    Tls13Aes128GcmSha256,
    /// TLS_AES_256_GCM_SHA384 (0x13,0x02)
    Tls13Aes256GcmSha384,
    /// TLS_CHACHA20_POLY1305_SHA256 (0x13,0x03)
    Tls13Chacha20Poly1305Sha256,

    // ── TLS 1.2 AEAD suites ──
    /// TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xC0,0x2B)
    Tls12EcdheEcdsaAes128GcmSha256,
    /// TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (0xC0,0x2C)
    Tls12EcdheEcdsaAes256GcmSha384,
    /// TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xC0,0x2F)
    Tls12EcdheRsaAes128GcmSha256,
    /// TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xC0,0x30)
    Tls12EcdheRsaAes256GcmSha384,
    /// TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0xCC,0xA9)
    Tls12EcdheEcdsaChacha20Poly1305Sha256,
    /// TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xCC,0xA8)
    Tls12EcdheRsaChacha20Poly1305Sha256,
    /// An unrecognised cipher suite not covered by the variants above.
    Unknown,
}

impl CipherSuite {
    /// Returns the IANA two-byte identifier for this cipher suite.
    ///
    /// Returns `[0x00, 0x00]` for [`CipherSuite::Unknown`].
    pub fn iana_value(&self) -> [u8; 2] {
        match self {
            CipherSuite::Tls13Aes128GcmSha256 => [0x13, 0x01],
            CipherSuite::Tls13Aes256GcmSha384 => [0x13, 0x02],
            CipherSuite::Tls13Chacha20Poly1305Sha256 => [0x13, 0x03],
            CipherSuite::Tls12EcdheEcdsaAes128GcmSha256 => [0xC0, 0x2B],
            CipherSuite::Tls12EcdheEcdsaAes256GcmSha384 => [0xC0, 0x2C],
            CipherSuite::Tls12EcdheRsaAes128GcmSha256 => [0xC0, 0x2F],
            CipherSuite::Tls12EcdheRsaAes256GcmSha384 => [0xC0, 0x30],
            CipherSuite::Tls12EcdheEcdsaChacha20Poly1305Sha256 => [0xCC, 0xA9],
            CipherSuite::Tls12EcdheRsaChacha20Poly1305Sha256 => [0xCC, 0xA8],
            CipherSuite::Unknown => [0xFF, 0xFF],
        }
    }

    /// Try to look up a cipher suite from its IANA two-byte identifier.
    pub fn from_iana(bytes: [u8; 2]) -> Option<Self> {
        match bytes {
            [0x13, 0x01] => Some(CipherSuite::Tls13Aes128GcmSha256),
            [0x13, 0x02] => Some(CipherSuite::Tls13Aes256GcmSha384),
            [0x13, 0x03] => Some(CipherSuite::Tls13Chacha20Poly1305Sha256),
            [0xC0, 0x2B] => Some(CipherSuite::Tls12EcdheEcdsaAes128GcmSha256),
            [0xC0, 0x2C] => Some(CipherSuite::Tls12EcdheEcdsaAes256GcmSha384),
            [0xC0, 0x2F] => Some(CipherSuite::Tls12EcdheRsaAes128GcmSha256),
            [0xC0, 0x30] => Some(CipherSuite::Tls12EcdheRsaAes256GcmSha384),
            [0xCC, 0xA9] => Some(CipherSuite::Tls12EcdheEcdsaChacha20Poly1305Sha256),
            [0xCC, 0xA8] => Some(CipherSuite::Tls12EcdheRsaChacha20Poly1305Sha256),
            _ => None,
        }
    }

    /// Whether this suite belongs to TLS 1.3.
    pub fn is_tls13(&self) -> bool {
        matches!(
            self,
            CipherSuite::Tls13Aes128GcmSha256
                | CipherSuite::Tls13Aes256GcmSha384
                | CipherSuite::Tls13Chacha20Poly1305Sha256
        )
    }

    /// Whether this suite belongs to TLS 1.2.
    pub fn is_tls12(&self) -> bool {
        matches!(
            self,
            CipherSuite::Tls12EcdheEcdsaAes128GcmSha256
                | CipherSuite::Tls12EcdheEcdsaAes256GcmSha384
                | CipherSuite::Tls12EcdheRsaAes128GcmSha256
                | CipherSuite::Tls12EcdheRsaAes256GcmSha384
                | CipherSuite::Tls12EcdheEcdsaChacha20Poly1305Sha256
                | CipherSuite::Tls12EcdheRsaChacha20Poly1305Sha256
        )
    }

    /// Whether this is the `Unknown` catch-all variant.
    pub fn is_unknown(&self) -> bool {
        matches!(self, CipherSuite::Unknown)
    }

    /// All named cipher suites (excluding [`CipherSuite::Unknown`]).
    pub const ALL: &'static [CipherSuite] = &[
        CipherSuite::Tls13Aes128GcmSha256,
        CipherSuite::Tls13Aes256GcmSha384,
        CipherSuite::Tls13Chacha20Poly1305Sha256,
        CipherSuite::Tls12EcdheEcdsaAes128GcmSha256,
        CipherSuite::Tls12EcdheEcdsaAes256GcmSha384,
        CipherSuite::Tls12EcdheRsaAes128GcmSha256,
        CipherSuite::Tls12EcdheRsaAes256GcmSha384,
        CipherSuite::Tls12EcdheEcdsaChacha20Poly1305Sha256,
        CipherSuite::Tls12EcdheRsaChacha20Poly1305Sha256,
    ];
}

impl fmt::Display for CipherSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            CipherSuite::Tls13Aes128GcmSha256 => "TLS_AES_128_GCM_SHA256",
            CipherSuite::Tls13Aes256GcmSha384 => "TLS_AES_256_GCM_SHA384",
            CipherSuite::Tls13Chacha20Poly1305Sha256 => "TLS_CHACHA20_POLY1305_SHA256",
            CipherSuite::Tls12EcdheEcdsaAes128GcmSha256 => {
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
            }
            CipherSuite::Tls12EcdheEcdsaAes256GcmSha384 => {
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
            }
            CipherSuite::Tls12EcdheRsaAes128GcmSha256 => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            CipherSuite::Tls12EcdheRsaAes256GcmSha384 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            CipherSuite::Tls12EcdheEcdsaChacha20Poly1305Sha256 => {
                "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
            }
            CipherSuite::Tls12EcdheRsaChacha20Poly1305Sha256 => {
                "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
            }
            CipherSuite::Unknown => "UNKNOWN",
        };
        write!(f, "{name}")
    }
}

impl std::str::FromStr for CipherSuite {
    type Err = TlsError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "TLS_AES_128_GCM_SHA256" => Ok(CipherSuite::Tls13Aes128GcmSha256),
            "TLS_AES_256_GCM_SHA384" => Ok(CipherSuite::Tls13Aes256GcmSha384),
            "TLS_CHACHA20_POLY1305_SHA256" => Ok(CipherSuite::Tls13Chacha20Poly1305Sha256),
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" => {
                Ok(CipherSuite::Tls12EcdheEcdsaAes128GcmSha256)
            }
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" => {
                Ok(CipherSuite::Tls12EcdheEcdsaAes256GcmSha384)
            }
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" => {
                Ok(CipherSuite::Tls12EcdheRsaAes128GcmSha256)
            }
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" => {
                Ok(CipherSuite::Tls12EcdheRsaAes256GcmSha384)
            }
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" => {
                Ok(CipherSuite::Tls12EcdheEcdsaChacha20Poly1305Sha256)
            }
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" => {
                Ok(CipherSuite::Tls12EcdheRsaChacha20Poly1305Sha256)
            }
            "UNKNOWN" => Ok(CipherSuite::Unknown),
            _ => Err(TlsError::Other(format!("unknown cipher suite: {s}"))),
        }
    }
}

// ── Connection Info ──────────────────────────────────────────────────────────

/// Information about a completed TLS connection.
///
/// Constructed incrementally by adapter crates after the handshake completes.
/// The builder pattern allows partial population (e.g. ALPN may be `None` if
/// not negotiated).
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    /// The negotiated TLS protocol version.
    pub version: Option<TlsVersion>,
    /// The negotiated cipher suite.
    pub cipher_suite: Option<CipherSuite>,
    /// The negotiated ALPN protocol (e.g. `b"h2"`, `b"http/1.1"`).
    pub alpn_protocol: Option<Vec<u8>>,
    /// The SNI (Server Name Indication) value sent by the client.
    pub sni: Option<String>,
    /// DER-encoded peer certificates (leaf first), if provided.
    pub peer_certificates: Vec<Vec<u8>>,
}

impl ConnectionInfo {
    /// Create a new empty `ConnectionInfo`.
    pub fn new() -> Self {
        Self {
            version: None,
            cipher_suite: None,
            alpn_protocol: None,
            sni: None,
            peer_certificates: Vec::new(),
        }
    }

    /// Set the negotiated TLS version.
    pub fn with_version(mut self, version: TlsVersion) -> Self {
        self.version = Some(version);
        self
    }

    /// Set the negotiated cipher suite.
    pub fn with_cipher_suite(mut self, suite: CipherSuite) -> Self {
        self.cipher_suite = Some(suite);
        self
    }

    /// Set the negotiated ALPN protocol.
    pub fn with_alpn_protocol(mut self, proto: Vec<u8>) -> Self {
        self.alpn_protocol = Some(proto);
        self
    }

    /// Set the SNI name.
    pub fn with_sni(mut self, sni: String) -> Self {
        self.sni = Some(sni);
        self
    }

    /// Set the peer certificate chain (DER-encoded, leaf first).
    pub fn with_peer_certificates(mut self, certs: Vec<Vec<u8>>) -> Self {
        self.peer_certificates = certs;
        self
    }

    /// The negotiated ALPN protocol as a UTF-8 string, if it is valid UTF-8.
    pub fn alpn_protocol_str(&self) -> Option<&str> {
        self.alpn_protocol
            .as_ref()
            .and_then(|p| std::str::from_utf8(p).ok())
    }
}

impl Default for ConnectionInfo {
    fn default() -> Self {
        Self::new()
    }
}

// ── ConnectionInfo Builder ───────────────────────────────────────────────────

/// Fluent builder for [`ConnectionInfo`].
///
/// Provides a separate builder type for constructing `ConnectionInfo` using
/// snake_case setter methods (`version()`, `cipher_suite()`, etc.) rather than
/// the `with_*` methods on `ConnectionInfo` itself.
///
/// # Example
/// ```
/// use oxitls_core::{CipherSuite, ConnectionInfoBuilder, TlsVersion};
///
/// let info = ConnectionInfoBuilder::new()
///     .version(TlsVersion::Tls13)
///     .cipher_suite(CipherSuite::Tls13Aes256GcmSha384)
///     .alpn_protocol(b"h2".to_vec())
///     .sni("example.com".to_string())
///     .build();
///
/// assert_eq!(info.version, Some(TlsVersion::Tls13));
/// ```
#[derive(Debug, Default)]
pub struct ConnectionInfoBuilder {
    inner: ConnectionInfo,
}

impl ConnectionInfoBuilder {
    /// Create a new builder with all fields set to `None`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the negotiated TLS version.
    pub fn version(mut self, version: TlsVersion) -> Self {
        self.inner.version = Some(version);
        self
    }

    /// Set the negotiated cipher suite.
    pub fn cipher_suite(mut self, suite: CipherSuite) -> Self {
        self.inner.cipher_suite = Some(suite);
        self
    }

    /// Set the negotiated ALPN protocol bytes.
    pub fn alpn_protocol(mut self, proto: Vec<u8>) -> Self {
        self.inner.alpn_protocol = Some(proto);
        self
    }

    /// Set the SNI server name.
    pub fn sni(mut self, sni: String) -> Self {
        self.inner.sni = Some(sni);
        self
    }

    /// Set the peer certificate chain (DER-encoded, leaf first).
    pub fn peer_certificates(mut self, certs: Vec<Vec<u8>>) -> Self {
        self.inner.peer_certificates = certs;
        self
    }

    /// Consume the builder and produce a [`ConnectionInfo`].
    pub fn build(self) -> ConnectionInfo {
        self.inner
    }
}

// ── TLS Error ────────────────────────────────────────────────────────────────

/// Errors that can occur during TLS operations.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum TlsError {
    /// An I/O error occurred, identified by its kind.
    Io(io::ErrorKind),
    /// A TLS handshake error.
    Handshake(String),
    /// An invalid or unacceptable certificate.
    BadCert(String),
    /// The TLS configuration is invalid.
    InvalidConfig(String),
    /// A certificate has been revoked (CRL or OCSP).
    CertRevoked(String),
    /// A certificate is invalid (e.g. bad signature, malformed DER, expired).
    CertInvalid(String),
    /// The remote peer violated the TLS protocol.
    ProtocolViolation(String),
    /// A TLS alert was received from the peer.
    AlertReceived(AlertDescription),
    /// Any other TLS error.
    Other(String),
}

impl TlsError {
    /// Returns `true` if this is a handshake error.
    pub fn is_handshake(&self) -> bool {
        matches!(self, TlsError::Handshake(_))
    }

    /// Returns `true` if this is an I/O error.
    pub fn is_io(&self) -> bool {
        matches!(self, TlsError::Io(_))
    }

    /// Returns `true` if this is a certificate-related error.
    pub fn is_cert(&self) -> bool {
        matches!(
            self,
            TlsError::BadCert(_) | TlsError::CertRevoked(_) | TlsError::CertInvalid(_)
        )
    }

    /// Returns `true` if this is a configuration error.
    pub fn is_config(&self) -> bool {
        matches!(self, TlsError::InvalidConfig(_))
    }

    /// Returns `true` if this is a protocol-violation error.
    pub fn is_protocol_violation(&self) -> bool {
        matches!(self, TlsError::ProtocolViolation(_))
    }
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlsError::Io(k) => write!(f, "I/O error: {k:?}"),
            TlsError::Handshake(s) => write!(f, "handshake error: {s}"),
            TlsError::BadCert(s) => write!(f, "bad certificate: {s}"),
            TlsError::InvalidConfig(s) => write!(f, "invalid config: {s}"),
            TlsError::CertRevoked(s) => write!(f, "certificate revoked: {s}"),
            TlsError::CertInvalid(s) => write!(f, "invalid certificate: {s}"),
            TlsError::ProtocolViolation(s) => write!(f, "protocol violation: {s}"),
            TlsError::AlertReceived(d) => write!(f, "TLS alert received: {d}"),
            TlsError::Other(s) => write!(f, "TLS error: {s}"),
        }
    }
}

impl std::error::Error for TlsError {}

impl From<io::Error> for TlsError {
    fn from(e: io::Error) -> Self {
        TlsError::Io(e.kind())
    }
}

impl From<TlsError> for io::Error {
    fn from(e: TlsError) -> Self {
        match e {
            TlsError::Io(kind) => io::Error::new(kind, "TLS I/O error"),
            TlsError::Handshake(s) => io::Error::new(io::ErrorKind::ConnectionAborted, s),
            TlsError::BadCert(s) => io::Error::new(io::ErrorKind::InvalidData, s),
            TlsError::InvalidConfig(s) => io::Error::new(io::ErrorKind::InvalidInput, s),
            TlsError::CertRevoked(s) => io::Error::new(io::ErrorKind::PermissionDenied, s),
            TlsError::CertInvalid(s) => io::Error::new(io::ErrorKind::InvalidData, s),
            TlsError::ProtocolViolation(s) => io::Error::new(io::ErrorKind::InvalidData, s),
            TlsError::AlertReceived(d) => {
                io::Error::new(io::ErrorKind::ConnectionAborted, format!("TLS alert: {d}"))
            }
            TlsError::Other(s) => io::Error::other(s),
        }
    }
}

impl From<rustls::Error> for TlsError {
    fn from(e: rustls::Error) -> Self {
        match &e {
            rustls::Error::NoCertificatesPresented => {
                TlsError::CertInvalid("no certificates presented".to_string())
            }
            rustls::Error::UnsupportedNameType => {
                TlsError::CertInvalid("unsupported name type".to_string())
            }
            rustls::Error::InvalidCertificate(reason) => {
                TlsError::CertInvalid(format!("{reason:?}"))
            }
            rustls::Error::PeerIncompatible(reason) => {
                TlsError::ProtocolViolation(format!("{reason:?}"))
            }
            rustls::Error::PeerMisbehaved(reason) => {
                TlsError::ProtocolViolation(format!("{reason:?}"))
            }
            rustls::Error::AlertReceived(alert) => TlsError::Handshake(format!("alert: {alert:?}")),
            rustls::Error::BadMaxFragmentSize => {
                TlsError::InvalidConfig("bad max fragment size".to_string())
            }
            rustls::Error::General(s) => TlsError::Other(s.clone()),
            _ => TlsError::Other(e.to_string()),
        }
    }
}

// ── TLS Stream ───────────────────────────────────────────────────────────────

/// A boxed async stream that can be read from and written to.
pub type TlsStream = Box<dyn TlsStreamTrait>;

/// Trait alias for an async TLS stream.
pub trait TlsStreamTrait: AsyncRead + AsyncWrite + Send + Sync + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Sync + Unpin> TlsStreamTrait for T {}

/// Types that can establish outbound TLS connections.
///
/// Implementations wrap a transport-layer stream in a TLS client handshake,
/// producing a [`TlsStream`] on success.  The trait is object-safe: it can be
/// used through `Box<dyn TlsConnector>` or `Arc<dyn TlsConnector>`.
pub trait TlsConnector: Send + Sync + 'static {
    /// Perform the TLS client handshake over `stream`, using `server_name`
    /// for SNI and certificate verification.
    ///
    /// Returns the wrapped [`TlsStream`] on success, or a [`TlsError`] on
    /// failure.
    fn connect(
        &self,
        stream: TlsStream,
        server_name: rustls::pki_types::ServerName<'static>,
    ) -> Pin<Box<dyn Future<Output = Result<TlsStream, TlsError>> + Send + '_>>;
}

/// Types that can accept inbound TLS connections.
///
/// Implementations wrap a transport-layer stream in a TLS server handshake,
/// producing a [`TlsStream`] on success.  The trait is object-safe: it can be
/// used through `Box<dyn TlsAcceptor>` or `Arc<dyn TlsAcceptor>`.
pub trait TlsAcceptor: Send + Sync + 'static {
    /// Perform the TLS server handshake over `stream`.
    ///
    /// Returns the wrapped [`TlsStream`] on success, or a [`TlsError`] on
    /// failure.
    fn accept(
        &self,
        stream: TlsStream,
    ) -> Pin<Box<dyn Future<Output = Result<TlsStream, TlsError>> + Send + '_>>;
}

/// Trait for TLS streams that can expose post-handshake connection metadata.
///
/// Implementors may override [`Self::connection_info`] to return a reference to the
/// [`ConnectionInfo`] populated after the handshake completes. The default
/// implementation returns `None`, which is appropriate for stream wrappers that
/// do not have access to connection metadata (e.g. transparent proxies).
///
/// # Example
/// ```
/// use oxitls_core::{ConnectionInfo, TlsStreamInfo};
///
/// struct MyStream {
///     info: ConnectionInfo,
/// }
///
/// impl TlsStreamInfo for MyStream {
///     fn connection_info(&self) -> Option<&ConnectionInfo> {
///         Some(&self.info)
///     }
/// }
/// ```
pub trait TlsStreamInfo {
    /// Return the [`ConnectionInfo`] for this stream, if available.
    ///
    /// Returns `None` until the TLS handshake has completed, or for streams
    /// that do not expose connection metadata.
    fn connection_info(&self) -> Option<&ConnectionInfo> {
        None
    }
}

// ── Generic Transport GAT Traits ─────────────────────────────────────────────

/// Boxed, pinned future returned by [`GenericTlsConnector`] and
/// [`GenericTlsAcceptor`] method implementations.
///
/// The lifetime `'a` is tied to `&'a self` so that implementations may borrow
/// `self` inside the async block.
#[cfg(feature = "generic-transport")]
pub type GenericTlsFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, TlsError>> + Send + 'a>>;

/// Types that can establish outbound TLS connections while preserving the
/// concrete underlying transport type.
///
/// Unlike [`TlsConnector`], which erases the transport to `Box<dyn
/// TlsStreamTrait>`, this trait uses a generic associated type (GAT)
/// `Stream<S>` so callers retain the concrete `S` through the TLS layer.
/// This avoids heap allocation of the transport itself: only the returned
/// `Future` is boxed.
///
/// # Usage
///
/// Implementations are used through `<C: GenericTlsConnector>` bounds, not
/// through `dyn GenericTlsConnector` (the GAT makes the trait non-object-safe).
///
/// # Example
///
/// ```ignore
/// async fn connect_plain<C: GenericTlsConnector, S>(
///     connector: &C,
///     stream: S,
///     name: rustls::pki_types::ServerName<'static>,
/// ) -> Result<C::Stream<S>, TlsError>
/// where
///     S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
/// {
///     connector.connect(stream, name).await
/// }
/// ```
#[cfg(feature = "generic-transport")]
pub trait GenericTlsConnector: Send + Sync + 'static {
    /// The TLS-wrapped stream type.  Preserves the concrete transport `S`.
    type Stream<S>: AsyncRead + AsyncWrite + Unpin + Send + TlsStreamInfo
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    /// Perform the TLS client handshake over `stream`, using `server_name`
    /// for SNI and certificate verification.
    ///
    /// Returns the wrapped `Self::Stream<S>` on success, or a [`TlsError`] on
    /// failure.  The returned `Future` is boxed so the method is callable from
    /// `dyn`-erased contexts that don't use the GAT.
    fn connect<S>(
        &self,
        stream: S,
        server_name: rustls::pki_types::ServerName<'static>,
    ) -> GenericTlsFuture<'_, Self::Stream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static;
}

/// Types that can accept inbound TLS connections while preserving the concrete
/// underlying transport type.
///
/// The mirror of [`GenericTlsConnector`] for the server side.  The GAT
/// `Stream<S>` avoids erasing the transport to a boxed trait object; only the
/// returned `Future` is boxed.
///
/// # Usage
///
/// Implementations are used through `<A: GenericTlsAcceptor>` bounds, not
/// through `dyn GenericTlsAcceptor` (the GAT makes the trait non-object-safe).
#[cfg(feature = "generic-transport")]
pub trait GenericTlsAcceptor: Send + Sync + 'static {
    /// The TLS-wrapped stream type.  Preserves the concrete transport `S`.
    type Stream<S>: AsyncRead + AsyncWrite + Unpin + Send + TlsStreamInfo
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    /// Perform the TLS server handshake over `stream`.
    ///
    /// Returns the wrapped `Self::Stream<S>` on success, or a [`TlsError`] on
    /// failure.  The returned `Future` is boxed so the method is callable from
    /// `dyn`-erased contexts that don't use the GAT.
    fn accept<S>(&self, stream: S) -> GenericTlsFuture<'_, Self::Stream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static;
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_version_display_roundtrip() {
        let v13 = TlsVersion::Tls13;
        let s = v13.to_string();
        assert_eq!(s, "TLS 1.3");
        let parsed: TlsVersion = s.parse().expect("should parse");
        assert_eq!(parsed, v13);

        let v12 = TlsVersion::Tls12;
        let s = v12.to_string();
        assert_eq!(s, "TLS 1.2");
        let parsed: TlsVersion = s.parse().expect("should parse");
        assert_eq!(parsed, v12);
    }

    #[test]
    fn tls_version_parse_variants() {
        assert_eq!("tls1.3".parse::<TlsVersion>().ok(), Some(TlsVersion::Tls13));
        assert_eq!(
            "TLSv1.2".parse::<TlsVersion>().ok(),
            Some(TlsVersion::Tls12)
        );
        assert_eq!("1.3".parse::<TlsVersion>().ok(), Some(TlsVersion::Tls13));
        assert!("TLS 1.0".parse::<TlsVersion>().is_err());
    }

    #[test]
    fn cipher_suite_display_roundtrip() {
        let suites = [
            CipherSuite::Tls13Aes128GcmSha256,
            CipherSuite::Tls13Aes256GcmSha384,
            CipherSuite::Tls13Chacha20Poly1305Sha256,
            CipherSuite::Tls12EcdheEcdsaAes128GcmSha256,
            CipherSuite::Tls12EcdheEcdsaAes256GcmSha384,
            CipherSuite::Tls12EcdheRsaAes128GcmSha256,
            CipherSuite::Tls12EcdheRsaAes256GcmSha384,
            CipherSuite::Tls12EcdheEcdsaChacha20Poly1305Sha256,
            CipherSuite::Tls12EcdheRsaChacha20Poly1305Sha256,
        ];
        for suite in &suites {
            let s = suite.to_string();
            let parsed: CipherSuite = s.parse().expect("should parse");
            assert_eq!(&parsed, suite);
        }
    }

    #[test]
    fn cipher_suite_iana_roundtrip() {
        let suites = [
            CipherSuite::Tls13Aes128GcmSha256,
            CipherSuite::Tls13Aes256GcmSha384,
            CipherSuite::Tls13Chacha20Poly1305Sha256,
            CipherSuite::Tls12EcdheEcdsaAes128GcmSha256,
            CipherSuite::Tls12EcdheRsaChacha20Poly1305Sha256,
        ];
        for suite in &suites {
            let iana = suite.iana_value();
            let from_iana = CipherSuite::from_iana(iana);
            assert_eq!(from_iana, Some(*suite));
        }
        assert_eq!(CipherSuite::from_iana([0xFF, 0xFF]), None);
    }

    #[test]
    fn cipher_suite_version_classification() {
        assert!(CipherSuite::Tls13Aes128GcmSha256.is_tls13());
        assert!(!CipherSuite::Tls13Aes128GcmSha256.is_tls12());
        assert!(CipherSuite::Tls12EcdheRsaAes128GcmSha256.is_tls12());
        assert!(!CipherSuite::Tls12EcdheRsaAes128GcmSha256.is_tls13());
    }

    #[test]
    fn connection_info_builder() {
        let info = ConnectionInfo::new()
            .with_version(TlsVersion::Tls13)
            .with_cipher_suite(CipherSuite::Tls13Aes256GcmSha384)
            .with_alpn_protocol(b"h2".to_vec())
            .with_sni("example.com".to_string());

        assert_eq!(info.version, Some(TlsVersion::Tls13));
        assert_eq!(info.cipher_suite, Some(CipherSuite::Tls13Aes256GcmSha384));
        assert_eq!(info.alpn_protocol_str(), Some("h2"));
        assert_eq!(info.sni.as_deref(), Some("example.com"));
        assert!(info.peer_certificates.is_empty());
    }

    #[test]
    fn connection_info_default() {
        let info = ConnectionInfo::default();
        assert_eq!(info.version, None);
        assert_eq!(info.cipher_suite, None);
        assert_eq!(info.alpn_protocol, None);
        assert_eq!(info.sni, None);
        assert!(info.peer_certificates.is_empty());
    }

    #[test]
    fn tls_error_display_all_variants() {
        let cases = [
            (TlsError::Io(io::ErrorKind::BrokenPipe), "I/O error:"),
            (TlsError::Handshake("test".into()), "handshake error:"),
            (TlsError::BadCert("test".into()), "bad certificate:"),
            (TlsError::InvalidConfig("test".into()), "invalid config:"),
            (TlsError::CertRevoked("test".into()), "certificate revoked:"),
            (TlsError::Other("test".into()), "TLS error:"),
        ];
        for (err, prefix) in &cases {
            assert!(
                err.to_string().starts_with(prefix),
                "{err} should start with {prefix}"
            );
        }
    }

    #[test]
    fn tls_error_predicates() {
        assert!(TlsError::Handshake("x".into()).is_handshake());
        assert!(!TlsError::Handshake("x".into()).is_io());
        assert!(TlsError::Io(io::ErrorKind::Other).is_io());
        assert!(TlsError::BadCert("x".into()).is_cert());
        assert!(TlsError::CertRevoked("x".into()).is_cert());
        assert!(!TlsError::Other("x".into()).is_cert());
        assert!(TlsError::InvalidConfig("x".into()).is_config());
    }

    #[test]
    fn tls_error_from_io_error() {
        let io_err = io::Error::new(io::ErrorKind::ConnectionRefused, "refused");
        let tls_err = TlsError::from(io_err);
        assert!(tls_err.is_io());
    }

    #[test]
    fn tls_error_into_io_error() {
        let cases: Vec<TlsError> = vec![
            TlsError::Io(io::ErrorKind::BrokenPipe),
            TlsError::Handshake("hs".into()),
            TlsError::BadCert("bc".into()),
            TlsError::InvalidConfig("ic".into()),
            TlsError::CertRevoked("cr".into()),
            TlsError::Other("ot".into()),
        ];
        for tls_err in cases {
            let io_err: io::Error = tls_err.into();
            // Just verify conversion works and kind is sensible.
            let _ = io_err.kind();
        }
    }
}
