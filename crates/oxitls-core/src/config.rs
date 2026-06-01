//! Generic TLS configuration introspection trait.

use crate::{CipherSuite, TlsVersion};

/// A trait for generic introspection of TLS configuration.
///
/// Adapter crates implement this trait on their configuration structs to
/// allow higher-level crates (e.g. `oxitls`, `oxitls-h2`) to read
/// the effective parameters without depending on adapter-specific types.
pub trait TlsConfig {
    /// The TLS protocol versions enabled by this configuration.
    fn protocol_versions(&self) -> &[TlsVersion];

    /// The ALPN protocol identifiers advertised by this configuration, in
    /// preference order.  Each entry is a raw byte string, e.g. `b"h2"`.
    fn alpn_protocols(&self) -> &[Vec<u8>];

    /// The SNI server name, if any, used for this configuration.
    fn sni_name(&self) -> Option<&str>;

    /// The cipher suites enabled by this configuration.
    ///
    /// Returns an empty slice when the implementation does not constrain
    /// cipher selection (i.e. the provider default is used).
    fn cipher_suites(&self) -> &[CipherSuite] {
        &[]
    }
}
