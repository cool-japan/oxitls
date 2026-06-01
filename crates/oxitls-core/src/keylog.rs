//! Key-logging policy for TLS session secret export.
//!
//! `KeyLogPolicy` controls whether session secrets are exported to a file
//! (SSLKEYLOGFILE format, compatible with Wireshark) or to a custom callback.

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

/// Trait for receiving TLS session secrets.
///
/// Implementations are responsible for recording the label, client random,
/// and secret triple in the NSS Key Log Format used by Wireshark and other
/// tools.
///
/// Implementors must be `Send + Sync + fmt::Debug`.
pub trait KeyLog: Send + Sync + fmt::Debug {
    /// Record a session secret.
    ///
    /// # Parameters
    /// - `label` — the NSS key log label, e.g. `"CLIENT_RANDOM"`.
    /// - `client_random` — the 32-byte client random from the ClientHello.
    /// - `secret` — the session secret bytes.
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]);
}

/// Policy governing TLS session-secret export.
///
/// This type is `Clone`; cloning a `Custom` variant clones the `Arc`, sharing
/// the same underlying logger instance.
#[derive(Clone)]
pub enum KeyLogPolicy {
    /// Session secrets are not exported (default).
    Disabled,
    /// Session secrets are appended to the given file in NSS Key Log Format.
    File(PathBuf),
    /// Session secrets are forwarded to a custom [`KeyLog`] implementation.
    Custom(Arc<dyn KeyLog>),
}

impl fmt::Debug for KeyLogPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyLogPolicy::Disabled => write!(f, "KeyLogPolicy::Disabled"),
            KeyLogPolicy::File(path) => write!(f, "KeyLogPolicy::File({path:?})"),
            KeyLogPolicy::Custom(_) => write!(f, "KeyLogPolicy::Custom(<KeyLog impl>)"),
        }
    }
}
