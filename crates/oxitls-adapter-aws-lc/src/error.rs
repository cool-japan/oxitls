//! Error conversions between aws-lc-rs / rustls error types and `oxitls_core::TlsError`.
//!
//! All items are gated on `#[cfg(feature = "aws-lc")]`.
//!
//! Because both `aws_lc_rs::error::Unspecified` and `oxitls_core::TlsError` are
//! foreign types, the orphan rule prevents a direct `impl From<Unspecified> for
//! TlsError`. We expose standalone conversion functions instead.
//!
//! Similarly, `rustls::Error` is a foreign type so a `From` impl cannot be
//! placed here; `rustls_error_to_tls_error` provides the same mapping as a
//! free function.

/// Convert `aws_lc_rs::error::Unspecified` into `TlsError::Other`.
///
/// # Example
/// ```no_run
/// # #[cfg(feature = "aws-lc")]
/// # {
/// use oxitls_adapter_aws_lc::error::unspecified_to_tls_error;
/// let err = unspecified_to_tls_error(aws_lc_rs::error::Unspecified);
/// # }
/// ```
#[cfg(feature = "aws-lc")]
pub fn unspecified_to_tls_error(e: aws_lc_rs::error::Unspecified) -> oxitls_core::TlsError {
    oxitls_core::TlsError::Other(format!("aws-lc-rs error: {e:?}"))
}

/// Convert `aws_lc_rs::error::KeyRejected` into `TlsError::InvalidConfig`.
#[cfg(feature = "aws-lc")]
pub fn key_rejected_to_tls_error(e: aws_lc_rs::error::KeyRejected) -> oxitls_core::TlsError {
    oxitls_core::TlsError::InvalidConfig(format!("aws-lc-rs key rejected: {e:?}"))
}

/// Convert a [`rustls::Error`] into an [`oxitls_core::TlsError`].
///
/// This function mirrors the conversion logic in `oxitls_core` and is
/// provided here as a convenience for code in this crate that needs to map
/// rustls errors without importing `oxitls_core` directly.
///
/// # Example
/// ```no_run
/// # #[cfg(feature = "aws-lc")]
/// # {
/// use oxitls_adapter_aws_lc::error::rustls_error_to_tls_error;
/// let tls_err = rustls_error_to_tls_error(rustls::Error::General("oops".into()));
/// # }
/// ```
#[cfg(feature = "aws-lc")]
pub fn rustls_error_to_tls_error(e: rustls::Error) -> oxitls_core::TlsError {
    use oxitls_core::{AlertDescription, TlsError};
    match e {
        rustls::Error::InvalidCertificate(reason) => TlsError::CertInvalid(format!("{reason:?}")),
        rustls::Error::AlertReceived(alert) => {
            TlsError::AlertReceived(AlertDescription::from(u8::from(alert)))
        }
        rustls::Error::PeerIncompatible(reason) => {
            TlsError::ProtocolViolation(format!("{reason:?}"))
        }
        rustls::Error::PeerMisbehaved(reason) => TlsError::ProtocolViolation(format!("{reason:?}")),
        rustls::Error::General(msg) => TlsError::Other(msg),
        other => TlsError::Other(format!("{other}")),
    }
}
