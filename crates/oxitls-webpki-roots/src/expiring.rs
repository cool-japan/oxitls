//! Root cert expiration introspection.
//!
//! # The webpki-roots limitation
//!
//! The `webpki-roots` crate ships *trust anchors*, not full X.509 certificates:
//! each anchor is just the `subject` DN + `subject_public_key_info` + optional
//! `name_constraints`. The original certificate's `notBefore` / `notAfter`
//! fields are **not** reachable from a `rustls_pki_types::TrustAnchor` — they
//! live only in the source PEM comments.
//!
//! As a result, the public [`expiring_roots`] iterates the Mozilla bundle but
//! cannot extract real expiration dates and always returns an empty `Vec`.
//! This function exists so callers can call it without conditionally
//! compiling; the *meaningful* variant is [`expiring_roots_from_ders`], which
//! takes full DER-encoded certificates and parses them with `x509-parser`.
//!
//! Typical use: build a list of full DERs from a different source (custom
//! roots, a CSR pipeline, or the platform native store) and feed them to
//! [`expiring_roots_from_ders`].

use rustls_pki_types::CertificateDer;
use time::{Duration, OffsetDateTime};
use x509_parser::prelude::FromDer;

use crate::TrustAnchorInfo;

/// Iterate the bundled Mozilla CA roots and return those expiring within
/// `within_days` days.
///
/// **Caveat:** the `webpki-roots` crate exposes only the trust-anchor subset
/// (subject DN + SPKI + name constraints) — there is no `notAfter` reachable
/// from a `rustls_pki_types::TrustAnchor`. Consequently this function always
/// returns `Vec::new()`. Use [`expiring_roots_from_ders`] with real DER
/// certificates for meaningful expiration queries.
pub fn expiring_roots(_within_days: u32) -> Vec<TrustAnchorInfo> {
    // No DER bytes accessible from `TrustAnchor` — see module docs.
    Vec::new()
}

/// Parse a slice of DER-encoded certificates and return [`TrustAnchorInfo`]
/// for each cert expiring within `within_days` days from now.
///
/// Certificates that cannot be parsed by `x509-parser` are skipped silently
/// (they never appear in the result). This matches the spec's "handle
/// gracefully" semantics — a malformed cert in the input should not cause the
/// whole call to fail.
///
/// # Example
///
/// ```no_run
/// # use rustls_pki_types::CertificateDer;
/// # let ders: Vec<CertificateDer<'static>> = Vec::new();
/// let expiring = oxitls_webpki_roots::expiring_roots_from_ders(&ders, 30);
/// for info in &expiring {
///     println!("{info}");
/// }
/// ```
pub fn expiring_roots_from_ders(
    ders: &[CertificateDer<'_>],
    within_days: u32,
) -> Vec<TrustAnchorInfo> {
    let now = OffsetDateTime::now_utc();
    let deadline = now.saturating_add(Duration::days(i64::from(within_days)));

    let mut result = Vec::new();
    for der in ders {
        if let Some(info) = info_if_expiring_within(der.as_ref(), deadline) {
            result.push(info);
        }
    }
    result
}

/// Helper: parse one DER and return `Some(info)` if its `notAfter` is at or
/// before `deadline`. Already-expired certs are also included — by definition
/// they have already passed any future deadline.
fn info_if_expiring_within(der: &[u8], deadline: OffsetDateTime) -> Option<TrustAnchorInfo> {
    let (_rest, cert) = x509_parser::certificate::X509Certificate::from_der(der).ok()?;
    let not_after = cert.validity().not_after.to_datetime();

    if not_after <= deadline {
        let info = TrustAnchorInfo::from_cert_der(der)?;
        Some(info.with_not_after(not_after))
    } else {
        None
    }
}

/// Parse the `notAfter` field of a single DER-encoded certificate.
///
/// Returns `None` if the certificate cannot be parsed. Useful for callers
/// that have a DER blob and want only the expiration date.
pub fn parse_not_after(der: &[u8]) -> Option<OffsetDateTime> {
    let (_rest, cert) = x509_parser::certificate::X509Certificate::from_der(der).ok()?;
    Some(cert.validity().not_after.to_datetime())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_helper_returns_empty_for_bundled_roots() {
        // Limitation: TrustAnchor lacks `notAfter` — public helper is empty.
        let v = expiring_roots(365_000);
        assert!(v.is_empty());
    }

    #[test]
    fn from_ders_empty_input_returns_empty() {
        let v = expiring_roots_from_ders(&[], 30);
        assert!(v.is_empty());
    }

    #[test]
    fn from_ders_invalid_der_skipped_not_panicked() {
        let bogus = CertificateDer::from(vec![0u8, 1, 2, 3]);
        let v = expiring_roots_from_ders(&[bogus], 30);
        assert!(v.is_empty());
    }
}
