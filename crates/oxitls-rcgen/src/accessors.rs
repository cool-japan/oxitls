//! Pure-Rust accessors over the DER blob in [`CertifiedKey`].
//!
//! These helpers parse `cert_der` on every call (via `x509-parser`) — they're
//! convenient for one-off queries (`println!`, log lines, server welcome
//! banners) but should not be invoked in hot paths. For repeated access,
//! parse once and cache the result.
//!
//! # Lifetime contract
//!
//! `x509-parser` returns structures that borrow from the input slice. Each
//! helper here parses, copies any needed value into an owned form, and drops
//! the parser before returning — so the API never exposes parser-borrowed
//! references to the caller.

use std::fmt;

use oxitls_core::TlsError;

use crate::cert::CertifiedKey;

impl CertifiedKey {
    /// Return the certificate's subject in RFC 4514 string form
    /// (e.g. `"CN=example.com"`).
    ///
    /// # Errors
    /// Returns [`TlsError::InvalidConfig`] if the cert DER cannot be parsed.
    pub fn subject_name(&self) -> Result<String, TlsError> {
        let (_rest, cert) = x509_parser::parse_x509_certificate(&self.cert_der)
            .map_err(|e| TlsError::InvalidConfig(format!("parse cert DER: {e:?}")))?;
        // X509Name implements Display via to_string_with_registry; the simple
        // Display impl emits the RFC 4514 form ("CN=...,O=...").
        Ok(cert.subject().to_string())
    }

    /// Return the certificate's expiration timestamp (`notAfter`).
    ///
    /// # Errors
    /// Returns [`TlsError::InvalidConfig`] if the cert DER cannot be parsed
    /// or if the embedded timestamp is malformed.
    pub fn not_after(&self) -> Result<time::OffsetDateTime, TlsError> {
        let (_rest, cert) = x509_parser::parse_x509_certificate(&self.cert_der)
            .map_err(|e| TlsError::InvalidConfig(format!("parse cert DER: {e:?}")))?;
        Ok(cert.validity().not_after.to_datetime())
    }

    /// Return the certificate's start-of-validity timestamp (`notBefore`).
    ///
    /// # Errors
    /// Returns [`TlsError::InvalidConfig`] if the cert DER cannot be parsed.
    pub fn not_before(&self) -> Result<time::OffsetDateTime, TlsError> {
        let (_rest, cert) = x509_parser::parse_x509_certificate(&self.cert_der)
            .map_err(|e| TlsError::InvalidConfig(format!("parse cert DER: {e:?}")))?;
        Ok(cert.validity().not_before.to_datetime())
    }

    /// Return the X.509 signature algorithm OID encoded by the issuer
    /// (e.g. `"1.2.840.10045.4.3.2"` for ECDSA-with-SHA256).
    ///
    /// # Errors
    /// Returns [`TlsError::InvalidConfig`] if the cert DER cannot be parsed.
    pub fn signature_algorithm_oid(&self) -> Result<String, TlsError> {
        let (_rest, cert) = x509_parser::parse_x509_certificate(&self.cert_der)
            .map_err(|e| TlsError::InvalidConfig(format!("parse cert DER: {e:?}")))?;
        Ok(cert.signature_algorithm.algorithm.to_id_string())
    }
}

/// Format a SHA-256 fingerprint as colon-separated uppercase hex
/// (`AA:BB:CC:...`), matching `openssl x509 -fingerprint -sha256`.
fn format_fingerprint(fp: &[u8; 32]) -> String {
    let mut out = String::with_capacity(32 * 3);
    for (i, b) in fp.iter().enumerate() {
        if i > 0 {
            out.push(':');
        }
        let hi = (*b >> 4) & 0x0F;
        let lo = *b & 0x0F;
        out.push(hex_digit(hi));
        out.push(hex_digit(lo));
    }
    out
}

const fn hex_digit(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'A' + (n - 10)) as char,
        _ => '?',
    }
}

impl fmt::Display for CertifiedKey {
    /// Multi-line human summary of the certificate. Format:
    ///
    /// ```text
    /// Subject:    CN=example.com
    /// Algorithm:  <OID>
    /// SHA-256:    AA:BB:...
    /// Not after:  2026-05-26T00:00:00+00:00
    /// ```
    ///
    /// Errors during DER parsing are surfaced inline as `<unparseable>`
    /// rather than being propagated — `Display` cannot return an error.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let subject = self
            .subject_name()
            .unwrap_or_else(|_| "<unparseable>".into());
        let algorithm = self
            .signature_algorithm_oid()
            .unwrap_or_else(|_| "<unparseable>".into());
        let fingerprint = format_fingerprint(&self.fingerprint_sha256());
        let not_after = match self.not_after() {
            Ok(dt) => dt
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_else(|_| "<unformattable>".into()),
            Err(_) => "<unparseable>".into(),
        };
        writeln!(f, "Subject:    {subject}")?;
        writeln!(f, "Algorithm:  {algorithm}")?;
        writeln!(f, "SHA-256:    {fingerprint}")?;
        write!(f, "Not after:  {not_after}")
    }
}
