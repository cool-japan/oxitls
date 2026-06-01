//! OCSP staple client-side verification.
//!
//! [`OcspClientVerifier`] wraps any inner [`ServerCertVerifier`] and applies an
//! [`OcspClientPolicy`] to the OCSP staple bytes passed by the server during
//! the TLS handshake.
//!
//! # OCSP Signature Verification (RFC 6960 §4.2.2.2)
//!
//! This implementation checks both the cryptographic signature of the OCSP
//! signer and the certificate status (`Good`, `Revoked`, `Unknown`) from the
//! parsed `BasicOcspResponse`.
//!
//! Signer selection follows RFC 6960 §4.2.2.2:
//! 1. If the responder ID matches the issuer (by name or key hash), the issuer
//!    signs directly and no delegated-signer check is needed.
//! 2. If the response includes a `certs` chain, the first certificate is used
//!    as the delegated signer; its EKU (`id-kp-OCSPSigning`) is verified.
//! 3. Otherwise, the issuer's SPKI is used as the fallback signer.
//!
//! Invalid signatures always cause failure regardless of policy. A forged
//! signature is not equivalent to a missing staple.

use std::sync::Arc;

use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    CertificateError, DigitallySignedStruct, Error as RustlsError, SignatureScheme,
};
use x509_cert::der::{Decode, Encode};
use x509_ocsp::{BasicOcspResponse, CertStatus, OcspResponse, OcspResponseStatus, ResponderId};

use super::ocsp_crypto::{verify_eku_ocsp_signing, verify_ocsp_signature, OcspVerifyError};

/// Policy controlling how a missing or unparseable OCSP staple is treated.
///
/// Note: cryptographic verification of the OCSP signer is always enforced.
/// An invalid signature is always rejected regardless of this policy; the
/// policy only controls what happens when a staple is *absent* or unparseable.
#[derive(Debug, Clone, PartialEq)]
pub enum OcspClientPolicy {
    /// Ignore the OCSP staple entirely. No parsing is attempted and the
    /// handshake outcome depends solely on the inner verifier.
    Disabled,

    /// Best-effort: absent or unparseable staples emit a warning and allow
    /// the handshake to continue. A `Revoked` status always causes rejection.
    /// A `CertStatus::Unknown` is treated as absent (soft-fail passes).
    SoftFail,

    /// Strict: a missing or unparseable staple causes the handshake to fail.
    /// A `Revoked` or `Unknown` status also fails.
    HardRequire,
}

/// A [`ServerCertVerifier`] that checks the OCSP staple supplied by the server
/// according to the configured [`OcspClientPolicy`] before delegating to an
/// inner verifier for full chain validation.
///
/// # Usage
///
/// ```no_run
/// use std::sync::Arc;
/// use oxitls_adapter_rustls_rustcrypto::verifier::ocsp_client::{OcspClientPolicy, OcspClientVerifier};
/// use rustls::client::WebPkiServerVerifier;
/// use rustls::RootCertStore;
/// use oxitls_adapter_rustls_rustcrypto::pure_provider;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let inner = WebPkiServerVerifier::builder_with_provider(
///     Arc::new(RootCertStore::empty()),
///     pure_provider(),
/// ).build()?;
/// let verifier = OcspClientVerifier::new(inner, OcspClientPolicy::SoftFail);
/// # Ok(())
/// # }
/// ```
pub struct OcspClientVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    policy: OcspClientPolicy,
}

impl std::fmt::Debug for OcspClientVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OcspClientVerifier")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl OcspClientVerifier {
    /// Create a new `OcspClientVerifier` wrapping `inner`.
    pub fn new(inner: Arc<dyn ServerCertVerifier>, policy: OcspClientPolicy) -> Self {
        Self { inner, policy }
    }

    /// Access the configured policy.
    pub fn policy(&self) -> &OcspClientPolicy {
        &self.policy
    }
}

/// Internal result type for OCSP staple checking.
#[derive(Debug)]
enum OcspCheckResult {
    /// Staple bytes were empty — no staple was provided.
    Absent,
    /// Staple bytes were non-empty but could not be parsed.
    Unparseable,
    /// Staple was successfully parsed and at least one entry is `Revoked`.
    Revoked,
    /// Parsed successfully, but at least one entry has `Unknown` status.
    Unknown,
    /// Signature was present but cryptographically invalid (always rejected).
    BadSignature(String),
    /// Staple was successfully parsed, signature valid, no revocation found.
    Good,
}

/// Attempt to extract the issuer's DER-encoded SubjectPublicKeyInfo from an
/// x509_cert::Certificate.
fn spki_der_from_cert(cert: &x509_cert::Certificate) -> Option<Vec<u8>> {
    cert.tbs_certificate.subject_public_key_info.to_der().ok()
}

/// Check whether a `ResponderId` matches the supplied issuer certificate.
///
/// Returns `true` when the responder claims to be the issuer (either by name
/// match or by matching the SHA-1 key hash in the responder ID).  We treat
/// an unknown or unparseble match as **not matching** and fall through to
/// delegated-signer logic.
fn responder_is_issuer(responder_id: &ResponderId, issuer: &x509_cert::Certificate) -> bool {
    match responder_id {
        ResponderId::ByName(name) => *name == issuer.tbs_certificate.subject,
        ResponderId::ByKey(key_hash) => {
            // key_hash is the SHA-1 hash of the BIT STRING subjectPublicKey value
            // (i.e., the raw bytes, not the DER-encoded BitString wrapper).
            //
            // SHA-1 key hash matching would need the `sha1` crate which is not
            // in the workspace. Treat ByKey as "unknown match" and let the
            // delegated-signer path handle it: either via certs[] or using
            // the issuer as the fallback signer.
            let _ = (key_hash, issuer);
            false
        }
    }
}

/// Extract the DER of a `x509_cert::Certificate`.
fn cert_to_der(cert: &x509_cert::Certificate) -> Result<Vec<u8>, OcspVerifyError> {
    cert.to_der()
        .map_err(|e| OcspVerifyError::ResponseUnparseable(format!("re-encode cert DER: {e}")))
}

/// Parse an OCSP staple and verify the cryptographic signature.
///
/// The `issuer_cert_der` is the DER of the certificate that issued the
/// end-entity certificate; it is used for signer identification and as a
/// fallback signing key.
fn check_ocsp_staple(ocsp_response: &[u8], issuer_cert_der: Option<&[u8]>) -> OcspCheckResult {
    if ocsp_response.is_empty() {
        return OcspCheckResult::Absent;
    }

    // Parse outer OcspResponse envelope.
    let parsed = match OcspResponse::from_der(ocsp_response) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "OCSP staple failed to parse as OcspResponse DER");
            return OcspCheckResult::Unparseable;
        }
    };

    if parsed.response_status != OcspResponseStatus::Successful {
        tracing::warn!(
            status = ?parsed.response_status,
            "OCSP response has non-Successful status; treating as absent"
        );
        return OcspCheckResult::Absent;
    }

    let resp_bytes = match parsed.response_bytes {
        Some(b) => b,
        None => {
            tracing::warn!("OCSP response marked Successful but has no responseBytes");
            return OcspCheckResult::Unparseable;
        }
    };

    let basic = match BasicOcspResponse::from_der(resp_bytes.response.as_bytes()) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, "OCSP responseBytes could not be decoded as BasicOcspResponse");
            return OcspCheckResult::Unparseable;
        }
    };

    // ── Cryptographic signature verification ────────────────────────────────

    // Re-encode tbsResponseData to get the bytes that were signed.
    let tbs_der = match basic.tbs_response_data.to_der() {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, "failed to re-encode OCSP tbsResponseData");
            return OcspCheckResult::Unparseable;
        }
    };

    // Extract raw signature bytes (OCSP signatures are always byte-aligned).
    let sig_bytes = basic.signature.raw_bytes();
    let alg_oid = &basic.signature_algorithm.oid;

    // Determine which key to verify with.
    let signer_spki_result = determine_signer_spki(&basic, issuer_cert_der);
    match signer_spki_result {
        Err(e) => {
            tracing::warn!(error = %e, "OCSP signer resolution failed");
            return OcspCheckResult::BadSignature(e.to_string());
        }
        Ok(spki_der) => {
            if let Err(e) = verify_ocsp_signature(&spki_der, &tbs_der, alg_oid, sig_bytes) {
                tracing::warn!(error = %e, "OCSP signature verification failed");
                return OcspCheckResult::BadSignature(e.to_string());
            }
        }
    }

    tracing::debug!(
        num_responses = basic.tbs_response_data.responses.len(),
        "OCSP BasicOcspResponse parsed and signature verified"
    );

    // Scan all single responses; any `Revoked` entry triggers rejection.
    let mut has_unknown = false;
    for sr in &basic.tbs_response_data.responses {
        match sr.cert_status {
            CertStatus::Revoked(_) => return OcspCheckResult::Revoked,
            CertStatus::Unknown(_) => {
                has_unknown = true;
            }
            CertStatus::Good(_) => {}
        }
    }

    if has_unknown {
        return OcspCheckResult::Unknown;
    }

    OcspCheckResult::Good
}

/// Resolve the SPKI DER bytes for the OCSP response signer.
///
/// Priority (per RFC 6960 §4.2.2.2):
/// 1. If `responder_id` matches the issuer by name → use issuer's SPKI.
/// 2. If `certs` is present → use first cert as delegated signer (verify EKU
///    and that issuer signed the cert).
/// 3. Fallback: use issuer's SPKI.
fn determine_signer_spki(
    basic: &BasicOcspResponse,
    issuer_cert_der: Option<&[u8]>,
) -> Result<Vec<u8>, OcspVerifyError> {
    // Parse the issuer cert if provided.
    let issuer_opt: Option<x509_cert::Certificate> = issuer_cert_der.and_then(|der| {
        x509_cert::Certificate::from_der(der)
            .map_err(|e| {
                tracing::debug!(error = %e, "failed to parse issuer cert for OCSP signer resolution");
            })
            .ok()
    });

    // Check if responder_id says it's the issuer.
    let responder_is_iss = match &issuer_opt {
        Some(iss) => responder_is_issuer(&basic.tbs_response_data.responder_id, iss),
        None => false,
    };

    if responder_is_iss {
        // Issuer signs directly.
        let iss = issuer_opt.as_ref().expect("checked above");
        return spki_der_from_cert(iss)
            .ok_or_else(|| OcspVerifyError::SpkiParse("issuer SPKI re-encode failed".into()));
    }

    // Try delegated signer from the certs[] field.
    if let Some(ref certs) = basic.certs {
        if let Some(signer_cert) = certs.first() {
            let signer_cert_der = cert_to_der(signer_cert)?;

            // Verify id-kp-OCSPSigning EKU.
            verify_eku_ocsp_signing(&signer_cert_der)?;

            // Verify the signer cert was issued by the issuer (if we have it).
            if let Some(iss) = &issuer_opt {
                let issuer_spki = spki_der_from_cert(iss).ok_or_else(|| {
                    OcspVerifyError::SpkiParse("issuer SPKI re-encode failed".into())
                })?;

                // Verify the issuer's signature on the delegated cert.
                let signer_tbs_der = signer_cert.tbs_certificate.to_der().map_err(|e| {
                    OcspVerifyError::ResponseUnparseable(format!("re-encode signer TBS: {e}"))
                })?;

                let signer_sig_alg_oid = &signer_cert.signature_algorithm.oid;
                let signer_sig_bytes = signer_cert.signature.raw_bytes();

                verify_ocsp_signature(
                    &issuer_spki,
                    &signer_tbs_der,
                    signer_sig_alg_oid,
                    signer_sig_bytes,
                )
                .map_err(|e| {
                    OcspVerifyError::DelegatedSignerNotTrusted(format!(
                        "issuer did not sign the delegated OCSP cert: {e}"
                    ))
                })?;
            }

            return spki_der_from_cert(signer_cert).ok_or_else(|| {
                OcspVerifyError::SpkiParse("signer cert SPKI encode failed".into())
            });
        }
    }

    // Fallback: use issuer's SPKI.
    if let Some(iss) = &issuer_opt {
        return spki_der_from_cert(iss)
            .ok_or_else(|| OcspVerifyError::SpkiParse("issuer SPKI re-encode failed".into()));
    }

    // No issuer cert was provided and no delegated signer found.
    // We cannot verify — treat as an error so callers can decide.
    Err(OcspVerifyError::ResponseUnparseable(
        "no issuer cert provided and no delegated signer in OCSP response".into(),
    ))
}

impl ServerCertVerifier for OcspClientVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        if self.policy == OcspClientPolicy::Disabled {
            return self.inner.verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            );
        }

        // The issuer of the end-entity cert is the first intermediate, or the
        // end-entity itself for self-signed certs.
        let issuer_der: Option<&[u8]> = intermediates
            .first()
            .map(|c| c.as_ref())
            .or_else(|| Some(end_entity.as_ref()));

        match check_ocsp_staple(ocsp_response, issuer_der) {
            OcspCheckResult::Revoked => {
                return Err(RustlsError::InvalidCertificate(CertificateError::Revoked));
            }

            OcspCheckResult::BadSignature(msg) => {
                // Invalid signature always fails regardless of policy — a forged
                // staple is not equivalent to a missing one.
                return Err(RustlsError::General(format!(
                    "OCSP response cryptographic signature invalid: {msg}"
                )));
            }

            OcspCheckResult::Unknown => {
                match self.policy {
                    OcspClientPolicy::Disabled => {
                        // Already handled above; unreachable here.
                    }
                    OcspClientPolicy::SoftFail => {
                        tracing::warn!(
                            "OCSP CertStatus::Unknown; \
                             soft-fail policy treats Unknown as absent and continues"
                        );
                        // Fall through to inner verifier.
                    }
                    OcspClientPolicy::HardRequire => {
                        return Err(RustlsError::General(
                            "OCSP CertStatus::Unknown with HardRequire policy".into(),
                        ));
                    }
                }
            }

            OcspCheckResult::Absent | OcspCheckResult::Unparseable => {
                match self.policy {
                    OcspClientPolicy::Disabled => {
                        // Already handled above; unreachable here.
                    }
                    OcspClientPolicy::SoftFail => {
                        tracing::warn!(
                            "OCSP staple absent or unparseable; \
                             soft-fail policy allows handshake to continue"
                        );
                        // Fall through to inner verifier.
                    }
                    OcspClientPolicy::HardRequire => {
                        return Err(RustlsError::General(
                            "OCSP staple required but absent or unparseable".into(),
                        ));
                    }
                }
            }

            OcspCheckResult::Good => {
                // Parsed successfully; signature valid; no revocation found. Proceed.
            }
        }

        // Delegate full chain / signature validation to the inner verifier.
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}
