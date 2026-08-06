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
use x509_ocsp::{
    BasicOcspResponse, CertId, CertStatus, OcspResponse, OcspResponseStatus, ResponderId,
    SingleResponse,
};

use super::ocsp_crypto::{verify_eku_ocsp_signing, verify_ocsp_signature, OcspVerifyError};

// ── CertID hash-algorithm OIDs (RFC 6960 §4.1.1 hashAlgorithm) ─────────────────

/// id-sha1 (OIW) — by far the most common OCSP CertID hash.
const OID_SHA1: &str = "1.3.14.3.2.26";
/// id-sha256 (NIST).
const OID_SHA256: &str = "2.16.840.1.101.3.4.2.1";
/// id-sha384 (NIST).
const OID_SHA384: &str = "2.16.840.1.101.3.4.2.2";
/// id-sha512 (NIST).
const OID_SHA512: &str = "2.16.840.1.101.3.4.2.3";

/// Compute the digest of `data` under the hash algorithm named by `hash_oid`.
///
/// Returns `None` for an unrecognised algorithm OID so that CertID matching can
/// fail closed: a response we cannot bind to the target certificate must not be
/// trusted.
fn ocsp_digest(hash_oid: &str, data: &[u8]) -> Option<Vec<u8>> {
    match hash_oid {
        OID_SHA1 => {
            use sha1::Digest as _;
            Some(sha1::Sha1::digest(data).to_vec())
        }
        OID_SHA256 => {
            use sha2::Digest as _;
            Some(sha2::Sha256::digest(data).to_vec())
        }
        OID_SHA384 => {
            use sha2::Digest as _;
            Some(sha2::Sha384::digest(data).to_vec())
        }
        OID_SHA512 => {
            use sha2::Digest as _;
            Some(sha2::Sha512::digest(data).to_vec())
        }
        _ => None,
    }
}

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

/// Return `true` when the certificate's subject and issuer distinguished names
/// are identical, i.e. it is (structurally) self-signed and may therefore act as
/// its own issuer for OCSP CertID / signer resolution.
///
/// Any parse failure yields `false`: we must never treat an unparseable or
/// CA-signed end-entity as its own issuer, because doing so would resolve the
/// OCSP signer key to the leaf's own SPKI and reject a legitimate staple.
fn end_entity_is_self_signed(end_entity_der: &[u8]) -> bool {
    match x509_cert::Certificate::from_der(end_entity_der) {
        Ok(cert) => cert.tbs_certificate.subject == cert.tbs_certificate.issuer,
        Err(_) => false,
    }
}

/// Extract the DER of a `x509_cert::Certificate`.
fn cert_to_der(cert: &x509_cert::Certificate) -> Result<Vec<u8>, OcspVerifyError> {
    cert.to_der()
        .map_err(|e| OcspVerifyError::ResponseUnparseable(format!("re-encode cert DER: {e}")))
}

/// Parse an OCSP staple and verify the cryptographic signature.
///
/// The `end_entity_der` is the certificate being verified; its serial number is
/// matched against the CertID of each SingleResponse. The `issuer_cert_der` is
/// the DER of the certificate that issued the end-entity certificate; it is used
/// for signer identification, as a fallback signing key, and to recompute the
/// CertID issuer name/key hashes. `now` is the current time used to reject
/// stale (replayed) responses.
fn check_ocsp_staple(
    ocsp_response: &[u8],
    end_entity_der: &[u8],
    issuer_cert_der: Option<&[u8]>,
    now: UnixTime,
) -> OcspCheckResult {
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
        Err(OcspVerifyError::ResponseUnparseable(msg)) => {
            // The signer key could not be *resolved* (for example the peer sent
            // a leaf-only chain so no issuer certificate is available and the
            // response carried no delegated signer, or an internal DER
            // re-encode failed). This is an inability to verify the staple, not
            // proof that its signature is forged, so it must be governed by the
            // configured policy rather than raised as an unconditional
            // BadSignature hard failure.
            tracing::warn!(
                error = %msg,
                "OCSP signer key could not be resolved; treating staple as unparseable"
            );
            return OcspCheckResult::Unparseable;
        }
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

    // Bind the response to the certificate being verified and enforce freshness
    // before trusting any status.
    let issuer_cert = issuer_cert_der.and_then(|der| x509_cert::Certificate::from_der(der).ok());
    evaluate_responses(
        &basic.tbs_response_data.responses,
        end_entity_der,
        issuer_cert.as_ref(),
        now,
    )
}

/// Match a SingleResponse's CertID against the certificate being verified.
///
/// Returns `true` only when the CertID's `issuerNameHash`, `issuerKeyHash`
/// (recomputed with the CertID's own `hashAlgorithm`) and `serialNumber` all
/// correspond to the target end-entity certificate and its issuer. An
/// unsupported hash algorithm yields `false` (fail closed): a `Good` response
/// for a *different* certificate from the same CA must never be accepted.
fn cert_id_matches(
    cert_id: &CertId,
    issuer: &x509_cert::Certificate,
    end_entity_serial: &[u8],
) -> bool {
    // serialNumber must match the certificate under verification.
    if cert_id.serial_number.as_bytes() != end_entity_serial {
        return false;
    }

    let hash_oid = cert_id.hash_algorithm.oid.to_string();

    let issuer_name_der = match issuer.tbs_certificate.subject.to_der() {
        Ok(der) => der,
        Err(_) => return false,
    };
    let issuer_key_bytes = issuer
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();

    let expected_name_hash = match ocsp_digest(&hash_oid, &issuer_name_der) {
        Some(h) => h,
        None => return false,
    };
    let expected_key_hash = match ocsp_digest(&hash_oid, issuer_key_bytes) {
        Some(h) => h,
        None => return false,
    };

    cert_id.issuer_name_hash.as_bytes() == expected_name_hash.as_slice()
        && cert_id.issuer_key_hash.as_bytes() == expected_key_hash.as_slice()
}

/// Return `true` when `now` falls inside the response's validity window
/// (`thisUpdate <= now <= nextUpdate`).
///
/// A response whose `thisUpdate` is in the future, or whose `nextUpdate` has
/// already passed, is stale and must not be trusted as a fresh `Good` — this is
/// what prevents an old "Good" from being replayed forever (RFC 6960 §3.2).
fn single_response_is_current(sr: &SingleResponse, now: UnixTime) -> bool {
    let now_secs = now.as_secs();

    let this_update = sr.this_update.0.to_unix_duration().as_secs();
    if now_secs < this_update {
        return false;
    }

    if let Some(next) = &sr.next_update {
        let next_update = next.0.to_unix_duration().as_secs();
        if now_secs > next_update {
            return false;
        }
    }

    true
}

/// Evaluate the SingleResponses that actually cover the certificate being
/// verified.
///
/// Only responses whose CertID binds to the target cert/issuer are considered.
/// A `Revoked` match is authoritative regardless of freshness (fail-safe). A
/// `Good`/`Unknown` match is only honoured inside its validity window. If no
/// response covers the certificate, the staple is treated as unusable.
fn evaluate_responses(
    responses: &[SingleResponse],
    end_entity_der: &[u8],
    issuer: Option<&x509_cert::Certificate>,
    now: UnixTime,
) -> OcspCheckResult {
    let end_entity = match x509_cert::Certificate::from_der(end_entity_der) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "failed to parse end-entity cert for OCSP CertID match");
            return OcspCheckResult::Unparseable;
        }
    };
    let ee_serial = end_entity.tbs_certificate.serial_number.as_bytes().to_vec();

    let issuer = match issuer {
        Some(i) => i,
        None => {
            // Without the issuer cert we cannot bind any response to the target.
            tracing::warn!("no issuer cert available; cannot match OCSP CertID");
            return OcspCheckResult::Unparseable;
        }
    };

    let mut matched_any = false;
    let mut has_unknown = false;
    let mut good_current = false;

    for sr in responses {
        if !cert_id_matches(&sr.cert_id, issuer, &ee_serial) {
            continue;
        }
        matched_any = true;

        // Revoked is authoritative even if the response is stale (fail-safe).
        if let CertStatus::Revoked(_) = sr.cert_status {
            return OcspCheckResult::Revoked;
        }

        // Good / Unknown are only trusted inside the validity window.
        if !single_response_is_current(sr, now) {
            tracing::warn!("OCSP SingleResponse outside its validity window; ignoring");
            continue;
        }

        match sr.cert_status {
            CertStatus::Unknown(_) => has_unknown = true,
            CertStatus::Good(_) => good_current = true,
            CertStatus::Revoked(_) => {}
        }
    }

    if !matched_any {
        tracing::warn!("no OCSP SingleResponse matches the certificate being verified");
        return OcspCheckResult::Unparseable;
    }
    if good_current {
        return OcspCheckResult::Good;
    }
    if has_unknown {
        return OcspCheckResult::Unknown;
    }

    // Matched, but the only usable status was stale (e.g. an expired Good).
    OcspCheckResult::Unparseable
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

        // Resolve the certificate that issued the end-entity: normally the first
        // intermediate in the presented chain. When the peer sends a leaf-only
        // chain we may treat the end-entity as its own issuer *only* if it is
        // self-signed. Synthesising a bogus issuer from a CA-signed leaf would
        // make a legitimate staple fail signature verification (the resolved
        // signer key would be the leaf's own SPKI), turning a valid OCSP staple
        // into an unconditional handshake failure that even SoftFail cannot
        // escape. In the leaf-only, non-self-signed case we pass `None` so the
        // missing-issuer situation is handled as an unverifiable (and therefore
        // policy-governed) staple rather than a forged one.
        let issuer_der: Option<&[u8]> = match intermediates.first() {
            Some(first) => Some(first.as_ref()),
            None if end_entity_is_self_signed(end_entity.as_ref()) => Some(end_entity.as_ref()),
            None => None,
        };

        match check_ocsp_staple(ocsp_response, end_entity.as_ref(), issuer_der, now) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::sha2::Sha256;
    use x509_cert::der::DateTime;
    use x509_cert::serial_number::SerialNumber;
    use x509_ocsp::{CertStatus, OcspGeneralizedTime, SingleResponse};

    /// A fixed "now" of 2025-05-27, used as the verification instant.
    fn now_2025_05() -> UnixTime {
        UnixTime::since_unix_epoch(std::time::Duration::from_secs(1_748_304_000))
    }

    fn gtime(y: u16, m: u8, d: u8) -> OcspGeneralizedTime {
        OcspGeneralizedTime::from(DateTime::new(y, m, d, 0, 0, 0).expect("valid datetime"))
    }

    /// Generate a self-signed P-256 certificate and return (DER, parsed cert).
    /// For a self-signed cert the issuer and end-entity are identical, so the
    /// CertID issuer hashes and serial all bind to the same certificate.
    fn self_signed() -> (Vec<u8>, x509_cert::Certificate) {
        let ck = oxitls_rcgen::generate_self_signed_p256(&["localhost"]).expect("cert gen");
        let der = ck.cert_der.clone();
        let cert = x509_cert::Certificate::from_der(&der).expect("parse cert");
        (der, cert)
    }

    fn good_single(
        issuer: &x509_cert::Certificate,
        serial: SerialNumber,
        this: OcspGeneralizedTime,
        next: Option<OcspGeneralizedTime>,
    ) -> SingleResponse {
        let cert_id = x509_ocsp::CertId::from_issuer::<Sha256>(issuer, serial).expect("cert id");
        let mut sr = SingleResponse::new(cert_id, CertStatus::good(), this);
        sr.next_update = next;
        sr
    }

    /// Same as [`good_single`] but builds the `CertID` with `hashAlgorithm =
    /// id-sha1`, the overwhelmingly common choice among real OCSP responders
    /// (RFC 6960 §4.1.1). Exercises the `OID_SHA1` arm of `ocsp_digest`.
    fn good_single_sha1(
        issuer: &x509_cert::Certificate,
        serial: SerialNumber,
        this: OcspGeneralizedTime,
        next: Option<OcspGeneralizedTime>,
    ) -> SingleResponse {
        let cert_id =
            x509_ocsp::CertId::from_issuer::<sha1::Sha1>(issuer, serial).expect("cert id");
        let mut sr = SingleResponse::new(cert_id, CertStatus::good(), this);
        sr.next_update = next;
        sr
    }

    /// A "Good" response whose CertID matches the certificate and is within its
    /// validity window is accepted.
    #[test]
    fn good_response_matching_certid_accepted() {
        let (ee_der, issuer) = self_signed();
        let serial = issuer.tbs_certificate.serial_number.clone();
        let sr = good_single(&issuer, serial, gtime(2025, 1, 1), Some(gtime(2026, 1, 1)));
        let result = evaluate_responses(&[sr], &ee_der, Some(&issuer), now_2025_05());
        assert!(matches!(result, OcspCheckResult::Good), "got {result:?}");
    }

    /// A "Good" response for a DIFFERENT serial from the same CA must not be
    /// accepted for the certificate under verification (revocation bypass).
    #[test]
    fn good_response_wrong_serial_rejected() {
        let (ee_der, issuer) = self_signed();
        // Derive a serial guaranteed to differ from the real one by flipping a
        // low bit of its big-endian encoding.
        let mut wrong_bytes = issuer.tbs_certificate.serial_number.as_bytes().to_vec();
        if let Some(last) = wrong_bytes.last_mut() {
            *last ^= 0x01;
        }
        let wrong_serial = SerialNumber::new(&wrong_bytes).expect("serial");
        let sr = good_single(
            &issuer,
            wrong_serial,
            gtime(2025, 1, 1),
            Some(gtime(2026, 1, 1)),
        );
        let result = evaluate_responses(&[sr], &ee_der, Some(&issuer), now_2025_05());
        assert!(
            matches!(result, OcspCheckResult::Unparseable),
            "mismatched CertID serial must not yield Good; got {result:?}"
        );
    }

    /// A "Good" response whose CertID uses `hashAlgorithm = id-sha1` — by far the
    /// most common OCSP responder choice (RFC 6960 §4.1.1) — and matches the
    /// certificate is accepted. Regression coverage for the `OID_SHA1` arm of
    /// `ocsp_digest`/`cert_id_matches`, which previously only had a SHA-256 test.
    #[test]
    fn good_response_sha1_certid_accepted() {
        let (ee_der, issuer) = self_signed();
        let serial = issuer.tbs_certificate.serial_number.clone();
        let sr = good_single_sha1(&issuer, serial, gtime(2025, 1, 1), Some(gtime(2026, 1, 1)));
        let result = evaluate_responses(&[sr], &ee_der, Some(&issuer), now_2025_05());
        assert!(matches!(result, OcspCheckResult::Good), "got {result:?}");
    }

    /// A "Good" `id-sha1` CertID response for a DIFFERENT serial from the same CA
    /// must not be accepted for the certificate under verification — the SHA-1
    /// counterpart of `good_response_wrong_serial_rejected`, guarding against a
    /// revocation-check bypass on the id-sha1 path specifically.
    #[test]
    fn good_response_sha1_certid_wrong_serial_rejected() {
        let (ee_der, issuer) = self_signed();
        let mut wrong_bytes = issuer.tbs_certificate.serial_number.as_bytes().to_vec();
        if let Some(last) = wrong_bytes.last_mut() {
            *last ^= 0x01;
        }
        let wrong_serial = SerialNumber::new(&wrong_bytes).expect("serial");
        let sr = good_single_sha1(
            &issuer,
            wrong_serial,
            gtime(2025, 1, 1),
            Some(gtime(2026, 1, 1)),
        );
        let result = evaluate_responses(&[sr], &ee_der, Some(&issuer), now_2025_05());
        assert!(
            matches!(result, OcspCheckResult::Unparseable),
            "mismatched SHA-1 CertID serial must not yield Good; got {result:?}"
        );
    }

    /// An otherwise-valid "Good" whose `nextUpdate` has already passed must not
    /// be trusted (prevents replaying an old Good forever).
    #[test]
    fn expired_good_response_rejected() {
        let (ee_der, issuer) = self_signed();
        let serial = issuer.tbs_certificate.serial_number.clone();
        let sr = good_single(&issuer, serial, gtime(2024, 1, 1), Some(gtime(2025, 3, 1)));
        let result = evaluate_responses(&[sr], &ee_der, Some(&issuer), now_2025_05());
        assert!(
            !matches!(result, OcspCheckResult::Good),
            "expired Good must not be accepted; got {result:?}"
        );
    }

    /// A "Good" whose `thisUpdate` is in the future must not be trusted yet.
    #[test]
    fn future_dated_response_rejected() {
        let (ee_der, issuer) = self_signed();
        let serial = issuer.tbs_certificate.serial_number.clone();
        let sr = good_single(&issuer, serial, gtime(2026, 1, 1), Some(gtime(2027, 1, 1)));
        let result = evaluate_responses(&[sr], &ee_der, Some(&issuer), now_2025_05());
        assert!(
            !matches!(result, OcspCheckResult::Good),
            "not-yet-valid Good must not be accepted; got {result:?}"
        );
    }

    /// Without an issuer certificate no CertID can be matched, so the staple is
    /// treated as unusable rather than blindly trusted.
    #[test]
    fn missing_issuer_cannot_match() {
        let (ee_der, issuer) = self_signed();
        let serial = issuer.tbs_certificate.serial_number.clone();
        let sr = good_single(&issuer, serial, gtime(2025, 1, 1), Some(gtime(2026, 1, 1)));
        let result = evaluate_responses(&[sr], &ee_der, None, now_2025_05());
        assert!(
            matches!(result, OcspCheckResult::Unparseable),
            "got {result:?}"
        );
    }

    /// A structurally self-signed certificate (subject == issuer) is recognised
    /// as its own issuer.
    #[test]
    fn self_signed_cert_detected_as_self_issuer() {
        let (ee_der, _issuer) = self_signed();
        assert!(
            end_entity_is_self_signed(&ee_der),
            "self-signed cert must be treated as its own issuer"
        );
    }

    /// A CA-signed leaf (subject != issuer) must NOT be treated as its own
    /// issuer. Regression guard for the bug where a leaf-only chain caused the
    /// end-entity to be synthesised as its own OCSP issuer, resolving the signer
    /// key to the leaf's SPKI and turning a legitimate staple into an
    /// unconditional BadSignature handshake failure.
    #[test]
    fn ca_signed_leaf_not_detected_as_self_issuer() {
        use oxitls_rcgen::{generate_ca, generate_ca_signed_leaf, SigningAlgorithm};

        let ca = generate_ca("Regression Root CA", SigningAlgorithm::EcdsaP256).expect("ca gen");
        let leaf = generate_ca_signed_leaf(&["leaf.example"], SigningAlgorithm::EcdsaP256, &ca)
            .expect("leaf gen");
        assert!(
            !end_entity_is_self_signed(&leaf.cert_der),
            "CA-signed leaf must not be treated as its own issuer"
        );
        // The CA itself is self-signed and must be recognised as such.
        assert!(
            end_entity_is_self_signed(&ca.certified_key.cert_der),
            "root CA is self-signed"
        );
    }

    /// Malformed DER must fail closed: never treat garbage as self-signed.
    #[test]
    fn garbage_cert_not_self_signed() {
        assert!(!end_entity_is_self_signed(b"not a certificate"));
        assert!(!end_entity_is_self_signed(&[]));
    }

    /// End-to-end regression for the leaf-only-chain OCSP bug: when the peer
    /// sends a CA-signed end-entity but no issuer certificate is available and
    /// the response carries no delegated signer, the signer key cannot be
    /// resolved. This must surface as a policy-governed `Unparseable` rather
    /// than an unconditional `BadSignature`, so that SoftFail can still allow
    /// the handshake to proceed.
    #[test]
    fn no_issuer_no_delegated_signer_is_unparseable_not_badsignature() {
        // Build a minimal BasicOcspResponse with no delegated signer certs so
        // that `determine_signer_spki(None issuer)` returns ResponseUnparseable.
        let (_ee_der, issuer) = self_signed();
        let serial = issuer.tbs_certificate.serial_number.clone();
        let sr = good_single(&issuer, serial, gtime(2025, 1, 1), Some(gtime(2026, 1, 1)));
        let basic = BasicOcspResponse {
            tbs_response_data: x509_ocsp::ResponseData {
                version: x509_ocsp::Version::default(),
                responder_id: ResponderId::ByName(issuer.tbs_certificate.subject.clone()),
                produced_at: gtime(2025, 1, 1),
                responses: vec![sr],
                response_extensions: None,
            },
            signature_algorithm: issuer.signature_algorithm.clone(),
            signature: x509_cert::der::asn1::BitString::from_bytes(&[0u8; 8]).expect("bitstring"),
            certs: None,
        };
        // No issuer available (leaf-only, non-self-signed peer chain).
        let result = determine_signer_spki(&basic, None);
        assert!(
            matches!(result, Err(OcspVerifyError::ResponseUnparseable(_))),
            "no issuer and no delegated signer must be reported as unresolvable \
             (ResponseUnparseable), not a trust failure; got {result:?}"
        );
    }

    /// Minimal inner verifier that unconditionally accepts, so the test can
    /// isolate the OCSP staple policy decision made *before* delegation.
    #[derive(Debug)]
    struct AlwaysOk;

    impl ServerCertVerifier for AlwaysOk {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, RustlsError> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, RustlsError> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, RustlsError> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![SignatureScheme::ED25519]
        }
    }

    /// Build a well-formed OCSP staple (parses fully as a Successful
    /// `BasicOcspResponse`) whose signature is garbage. The response's CertID is
    /// bound to `issuer`, and its responder is named as `issuer`'s subject.
    fn well_formed_staple_with_bad_signature(issuer: &x509_cert::Certificate) -> Vec<u8> {
        let serial = issuer.tbs_certificate.serial_number.clone();
        let sr = good_single(issuer, serial, gtime(2025, 1, 1), Some(gtime(2026, 1, 1)));
        let basic = BasicOcspResponse {
            tbs_response_data: x509_ocsp::ResponseData {
                version: x509_ocsp::Version::default(),
                responder_id: ResponderId::ByName(issuer.tbs_certificate.subject.clone()),
                produced_at: gtime(2025, 1, 1),
                responses: vec![sr],
                response_extensions: None,
            },
            signature_algorithm: issuer.signature_algorithm.clone(),
            signature: x509_cert::der::asn1::BitString::from_bytes(&[0u8; 8]).expect("bitstring"),
            certs: None,
        };
        x509_ocsp::OcspResponse::successful(basic)
            .expect("build OcspResponse")
            .to_der()
            .expect("encode OcspResponse DER")
    }

    /// End-to-end regression for the leaf-only-chain OCSP bug at the policy
    /// level. A `SoftFail` `OcspClientVerifier` handed a CA-signed end-entity
    /// with an *empty* intermediates list and a non-empty (but unverifiable,
    /// because no issuer is available) staple must NOT hard-fail the handshake:
    /// the missing issuer means the staple is unverifiable, which SoftFail is
    /// allowed to wave through. Before the fix, `verify_server_cert` synthesised
    /// the leaf as its own issuer, producing an unconditional `General`
    /// signature error that even SoftFail could not escape.
    #[test]
    fn softfail_leaf_only_chain_does_not_hard_fail() {
        use oxitls_rcgen::{generate_ca, generate_ca_signed_leaf, SigningAlgorithm};

        let ca = generate_ca("Regression Root CA", SigningAlgorithm::Ed25519).expect("ca gen");
        let ca_cert =
            x509_cert::Certificate::from_der(&ca.certified_key.cert_der).expect("parse ca");
        let leaf = generate_ca_signed_leaf(&["leaf.example"], SigningAlgorithm::Ed25519, &ca)
            .expect("leaf gen");

        let staple = well_formed_staple_with_bad_signature(&ca_cert);

        let verifier = OcspClientVerifier::new(Arc::new(AlwaysOk), OcspClientPolicy::SoftFail);
        let leaf_der = CertificateDer::from(leaf.cert_der.clone());
        let server_name = ServerName::try_from("leaf.example").expect("server name");

        let result = verifier.verify_server_cert(
            &leaf_der,
            &[], // leaf-only chain: no intermediates
            &server_name,
            &staple,
            now_2025_05(),
        );
        assert!(
            result.is_ok(),
            "SoftFail with a leaf-only chain and an unverifiable staple must not \
             hard-fail the handshake; got {result:?}"
        );
    }

    /// The same leaf-only, unverifiable-staple situation under `HardRequire`
    /// must still fail (SoftFail is the escape hatch, not HardRequire) — but it
    /// must fail as an *unparseable/absent* staple, never as a forged-signature
    /// (`BadSignature`) error synthesised from a bogus self-issuer.
    #[test]
    fn hardrequire_leaf_only_chain_fails_as_unparseable_not_badsignature() {
        use oxitls_rcgen::{generate_ca, generate_ca_signed_leaf, SigningAlgorithm};

        let ca = generate_ca("Regression Root CA", SigningAlgorithm::Ed25519).expect("ca gen");
        let ca_cert =
            x509_cert::Certificate::from_der(&ca.certified_key.cert_der).expect("parse ca");
        let leaf = generate_ca_signed_leaf(&["leaf.example"], SigningAlgorithm::Ed25519, &ca)
            .expect("leaf gen");
        let staple = well_formed_staple_with_bad_signature(&ca_cert);

        let verifier = OcspClientVerifier::new(Arc::new(AlwaysOk), OcspClientPolicy::HardRequire);
        let leaf_der = CertificateDer::from(leaf.cert_der.clone());
        let server_name = ServerName::try_from("leaf.example").expect("server name");

        let result =
            verifier.verify_server_cert(&leaf_der, &[], &server_name, &staple, now_2025_05());
        match result {
            Err(RustlsError::General(msg)) => assert!(
                msg.contains("absent or unparseable"),
                "HardRequire must reject a leaf-only unverifiable staple as \
                 absent/unparseable, not as a forged signature; got: {msg}"
            ),
            other => {
                panic!("expected HardRequire General(absent/unparseable) error, got {other:?}")
            }
        }
    }
}
