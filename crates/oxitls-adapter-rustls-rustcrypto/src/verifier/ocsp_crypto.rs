//! Pure-Rust cryptographic helpers for RFC 6960 OCSP signer verification.
//!
//! Provides [`verify_ocsp_signature`], which dispatches over the signature
//! algorithm OID and calls the appropriate RustCrypto primitive.  Supports:
//!
//! - `1.2.840.113549.1.1.11` (sha256WithRSAEncryption) via `rsa`
//! - `1.2.840.10045.4.3.2`   (ecdsaWithSHA256) via `p256`
//! - `1.2.840.10045.4.3.3`   (ecdsaWithSHA384) via `p384`
//! - `1.3.101.112`            (id-Ed25519) via `ed25519-dalek`

use spki::SubjectPublicKeyInfoRef;
use std::fmt;
use x509_cert::der::asn1::ObjectIdentifier;

// ── OIDs ─────────────────────────────────────────────────────────────────────

/// sha256WithRSAEncryption (RFC 4055 §3.2 / RFC 3279 §2.2.1)
const OID_SHA256_WITH_RSA: &str = "1.2.840.113549.1.1.11";
/// ecdsaWithSHA256 (RFC 5480 §2.1.1)
const OID_ECDSA_WITH_SHA256: &str = "1.2.840.10045.4.3.2";
/// ecdsaWithSHA384 (RFC 5480 §2.1.1)
const OID_ECDSA_WITH_SHA384: &str = "1.2.840.10045.4.3.3";
/// id-Ed25519 (RFC 8410 §3)
const OID_ED25519: &str = "1.3.101.112";

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors returned by OCSP cryptographic verification helpers.
#[derive(Debug)]
pub enum OcspVerifyError {
    /// Algorithm OID not supported by this implementation.
    UnsupportedAlgorithm(String),
    /// Signature bytes failed cryptographic verification.
    SignatureInvalid,
    /// Delegated signer certificate does not chain to the expected issuer.
    DelegatedSignerNotTrusted(String),
    /// Delegated signer certificate is missing the id-kp-OCSPSigning EKU.
    MissingOcspSigningEku,
    /// Failed to parse the SubjectPublicKeyInfo.
    SpkiParse(String),
    /// Failed to decode the OCSP response structure.
    ResponseUnparseable(String),
}

impl fmt::Display for OcspVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedAlgorithm(oid) => {
                write!(f, "OCSP signer algorithm OID {oid} is not supported")
            }
            Self::SignatureInvalid => write!(f, "OCSP response signature verification failed"),
            Self::DelegatedSignerNotTrusted(reason) => {
                write!(f, "delegated OCSP signer not trusted: {reason}")
            }
            Self::MissingOcspSigningEku => {
                write!(
                    f,
                    "delegated OCSP signer certificate missing id-kp-OCSPSigning EKU"
                )
            }
            Self::SpkiParse(msg) => write!(f, "failed to parse SubjectPublicKeyInfo: {msg}"),
            Self::ResponseUnparseable(msg) => {
                write!(f, "OCSP response could not be decoded: {msg}")
            }
        }
    }
}

impl std::error::Error for OcspVerifyError {}

// ── Public API ────────────────────────────────────────────────────────────────

/// Verify an OCSP signature.
///
/// # Parameters
///
/// - `spki_der`: DER-encoded SubjectPublicKeyInfo of the signing key.
/// - `tbs_der`:  DER re-encoding of `tbsResponseData` (the signed bytes).
/// - `alg_oid`:  The `signatureAlgorithm` OID from `BasicOcspResponse`.
/// - `sig_bytes`: Raw signature bytes (from `BasicOcspResponse.signature`,
///   obtained via `BitString::raw_bytes()`).
///
/// # Errors
///
/// Returns [`OcspVerifyError::SignatureInvalid`] on a bad signature,
/// [`OcspVerifyError::UnsupportedAlgorithm`] for an unrecognised OID, and
/// [`OcspVerifyError::SpkiParse`] when the public key cannot be decoded.
pub fn verify_ocsp_signature(
    spki_der: &[u8],
    tbs_der: &[u8],
    alg_oid: &ObjectIdentifier,
    sig_bytes: &[u8],
) -> Result<(), OcspVerifyError> {
    let oid_str = alg_oid.to_string();
    match oid_str.as_str() {
        OID_SHA256_WITH_RSA => verify_rsa_pkcs1_sha256(spki_der, tbs_der, sig_bytes),
        OID_ECDSA_WITH_SHA256 => verify_ecdsa_p256_sha256(spki_der, tbs_der, sig_bytes),
        OID_ECDSA_WITH_SHA384 => verify_ecdsa_p384_sha384(spki_der, tbs_der, sig_bytes),
        OID_ED25519 => verify_ed25519(spki_der, tbs_der, sig_bytes),
        _ => Err(OcspVerifyError::UnsupportedAlgorithm(oid_str)),
    }
}

/// Verify the OCSP-signing Extended Key Usage (id-kp-OCSPSigning) is present
/// in a delegated signer certificate.
///
/// Must only be called for **delegated** signers — i.e., when the responder
/// is not the issuer itself.
///
/// # Errors
///
/// Returns [`OcspVerifyError::MissingOcspSigningEku`] when the extension is
/// absent or does not contain `id-kp-OCSPSigning` (OID `1.3.6.1.5.5.7.3.9`).
/// Returns [`OcspVerifyError::ResponseUnparseable`] when the certificate cannot
/// be parsed.
pub fn verify_eku_ocsp_signing(cert_der: &[u8]) -> Result<(), OcspVerifyError> {
    use x509_parser::prelude::FromDer;

    const EKU_OID: &str = "2.5.29.37";
    const OCSP_SIGNING_OID: &str = "1.3.6.1.5.5.7.3.9";

    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(cert_der).map_err(|e| {
        OcspVerifyError::ResponseUnparseable(format!("failed to parse delegated cert: {e}"))
    })?;

    // Find the extKeyUsage extension.
    for ext in cert.extensions() {
        if ext.oid.to_id_string() == EKU_OID {
            // The extension value is DER-encoded ExtKeyUsageSyntax (SEQUENCE OF OID).
            // Use x509_parser's parsed_extension helper.
            use x509_parser::extensions::ParsedExtension;
            if let ParsedExtension::ExtendedKeyUsage(eku) = ext.parsed_extension() {
                if eku.any
                    || eku
                        .other
                        .iter()
                        .any(|o| o.to_id_string() == OCSP_SIGNING_OID)
                    || eku.ocsp_signing
                {
                    return Ok(());
                }
            }
            // Extension present but OCSPSigning OID not found.
            return Err(OcspVerifyError::MissingOcspSigningEku);
        }
    }

    Err(OcspVerifyError::MissingOcspSigningEku)
}

// ── Private dispatch helpers ──────────────────────────────────────────────────

/// Extract the raw public key bytes from a DER-encoded SPKI.
fn spki_raw_bytes(spki_der: &[u8]) -> Result<Vec<u8>, OcspVerifyError> {
    let spki_ref = SubjectPublicKeyInfoRef::try_from(spki_der)
        .map_err(|e| OcspVerifyError::SpkiParse(e.to_string()))?;
    Ok(spki_ref.subject_public_key.raw_bytes().to_vec())
}

fn verify_rsa_pkcs1_sha256(
    spki_der: &[u8],
    tbs_der: &[u8],
    sig_bytes: &[u8],
) -> Result<(), OcspVerifyError> {
    use rsa::pkcs1v15::{Signature as Pkcs1Sig, VerifyingKey};
    use rsa::sha2::Sha256;
    use rsa::signature::Verifier as _;
    use x509_cert::der::Decode as _;

    // Parse the RSAPublicKey from the SPKI using the pkcs1 encoding.
    // We parse the SPKI with spki 0.7 to get the SubjectPublicKeyInfo, then
    // decode the inner RSAPublicKey from the subject_public_key bit-string content.
    let spki_ref = SubjectPublicKeyInfoRef::try_from(spki_der)
        .map_err(|e| OcspVerifyError::SpkiParse(e.to_string()))?;
    let inner_bytes = spki_ref.subject_public_key.raw_bytes();
    // inner_bytes is DER-encoded RSAPublicKey (SEQUENCE { modulus, exponent })
    let rsa_pub = rsa::pkcs1::RsaPublicKey::from_der(inner_bytes)
        .map_err(|e| OcspVerifyError::SpkiParse(format!("RSAPublicKey parse: {e}")))?;
    let n = rsa::BigUint::from_bytes_be(rsa_pub.modulus.as_bytes());
    let e = rsa::BigUint::from_bytes_be(rsa_pub.public_exponent.as_bytes());
    let key = rsa::RsaPublicKey::new(n, e)
        .map_err(|e| OcspVerifyError::SpkiParse(format!("RsaPublicKey::new: {e}")))?;

    let vk = VerifyingKey::<Sha256>::new(key);

    let sig = Pkcs1Sig::try_from(sig_bytes).map_err(|_| OcspVerifyError::SignatureInvalid)?;

    vk.verify(tbs_der, &sig)
        .map_err(|_| OcspVerifyError::SignatureInvalid)
}

fn verify_ecdsa_p256_sha256(
    spki_der: &[u8],
    tbs_der: &[u8],
    sig_bytes: &[u8],
) -> Result<(), OcspVerifyError> {
    use p256::ecdsa::{signature::Verifier as _, DerSignature, VerifyingKey};

    // Extract the SEC1-encoded public key bytes from the SPKI, then use
    // from_sec1_bytes — avoids the spki version conflict.
    let raw = spki_raw_bytes(spki_der)?;
    let vk = VerifyingKey::from_sec1_bytes(&raw)
        .map_err(|e| OcspVerifyError::SpkiParse(e.to_string()))?;

    let sig = DerSignature::try_from(sig_bytes).map_err(|_| OcspVerifyError::SignatureInvalid)?;

    vk.verify(tbs_der, &sig)
        .map_err(|_| OcspVerifyError::SignatureInvalid)
}

fn verify_ecdsa_p384_sha384(
    spki_der: &[u8],
    tbs_der: &[u8],
    sig_bytes: &[u8],
) -> Result<(), OcspVerifyError> {
    use p384::ecdsa::{signature::Verifier as _, DerSignature, VerifyingKey};

    let raw = spki_raw_bytes(spki_der)?;
    let vk = VerifyingKey::from_sec1_bytes(&raw)
        .map_err(|e| OcspVerifyError::SpkiParse(e.to_string()))?;

    let sig = DerSignature::try_from(sig_bytes).map_err(|_| OcspVerifyError::SignatureInvalid)?;

    vk.verify(tbs_der, &sig)
        .map_err(|_| OcspVerifyError::SignatureInvalid)
}

fn verify_ed25519(
    spki_der: &[u8],
    tbs_der: &[u8],
    sig_bytes: &[u8],
) -> Result<(), OcspVerifyError> {
    // Parse the SPKI to extract the raw 32-byte key.
    let raw_bytes = spki_raw_bytes(spki_der)?;
    let key_bytes: [u8; 32] = raw_bytes
        .as_slice()
        .try_into()
        .map_err(|_| OcspVerifyError::SpkiParse("Ed25519 public key must be 32 bytes".into()))?;

    let vk = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| OcspVerifyError::SpkiParse(e.to_string()))?;

    let sig = ed25519_dalek::Signature::from_slice(sig_bytes)
        .map_err(|_| OcspVerifyError::SignatureInvalid)?;

    vk.verify_strict(tbs_der, &sig)
        .map_err(|_| OcspVerifyError::SignatureInvalid)
}
