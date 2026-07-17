//! SCT (Signed Certificate Timestamp) / Certificate Transparency verification.
//!
//! [`SctVerifier`] wraps any inner [`ServerCertVerifier`] and checks that the
//! leaf certificate contains an embedded SCT list extension
//! (OID `1.3.6.1.4.1.11129.2.4.2`) with entries from recognised CT logs,
//! cryptographically verifying each SCT signature against the corresponding
//! log public key.
//!
//! Embedded SCTs are signed over a `precert_entry` (RFC 6962 §3.2), not the
//! final certificate DER. The `precert_entry` payload contains:
//! - `issuer_key_hash[32]`: SHA-256 of the issuer's SubjectPublicKeyInfo DER
//! - `TBSCertificate` of the leaf cert with the SCT list extension (OID
//!   `1.3.6.1.4.1.11129.2.4.2`) removed
//!
//! [`build_sct_signed_data`] produces `x509_entry` payloads (type 0x0000) and
//! is kept for OCSP-delivered SCTs. [`build_sct_signed_data_precert`] produces
//! `precert_entry` payloads (type 0x0001) and is used for embedded SCTs.

use std::collections::HashSet;
use std::fmt;
use std::sync::{Arc, OnceLock};

use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, Error as RustlsError, SignatureScheme,
};
use sha2::{Digest as _, Sha256};
use x509_cert::{
    certificate::Certificate,
    der::{asn1::ObjectIdentifier, Decode, Encode},
};
use x509_parser::{certificate::X509Certificate, prelude::FromDer};

/// OID for the embedded SCT list extension (RFC 6962 §3.3).
const SCT_LIST_OID: &str = "1.3.6.1.4.1.11129.2.4.2";

/// The OID for the SCT list extension as an `ObjectIdentifier`, used for
/// matching when filtering extensions via x509-cert's type system.
///
/// `new_unwrap` in a `const` context panics at **compile time** if the string
/// is invalid — this is a static guarantee, not a runtime `unwrap`.
const SCT_LIST_OID_CONST: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.4.2");

// ── SCT parsing ───────────────────────────────────────────────────────────────

/// A fully-parsed SCT entry from the embedded SCT list extension.
///
/// Wire format per RFC 6962 §3.2:
/// ```text
/// struct {
///   Version sct_version;             // u8
///   LogID id;                        // [32]
///   uint64 timestamp;                // u64 BE
///   CtExtensions extensions;         // u16 length-prefixed
///   Signature signature;             // hash u8, sig u8, u16 length-prefixed bytes
/// }
/// ```
#[derive(Debug, Clone)]
pub struct ParsedSct {
    /// SCT version byte (0x00 = v1).
    pub sct_version: u8,
    /// 32-byte SHA-256 log ID.
    pub log_id: [u8; 32],
    /// Timestamp in milliseconds since the Unix epoch (big-endian u64).
    pub timestamp_ms: u64,
    /// Raw extension bytes (may be empty).
    pub extensions: Vec<u8>,
    /// Hash algorithm identifier byte (2 = SHA-256).
    pub hash_alg: u8,
    /// Signature algorithm identifier byte (3 = ECDSA, 7 = Ed25519).
    pub sig_alg: u8,
    /// Raw signature bytes.
    pub signature: Vec<u8>,
}

/// Error returned when parsing an SCT list fails.
#[derive(Debug)]
pub enum SctParseError {
    /// The outer list length field exceeds the available bytes.
    ListLenOverflow,
    /// An individual SCT entry length field exceeds the remaining bytes.
    EntryLenOverflow,
    /// An SCT entry is too short to contain the mandatory fields.
    EntryTooShort,
    /// SCT version byte is not 0x00.
    UnknownVersion(u8),
}

impl fmt::Display for SctParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ListLenOverflow => write!(f, "SCT list length exceeds available bytes"),
            Self::EntryLenOverflow => {
                write!(f, "SCT entry length exceeds remaining list bytes")
            }
            Self::EntryTooShort => write!(f, "SCT entry is too short"),
            Self::UnknownVersion(v) => write!(f, "unknown SCT version 0x{v:02x}"),
        }
    }
}

impl std::error::Error for SctParseError {}

/// Error returned when SCT signature verification fails.
#[derive(Debug)]
pub enum SctVerifyError {
    /// The log key algorithm is not supported.
    UnsupportedKeyAlg,
    /// Signature verification failed.
    SignatureInvalid,
    /// The public key could not be decoded.
    KeyDecode(String),
    /// The signature bytes could not be decoded.
    SigDecode(String),
    /// Certificate parsing or re-encoding failed (e.g. precert reconstruction).
    ParseError(String),
}

impl fmt::Display for SctVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedKeyAlg => write!(f, "SCT log key algorithm not supported"),
            Self::SignatureInvalid => write!(f, "SCT signature verification failed"),
            Self::KeyDecode(msg) => write!(f, "SCT log key decode error: {msg}"),
            Self::SigDecode(msg) => write!(f, "SCT signature decode error: {msg}"),
            Self::ParseError(msg) => write!(f, "SCT precert parse/encode error: {msg}"),
        }
    }
}

impl std::error::Error for SctVerifyError {}

// ── CT log types ──────────────────────────────────────────────────────────────

/// Key algorithm used by a CT log's signing key.
#[derive(Debug, Clone)]
pub enum CtKeyAlg {
    /// ECDSA P-256 with SHA-256.
    EcdsaP256Sha256,
    /// Ed25519.
    Ed25519,
}

/// A trusted Certificate Transparency log entry.
#[derive(Debug, Clone)]
pub struct CtLog {
    /// 32-byte SHA-256 hash of the log's DER-encoded public key (the log ID
    /// as defined in RFC 6962 §3.2).
    pub id: [u8; 32],
    /// DER-encoded SubjectPublicKeyInfo of the log's signing key.
    pub public_key_der: Vec<u8>,
    /// Signing algorithm of the log key.
    pub key_alg: CtKeyAlg,
}

/// An ordered list of trusted CT logs used to validate SCT entries.
#[derive(Debug, Clone)]
pub struct CtLogList(pub Vec<CtLog>);

impl CtLogList {
    /// Create an empty log list.
    ///
    /// When used with [`SctPolicy::Permissive`], an empty list allows all
    /// handshakes while emitting a warning. When used with
    /// [`SctPolicy::Strict`], it will cause every handshake that has an SCT
    /// extension to fail (zero trusted logs found).
    pub fn empty() -> Self {
        Self(vec![])
    }

    /// Returns `true` if the log list contains no entries.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Policy controlling how SCT / CT log verification is applied.
#[derive(Debug, Clone)]
pub enum SctPolicy {
    /// Do not check SCTs. The inner verifier is called unconditionally.
    Disabled,

    /// Best-effort: missing SCT extension or empty log list emits a warning
    /// and allows the handshake to continue. Insufficient distinct logs also
    /// only warns.
    Permissive {
        /// Minimum number of distinct trusted logs that must appear in the
        /// SCT list.
        min_distinct_logs: u8,
    },

    /// Strict: missing SCT extension causes handshake failure. Insufficient
    /// distinct logs also causes failure.
    Strict {
        /// Minimum number of distinct trusted logs that must appear in the
        /// SCT list.
        min_distinct_logs: u8,
    },
}

/// A [`ServerCertVerifier`] that inspects the embedded SCT list extension of
/// the leaf certificate and checks it against a list of trusted CT logs,
/// cryptographically verifying each SCT signature.
pub struct SctVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    policy: SctPolicy,
    logs: CtLogList,
    /// Tracks whether the empty-log-list warning has been emitted (once-only).
    empty_log_warned: OnceLock<bool>,
}

impl std::fmt::Debug for SctVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SctVerifier")
            .field("policy", &self.policy)
            .field("num_logs", &self.logs.0.len())
            .finish_non_exhaustive()
    }
}

impl SctVerifier {
    /// Create a new `SctVerifier`.
    pub fn new(inner: Arc<dyn ServerCertVerifier>, policy: SctPolicy, logs: CtLogList) -> Self {
        Self {
            inner,
            policy,
            logs,
            empty_log_warned: OnceLock::new(),
        }
    }

    /// Access the configured policy.
    pub fn policy(&self) -> &SctPolicy {
        &self.policy
    }
}

// ── SCT parsing ───────────────────────────────────────────────────────────────

/// Parse the raw SCT list extension value (RFC 6962 §3.3 / §3.2).
///
/// Wire format (the bytes come from the extension's OctetString value):
/// ```text
/// u16-BE  total_length_of_list
/// Repeated:
///     u16-BE  sct_length
///     [sct_length bytes]:
///         u8      version (0 = v1)
///         [32]    log_id
///         u64-BE  timestamp_ms
///         u16-BE  ext_len
///         [ext_len bytes]  extensions
///         u8      hash_alg
///         u8      sig_alg
///         u16-BE  sig_len
///         [sig_len bytes]  signature
/// ```
pub fn parse_sct_list(bytes: &[u8]) -> Result<Vec<ParsedSct>, SctParseError> {
    let mut out = Vec::new();

    if bytes.len() < 2 {
        return Ok(out);
    }

    let list_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
    let mut pos = 2usize;
    let end = pos + list_len;

    if end > bytes.len() {
        return Err(SctParseError::ListLenOverflow);
    }

    while pos + 2 <= end {
        let sct_len = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
        pos += 2;

        if pos + sct_len > end {
            return Err(SctParseError::EntryLenOverflow);
        }

        let sct_bytes = &bytes[pos..pos + sct_len];
        pos += sct_len;

        if sct_bytes.len() < 43 {
            // Minimum: 1 + 32 + 8 + 2 = 43 bytes before any extensions/sig
            return Err(SctParseError::EntryTooShort);
        }

        let version = sct_bytes[0];
        if version != 0x00 {
            return Err(SctParseError::UnknownVersion(version));
        }

        let mut log_id = [0u8; 32];
        log_id.copy_from_slice(&sct_bytes[1..33]);

        let timestamp_ms = u64::from_be_bytes(
            sct_bytes[33..41]
                .try_into()
                .map_err(|_| SctParseError::EntryTooShort)?,
        );

        let mut inner_pos = 41usize;

        if inner_pos + 2 > sct_bytes.len() {
            return Err(SctParseError::EntryTooShort);
        }
        let ext_len = u16::from_be_bytes([sct_bytes[inner_pos], sct_bytes[inner_pos + 1]]) as usize;
        inner_pos += 2;

        if inner_pos + ext_len > sct_bytes.len() {
            return Err(SctParseError::EntryTooShort);
        }
        let extensions = sct_bytes[inner_pos..inner_pos + ext_len].to_vec();
        inner_pos += ext_len;

        // hash_alg + sig_alg + sig_len + sig
        if inner_pos + 4 > sct_bytes.len() {
            return Err(SctParseError::EntryTooShort);
        }
        let hash_alg = sct_bytes[inner_pos];
        let sig_alg = sct_bytes[inner_pos + 1];
        let sig_len =
            u16::from_be_bytes([sct_bytes[inner_pos + 2], sct_bytes[inner_pos + 3]]) as usize;
        inner_pos += 4;

        if inner_pos + sig_len > sct_bytes.len() {
            return Err(SctParseError::EntryTooShort);
        }
        let signature = sct_bytes[inner_pos..inner_pos + sig_len].to_vec();

        tracing::debug!(
            log_id_prefix = hex_id(&log_id),
            timestamp_ms,
            "Parsed SCT entry"
        );

        out.push(ParsedSct {
            sct_version: version,
            log_id,
            timestamp_ms,
            extensions,
            hash_alg,
            sig_alg,
            signature,
        });
    }

    Ok(out)
}

/// Build the RFC 6962 §3.2 `digitally-signed` input for a certificate SCT
/// delivered via OCSP (`x509_entry`, type 0x0000).
///
/// Structure:
/// ```text
/// struct {
///   Version          sct_version;         // 0x00
///   SignatureType    signature_type;       // 0x00 (certificate_timestamp)
///   uint64           timestamp;           // 8 bytes big-endian
///   LogEntryType     entry_type;          // 0x00 0x00 (x509_entry)
///   ASN.1Cert        signed_entry;        // u24 length + cert_der
///   CtExtensions     extensions;          // u16 length + extensions
/// }
/// ```
pub fn build_sct_signed_data(sct: &ParsedSct, cert_der: &[u8]) -> Vec<u8> {
    let cert_len = cert_der.len();
    let ext_len = sct.extensions.len();

    let mut buf = Vec::with_capacity(2 + 8 + 2 + 3 + cert_len + 2 + ext_len);

    // version + signature_type
    buf.push(0x00); // sct_version = v1
    buf.push(0x00); // signature_type = certificate_timestamp

    // timestamp (u64 big-endian)
    buf.extend_from_slice(&sct.timestamp_ms.to_be_bytes());

    // entry_type = x509_entry (u16 = 0)
    buf.push(0x00);
    buf.push(0x00);

    // signed_entry: u24 cert length + cert DER
    buf.push(((cert_len >> 16) & 0xff) as u8);
    buf.push(((cert_len >> 8) & 0xff) as u8);
    buf.push((cert_len & 0xff) as u8);
    buf.extend_from_slice(cert_der);

    // extensions: u16 length + bytes
    buf.push(((ext_len >> 8) & 0xff) as u8);
    buf.push((ext_len & 0xff) as u8);
    buf.extend_from_slice(&sct.extensions);

    buf
}

/// Build the RFC 6962 §3.2 `digitally-signed` input for an **embedded** SCT
/// (`precert_entry`, type 0x0001).
///
/// Per RFC 6962 §3.2, embedded SCTs are signed over:
/// ```text
/// struct {
///   Version          sct_version;       // 0x00
///   SignatureType    signature_type;    // 0x00 (certificate_timestamp)
///   uint64           timestamp;         // 8 bytes big-endian
///   LogEntryType     entry_type;        // 0x00 0x01 (precert_entry)
///   [32]             issuer_key_hash;   // SHA-256 of issuer SPKI DER
///   u24              tbs_length;        // length of modified TBSCertificate
///   [tbs_length]     tbs_no_sct;        // TBS with SCT extension removed
///   u16              ext_length;        // length of CtExtensions
///   [ext_length]     extensions;        // CtExtensions bytes
/// }
/// ```
pub fn build_sct_signed_data_precert(
    sct: &ParsedSct,
    tbs_no_sct: &[u8],
    issuer_key_hash: &[u8; 32],
) -> Vec<u8> {
    let tbs_len = tbs_no_sct.len();
    let ext_len = sct.extensions.len();

    let mut buf = Vec::with_capacity(2 + 8 + 2 + 32 + 3 + tbs_len + 2 + ext_len);

    // version (0x00 = v1) + signature_type (0x00 = certificate_timestamp)
    buf.push(sct.sct_version);
    buf.push(0x00);

    // timestamp (u64 big-endian)
    buf.extend_from_slice(&sct.timestamp_ms.to_be_bytes());

    // entry_type = precert_entry = 0x0001
    buf.push(0x00);
    buf.push(0x01);

    // issuer_key_hash (32 bytes, no length prefix — fixed-size field)
    buf.extend_from_slice(issuer_key_hash);

    // u24_be(tbs_len) + tbs_no_sct
    buf.push(((tbs_len >> 16) & 0xff) as u8);
    buf.push(((tbs_len >> 8) & 0xff) as u8);
    buf.push((tbs_len & 0xff) as u8);
    buf.extend_from_slice(tbs_no_sct);

    // u16_be(ext_len) + extensions
    buf.extend_from_slice(&(ext_len as u16).to_be_bytes());
    buf.extend_from_slice(&sct.extensions);

    buf
}

/// Reconstruct the `precert_entry` inputs required for embedded-SCT
/// verification per RFC 6962 §3.2.
///
/// Returns `(issuer_key_hash, tbs_without_sct_extension_der)` where:
/// - `issuer_key_hash` is the SHA-256 hash of the issuer certificate's
///   SubjectPublicKeyInfo DER bytes (raw, not re-encoded).
/// - `tbs_without_sct_extension_der` is the leaf certificate's
///   TBSCertificate re-encoded with the SCT list extension
///   (OID `1.3.6.1.4.1.11129.2.4.2`) removed.
///
/// # Errors
/// Returns [`SctVerifyError::ParseError`] if either certificate cannot be
/// parsed or the modified TBSCertificate cannot be DER-encoded.
pub fn precert_tbs_and_issuer_hash(
    leaf_der: &[u8],
    issuer_der: &[u8],
) -> Result<([u8; 32], Vec<u8>), SctVerifyError> {
    // ── 1. Compute issuer_key_hash from raw SPKI bytes (no re-encode) ─────────
    //
    // We use x509-parser here because it exposes the raw SubjectPublicKeyInfo
    // bytes directly via `SubjectPublicKeyInfo::raw`, avoiding any re-encoding
    // that could introduce DER differences.
    let (_, issuer_parsed) = X509Certificate::from_der(issuer_der)
        .map_err(|e| SctVerifyError::ParseError(format!("issuer cert parse: {e}")))?;

    let issuer_spki_raw = issuer_parsed.tbs_certificate.public_key().raw;

    let issuer_key_hash: [u8; 32] = Sha256::digest(issuer_spki_raw).into();

    // ── 2. Strip the SCT list extension from the leaf TBSCertificate ──────────
    //
    // We use x509-cert (which derives `Sequence` → `Encode`) to parse and
    // re-encode the modified TBSCertificate.  The OID comparison uses the
    // compile-time constant `SCT_LIST_OID_CONST` so there is no runtime
    // string allocation.
    let leaf_cert = Certificate::from_der(leaf_der)
        .map_err(|e| SctVerifyError::ParseError(format!("leaf cert parse: {e}")))?;

    let mut tbs = leaf_cert.tbs_certificate;

    if let Some(exts) = tbs.extensions.as_mut() {
        exts.retain(|ext| ext.extn_id != SCT_LIST_OID_CONST);
    }

    // Re-encode the modified TBSCertificate to DER.
    let tbs_bytes = tbs
        .to_der()
        .map_err(|e| SctVerifyError::ParseError(format!("tbs re-encode: {e}")))?;

    Ok((issuer_key_hash, tbs_bytes))
}

/// Verify an SCT signature against the given [`CtLog`].
pub fn verify_sct_signature(
    log: &CtLog,
    signed_data: &[u8],
    sct: &ParsedSct,
) -> Result<(), SctVerifyError> {
    match log.key_alg {
        CtKeyAlg::EcdsaP256Sha256 => {
            use p256::ecdsa::{signature::Verifier as _, DerSignature, VerifyingKey};
            use spki::SubjectPublicKeyInfoRef;

            // Use spki 0.7 to extract raw SEC1 bytes, then use from_sec1_bytes
            // to avoid the spki 0.7 vs 0.8 version conflict.
            let spki_ref = SubjectPublicKeyInfoRef::try_from(log.public_key_der.as_slice())
                .map_err(|e| SctVerifyError::KeyDecode(e.to_string()))?;
            let raw = spki_ref.subject_public_key.raw_bytes();

            let vk = VerifyingKey::from_sec1_bytes(raw)
                .map_err(|e| SctVerifyError::KeyDecode(e.to_string()))?;
            let sig = DerSignature::try_from(sct.signature.as_slice())
                .map_err(|e| SctVerifyError::SigDecode(e.to_string()))?;
            vk.verify(signed_data, &sig)
                .map_err(|_| SctVerifyError::SignatureInvalid)
        }
        CtKeyAlg::Ed25519 => {
            use spki::SubjectPublicKeyInfoRef;

            let spki_ref = SubjectPublicKeyInfoRef::try_from(log.public_key_der.as_slice())
                .map_err(|e| SctVerifyError::KeyDecode(e.to_string()))?;

            let raw = spki_ref.subject_public_key.raw_bytes();
            let key_arr: [u8; 32] = raw
                .try_into()
                .map_err(|_| SctVerifyError::KeyDecode("Ed25519 key must be 32 bytes".into()))?;

            let vk = ed25519_dalek::VerifyingKey::from_bytes(&key_arr)
                .map_err(|e| SctVerifyError::KeyDecode(e.to_string()))?;

            let sig = ed25519_dalek::Signature::from_slice(&sct.signature)
                .map_err(|e| SctVerifyError::SigDecode(e.to_string()))?;

            vk.verify_strict(signed_data, &sig)
                .map_err(|_| SctVerifyError::SignatureInvalid)
        }
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Format first 8 bytes of a log ID as hex for debug output.
fn hex_id(id: &[u8; 32]) -> String {
    id.iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

/// Count how many of the `scts` have valid signatures from trusted logs
/// (de-duplicated by log ID).
///
/// For embedded SCTs (`issuer_der` is `Some`), the signed payload is a
/// `precert_entry` (RFC 6962 §3.2 type 0x0001).  For OCSP-delivered SCTs
/// (`issuer_der` is `None`), the signed payload is an `x509_entry` (type
/// 0x0000).
fn count_trusted_verified(
    scts: &[ParsedSct],
    logs: &CtLogList,
    leaf_der: &[u8],
    issuer_der: Option<&[u8]>,
) -> u8 {
    // Pre-compute the precert inputs once (they are identical for all SCTs in
    // the same handshake).  On failure we log a warning and fall back to zero
    // verified SCTs, which fails closed under Strict policy.
    let precert_inputs: Option<([u8; 32], Vec<u8>)> = match issuer_der {
        Some(issuer) => match precert_tbs_and_issuer_hash(leaf_der, issuer) {
            Ok(pair) => Some(pair),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "precert reconstruction failed; embedded SCT verification will count 0"
                );
                None
            }
        },
        None => None,
    };

    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    for sct in scts {
        // Already counted this log.
        if seen.contains(&sct.log_id) {
            continue;
        }

        // Look up the log by log_id.
        let log = match logs.0.iter().find(|l| l.id == sct.log_id) {
            Some(l) => l,
            None => {
                tracing::debug!(
                    log_id = hex_id(&sct.log_id),
                    "SCT log ID not in trusted log list"
                );
                continue;
            }
        };

        // Build the signed data: precert_entry for embedded SCTs, x509_entry
        // for OCSP-delivered SCTs.
        let signed_data = match &precert_inputs {
            Some((issuer_key_hash, tbs_no_sct)) => {
                build_sct_signed_data_precert(sct, tbs_no_sct, issuer_key_hash)
            }
            None => build_sct_signed_data(sct, leaf_der),
        };

        match verify_sct_signature(log, &signed_data, sct) {
            Ok(()) => {
                tracing::debug!(
                    log_id = hex_id(&sct.log_id),
                    "SCT signature verified successfully"
                );
                seen.insert(sct.log_id);
            }
            Err(e) => {
                tracing::warn!(
                    log_id = hex_id(&sct.log_id),
                    error = %e,
                    "SCT signature verification failed"
                );
            }
        }
    }
    // Saturating cast: at most 255 distinct logs in practice.
    seen.len().min(usize::from(u8::MAX)) as u8
}

/// Strip the nested DER `OCTET STRING` (tag + length) that wraps the
/// TLS-encoded SCT list inside the extension value.
///
/// RFC 6962 §3.3 defines the extension value as an `OCTET STRING` whose content
/// is itself `SignedCertificateTimestampList ::= OCTET STRING`. `x509-parser`
/// hands us the *content* of the outer extnValue `OCTET STRING`, which is still
/// a DER `OCTET STRING` (`0x04 <len> <tls-encoded list>`). The bytes that
/// [`parse_sct_list`] expects (`u16` list length followed by the SCTs) only
/// begin after this inner tag+length.
///
/// Returns `None` when the bytes are not a well-formed definite-length DER
/// `OCTET STRING`.
fn strip_sct_octet_string(bytes: &[u8]) -> Option<&[u8]> {
    let (&tag, rest) = bytes.split_first()?;
    if tag != 0x04 {
        return None;
    }
    let (&len_byte, rest) = rest.split_first()?;
    let (content_len, rest) = if len_byte < 0x80 {
        (usize::from(len_byte), rest)
    } else {
        // Long-form length. 0x80 (indefinite) is invalid in DER; support the
        // 1- and 2-byte forms that cover any real-world SCT list (< 64 KiB).
        let num_bytes = usize::from(len_byte & 0x7f);
        if num_bytes == 0 || num_bytes > 2 || rest.len() < num_bytes {
            return None;
        }
        let mut len = 0usize;
        for &b in &rest[..num_bytes] {
            len = (len << 8) | usize::from(b);
        }
        (len, &rest[num_bytes..])
    };
    if rest.len() < content_len {
        return None;
    }
    Some(&rest[..content_len])
}

/// Try to extract the raw TLS-encoded SCT list from a DER cert.
///
/// Returns `None` if the extension is absent, the cert cannot be parsed, or the
/// nested `OCTET STRING` wrapper is malformed.
fn extract_sct_extension(cert_der: &CertificateDer<'_>) -> Option<Vec<u8>> {
    let (_, cert) = X509Certificate::from_der(cert_der.as_ref()).ok()?;
    let ext = cert
        .extensions()
        .iter()
        .find(|e| e.oid.to_id_string() == SCT_LIST_OID)?;
    // The extension value wraps the TLS-encoded SCT list in a nested DER
    // OCTET STRING; strip it before returning the raw list bytes.
    strip_sct_octet_string(ext.value).map(<[u8]>::to_vec)
}

impl ServerCertVerifier for SctVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        let is_strict = matches!(self.policy, SctPolicy::Strict { .. });

        if matches!(self.policy, SctPolicy::Disabled) {
            return self.inner.verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            );
        }

        // Warn once if the log list is empty.
        if self.logs.is_empty() {
            let _ = self.empty_log_warned.get_or_init(|| {
                tracing::warn!(
                    "SctVerifier: trusted CT log list is empty; \
                     all SCT log ID checks will find zero trusted logs"
                );
                true
            });
        }

        // Try to extract the SCT extension from the leaf cert.
        let sct_value = extract_sct_extension(end_entity);

        let (min_logs, scts) = match sct_value {
            None => {
                // No SCT extension present.
                if is_strict {
                    return Err(RustlsError::General(
                        "No SCT extension found in leaf certificate (strict SCT policy)".into(),
                    ));
                }
                tracing::warn!(
                    "No SCT extension found in leaf certificate; \
                     permissive SCT policy allows handshake to continue"
                );
                return self.inner.verify_server_cert(
                    end_entity,
                    intermediates,
                    server_name,
                    ocsp_response,
                    now,
                );
            }
            Some(ref val) => {
                let parsed = match parse_sct_list(val) {
                    Ok(v) => v,
                    Err(e) => {
                        let msg = format!("failed to parse SCT list: {e}");
                        if is_strict {
                            return Err(RustlsError::General(msg));
                        }
                        tracing::warn!("{msg}; permissive policy continues");
                        return self.inner.verify_server_cert(
                            end_entity,
                            intermediates,
                            server_name,
                            ocsp_response,
                            now,
                        );
                    }
                };
                let min = match &self.policy {
                    SctPolicy::Permissive { min_distinct_logs } => *min_distinct_logs,
                    SctPolicy::Strict { min_distinct_logs } => *min_distinct_logs,
                    SctPolicy::Disabled => 0,
                };
                (min, parsed)
            }
        };

        // Embedded SCTs require the issuer cert to reconstruct the precert
        // signed payload.  Pass the first intermediate as the issuer.
        let issuer_der: Option<&[u8]> = intermediates.first().map(|c| c.as_ref());

        // Count SCTs that have valid cryptographic signatures from trusted logs.
        let distinct = count_trusted_verified(&scts, &self.logs, end_entity.as_ref(), issuer_der);

        if distinct < min_logs {
            let msg = format!(
                "SCT policy requires {min_logs} distinct trusted log(s) with valid signatures, \
                 found {distinct}"
            );
            if is_strict {
                return Err(RustlsError::General(msg));
            }
            tracing::warn!("{msg}; permissive policy allows continuation");
        }

        // Delegate chain / signature validation to the inner verifier.
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

    /// Build one minimal, structurally-valid SCT entry (47 bytes) wrapped in the
    /// enclosing TLS `SignedCertificateTimestampList` wire format.
    fn minimal_sct_list_wire() -> Vec<u8> {
        let mut entry = Vec::new();
        entry.push(0x00); // version v1
        entry.extend_from_slice(&[0xAB; 32]); // log_id
        entry.extend_from_slice(&0x0102_0304_0506_0708u64.to_be_bytes()); // timestamp
        entry.extend_from_slice(&0u16.to_be_bytes()); // ext_len = 0
        entry.push(0x04); // hash_alg (sha256)
        entry.push(0x03); // sig_alg (ecdsa)
        entry.extend_from_slice(&0u16.to_be_bytes()); // sig_len = 0
        assert_eq!(entry.len(), 47);

        let entry_len = u16::try_from(entry.len()).expect("entry fits u16");
        let body_len = u16::try_from(2 + entry.len()).expect("body fits u16");
        let mut wire = Vec::new();
        wire.extend_from_slice(&body_len.to_be_bytes());
        wire.extend_from_slice(&entry_len.to_be_bytes());
        wire.extend_from_slice(&entry);
        wire
    }

    /// Wrap `content` in a short-form DER `OCTET STRING`.
    fn der_octet_string(content: &[u8]) -> Vec<u8> {
        let len = u8::try_from(content.len()).expect("short form");
        let mut v = vec![0x04, len];
        v.extend_from_slice(content);
        v
    }

    #[test]
    fn strip_octet_string_unwraps_wrapped_sct_list() {
        let wire = minimal_sct_list_wire();
        let wrapped = der_octet_string(&wire);

        let stripped = strip_sct_octet_string(&wrapped).expect("well-formed OCTET STRING");
        assert_eq!(stripped, wire.as_slice());

        // The stripped bytes parse into exactly one SCT.
        let scts = parse_sct_list(stripped).expect("stripped list parses");
        assert_eq!(scts.len(), 1);

        // Regression guard: feeding the *un-stripped* bytes to the parser
        // misparses (the DER tag/length are read as the list length).
        assert!(
            parse_sct_list(&wrapped).is_err(),
            "un-stripped wrapper must not parse as an SCT list"
        );
    }

    #[test]
    fn strip_octet_string_supports_long_form_length() {
        let content = vec![0xEE; 200];
        let mut wrapped = vec![0x04, 0x81, 200]; // long form: 0x81 <len>
        wrapped.extend_from_slice(&content);
        let stripped = strip_sct_octet_string(&wrapped).expect("long-form OCTET STRING");
        assert_eq!(stripped, content.as_slice());
    }

    #[test]
    fn strip_octet_string_rejects_malformed() {
        assert!(strip_sct_octet_string(&[]).is_none(), "empty");
        assert!(strip_sct_octet_string(&[0x30, 0x00]).is_none(), "wrong tag");
        assert!(
            strip_sct_octet_string(&[0x04, 0x05, 0x00]).is_none(),
            "truncated content"
        );
    }

    /// End-to-end: a certificate carrying a correctly nested SCT-list extension
    /// yields the raw list bytes, which then parse into one SCT.
    #[test]
    fn extract_sct_extension_strips_nested_octet_string() {
        use rcgen::{CertificateParams, CustomExtension, KeyPair};

        let wire = minimal_sct_list_wire();
        let wrapped = der_octet_string(&wire);

        let mut params = CertificateParams::new(vec!["localhost".to_string()]).expect("params");
        let sct_oid: &[u64] = &[1, 3, 6, 1, 4, 1, 11129, 2, 4, 2];
        params
            .custom_extensions
            .push(CustomExtension::from_oid_content(sct_oid, wrapped));
        let kp = KeyPair::generate().expect("keypair");
        let cert = params.self_signed(&kp).expect("self-signed");
        let cert_der = CertificateDer::from(cert.der().to_vec());

        let extracted = extract_sct_extension(&cert_der).expect("SCT ext present");
        assert_eq!(extracted, wire, "extract must return the unwrapped list");
        assert_eq!(parse_sct_list(&extracted).expect("parses").len(), 1);
    }
}
