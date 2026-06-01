//! Certificate Signing Request (CSR) generation and signing.
//!
//! This module is intentionally independent of rcgen's `CertificateSigningRequestParams::from_der`:
//! that helper unconditionally invokes `x509-parser`'s `verify_signature`, which compiles only
//! when the `verify` feature is enabled — and that pulls in `ring`. Because oxitls-rcgen
//! must remain Pure Rust (no ring / aws-lc-rs), we parse CSRs directly with `x509-parser`
//! (no verification feature) and re-sign via a small adapter that implements
//! [`rcgen::PublicKeyData`] over the extracted SubjectPublicKeyInfo BIT STRING.
//!
//! # Signature verification
//!
//! Signature verification on the inbound CSR is intentionally **not** performed here. In
//! production deployments where the CSR may originate from a hostile party, the caller
//! must verify the signature out-of-band (e.g. through a Pure-Rust verifier wired to the
//! same algorithm family). For internal-use CA flows that produce the CSR with one of
//! this crate's own `OxiEcdsa*Key`/`OxiRsa*Key` types, the in-memory roundtrip is
//! authenticated by construction.

use rcgen::{
    CertificateParams, DistinguishedName, DnType, PublicKeyData, SanType, SerialNumber,
    SignatureAlgorithm, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384, PKCS_ED25519,
    PKCS_RSA_SHA256,
};
use sha2::{Digest, Sha256};

use oxitls_core::TlsError;

use crate::cert::{CaCertifiedKey, CaSignerInner, SigningAlgorithm};
use crate::keypair::{
    OxiEcdsaP256Key, OxiEcdsaP384Key, OxiEd25519Key, OxiRsa2048Key, OxiRsa4096Key,
};

/// A serialized certificate signing request.
///
/// `der` is the binary PKCS#10 encoding; `pem` is the standard
/// `-----BEGIN CERTIFICATE REQUEST-----` block.
#[derive(Debug, Clone)]
pub struct CsrBytes {
    /// DER-encoded PKCS#10 CSR.
    pub der: Vec<u8>,
    /// PEM-encoded PKCS#10 CSR (`-----BEGIN CERTIFICATE REQUEST-----`).
    pub pem: String,
}

/// A certificate issued by signing a CSR.
///
/// Unlike [`crate::CertifiedKey`], this struct intentionally does **not** carry
/// a private key — the CA never sees the subject's private key in a real CSR
/// flow, only the public key embedded in the CSR.
#[derive(Debug, Clone)]
pub struct SignedCertificate {
    /// DER-encoded X.509 certificate.
    pub cert_der: Vec<u8>,
    /// PEM-encoded X.509 certificate.
    pub cert_pem: String,
}

// ── CSR generation ───────────────────────────────────────────────────────────

/// Generate a fresh CSR for the given subject CN using the chosen algorithm.
///
/// The returned tuple is `(csr_bytes, pkcs8_der_private_key)`. The caller
/// retains the private key — CSRs themselves do **not** embed a private key.
///
/// # Algorithms
/// All five [`SigningAlgorithm`] variants are supported. RSA-4096 keygen takes
/// 2–5 seconds; document accordingly when invoking from a request handler.
///
/// # Errors
/// Returns [`TlsError`] on key generation or CSR serialization failure.
pub fn generate_csr(
    subject_cn: &str,
    alg: SigningAlgorithm,
) -> Result<(CsrBytes, Vec<u8>), TlsError> {
    match alg {
        SigningAlgorithm::Ed25519 => {
            let key = OxiEd25519Key::generate()?;
            let csr = build_csr_with_key(subject_cn, &key)?;
            Ok((csr, key.pkcs8_der().to_vec()))
        }
        SigningAlgorithm::EcdsaP256 => {
            let key = OxiEcdsaP256Key::generate()?;
            let csr = build_csr_with_key(subject_cn, &key)?;
            Ok((csr, key.pkcs8_der().to_vec()))
        }
        SigningAlgorithm::EcdsaP384 => {
            let key = OxiEcdsaP384Key::generate()?;
            let csr = build_csr_with_key(subject_cn, &key)?;
            Ok((csr, key.pkcs8_der().to_vec()))
        }
        SigningAlgorithm::Rsa2048 => {
            let key = OxiRsa2048Key::generate()?;
            let csr = build_csr_with_key(subject_cn, &key)?;
            Ok((csr, key.pkcs8_der().to_vec()))
        }
        SigningAlgorithm::Rsa4096 => {
            let key = OxiRsa4096Key::generate()?;
            let csr = build_csr_with_key(subject_cn, &key)?;
            Ok((csr, key.pkcs8_der().to_vec()))
        }
    }
}

/// Build a CSR (PKCS#10) from a generic signing key implementing rcgen's
/// `SigningKey + PublicKeyData` pair.
fn build_csr_with_key<K>(subject_cn: &str, key: &K) -> Result<CsrBytes, TlsError>
where
    K: rcgen::SigningKey + PublicKeyData,
{
    // Build minimal CertificateParams. CSRs don't carry not_before/not_after
    // — rcgen silently drops those when serializing the request.
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, subject_cn);
    params.distinguished_name = dn;
    // SAN derived from the CN keeps the CSR self-contained for callers that
    // immediately pass the result into a TLS handshake test harness.
    let san: SanType = subject_cn
        .to_string()
        .try_into()
        .map(SanType::DnsName)
        .map_err(|e: rcgen::Error| TlsError::InvalidConfig(e.to_string()))?;
    params.subject_alt_names = vec![san];

    let csr = params
        .serialize_request(key)
        .map_err(|e| TlsError::InvalidConfig(format!("CSR serialize: {e}")))?;
    let der = csr.der().to_vec();
    let pem = csr
        .pem()
        .map_err(|e| TlsError::InvalidConfig(format!("CSR pem: {e}")))?;
    Ok(CsrBytes { der, pem })
}

// ── CSR signing ──────────────────────────────────────────────────────────────

/// Sign a CSR with the given CA, producing a leaf certificate valid for
/// `validity_days` days starting from the current system time.
///
/// The output certificate carries the CSR's subject public key (extracted from
/// the SubjectPublicKeyInfo BIT STRING) and is signed by the CA's private key.
///
/// # Signature verification
/// This function does **not** verify the CSR's self-signature. Production
/// callers should verify the CSR's signature out-of-band with a Pure-Rust
/// verifier before invoking this function.
///
/// # Errors
/// Returns [`TlsError`] if the CSR cannot be parsed, if the algorithm OID is
/// unrecognised, or if rcgen rejects the constructed parameters.
pub fn sign_csr(
    csr_der: &[u8],
    ca: &CaCertifiedKey,
    validity_days: u32,
) -> Result<SignedCertificate, TlsError> {
    // 1. Parse the inbound CSR with x509-parser (no verify feature → no ring).
    let parsed = parse_csr_components(csr_der)?;

    // 2. Build CertificateParams that pin the subject DN and SANs from the
    //    CSR. Validity period comes from the CA's choice (not the CSR — which
    //    cannot legally specify it per RFC 2986).
    let mut params = CertificateParams::default();
    params.distinguished_name = parsed.subject_dn;
    params.subject_alt_names = parsed.sans;
    let kid: Vec<u8> = Sha256::digest(&parsed.spki_full).to_vec();
    params.key_identifier_method = rcgen::KeyIdMethod::PreSpecified(kid);
    params.serial_number = Some(SerialNumber::from(1u64));

    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::minutes(5); // small clock-skew buffer
    params.not_after = now + time::Duration::days(i64::from(validity_days));

    // 3. Dispatch on the CA's signing key. Each branch calls `params.signed_by`
    //    using rcgen's `Issuer` and our `CsrPublicKey` wrapper.
    let csr_pub = CsrPublicKey {
        raw: parsed.public_key_bit_string,
        alg: parsed.algorithm,
    };

    let (cert_der, cert_pem) = match &ca.signer {
        CaSignerInner::Ed25519(ca_key) => {
            sign_with_issuer(&params, &csr_pub, &ca.ca_params, ca_key)?
        }
        CaSignerInner::P256(ca_key) => sign_with_issuer(&params, &csr_pub, &ca.ca_params, ca_key)?,
        CaSignerInner::P384(ca_key) => sign_with_issuer(&params, &csr_pub, &ca.ca_params, ca_key)?,
        CaSignerInner::Rsa2048(ca_key) => {
            sign_with_issuer(&params, &csr_pub, &ca.ca_params, ca_key)?
        }
        CaSignerInner::Rsa4096(ca_key) => {
            sign_with_issuer(&params, &csr_pub, &ca.ca_params, ca_key)?
        }
    };

    Ok(SignedCertificate { cert_der, cert_pem })
}

fn sign_with_issuer<S: rcgen::SigningKey>(
    params: &CertificateParams,
    csr_pub: &CsrPublicKey,
    ca_params: &CertificateParams,
    ca_key: &S,
) -> Result<(Vec<u8>, String), TlsError> {
    let issuer = rcgen::Issuer::from_params(ca_params, ca_key);
    let cert = params
        .signed_by(csr_pub, &issuer)
        .map_err(|e| TlsError::InvalidConfig(format!("sign CSR: {e}")))?;
    Ok((cert.der().to_vec(), cert.pem()))
}

// ── Parsing helpers ──────────────────────────────────────────────────────────

/// Subset of CSR fields we need to construct a signed certificate. Owned
/// values only — the parser borrows from the input slice and must be dropped
/// before this struct is returned.
struct ParsedCsr {
    subject_dn: DistinguishedName,
    sans: Vec<SanType>,
    /// Raw BIT STRING contents of SubjectPublicKeyInfo — fed back into
    /// [`CsrPublicKey::der_bytes`] for re-signing.
    public_key_bit_string: Vec<u8>,
    /// Full SPKI DER (used to compute the Subject Key Identifier).
    spki_full: Vec<u8>,
    algorithm: &'static SignatureAlgorithm,
}

fn parse_csr_components(csr_der: &[u8]) -> Result<ParsedCsr, TlsError> {
    use x509_parser::der_parser::oid::Oid;
    use x509_parser::prelude::*;

    let (_rest, csr) = X509CertificationRequest::from_der(csr_der)
        .map_err(|e| TlsError::InvalidConfig(format!("parse CSR DER: {e:?}")))?;

    let info = &csr.certification_request_info;

    // Extract the algorithm OID and map to rcgen's static `SignatureAlgorithm`.
    let alg_oid: Vec<u64> = csr
        .signature_algorithm
        .algorithm
        .iter()
        .ok_or_else(|| TlsError::InvalidConfig("CSR signature algorithm OID is missing".into()))?
        .collect();
    let algorithm = signature_algorithm_from_oid(&alg_oid)?;

    // Subject DN.
    let subject_dn = dn_from_x509_name(&info.subject)?;

    // Subject Alternative Names — opportunistic, ignore parse errors so a CSR
    // without SAN attribute still produces a valid (DN-only) signed cert.
    let mut sans: Vec<SanType> = Vec::new();
    if let Ok(Some(req_exts)) = collect_requested_extensions(&csr) {
        for ext in req_exts {
            if let ParsedExtension::SubjectAlternativeName(san) = ext {
                for gn in &san.general_names {
                    if let Some(sty) = san_from_general_name(gn) {
                        sans.push(sty);
                    }
                }
            }
        }
    }

    // SubjectPublicKeyInfo: full SPKI DER + the BIT STRING contents.
    let public_key_bit_string = info.subject_pki.subject_public_key.data.to_vec();
    // Use yasna-equivalent: serialise the full SPKI by ourselves via the
    // parser's raw range. x509-parser stores `raw` on `SubjectPublicKeyInfo`.
    let spki_full = info.subject_pki.raw.to_vec();

    // x509-parser's OID type is borrowed; copy now and drop the parser.
    let _ = alg_oid;
    let _: Oid<'_> = csr.signature_algorithm.algorithm.clone();

    Ok(ParsedCsr {
        subject_dn,
        sans,
        public_key_bit_string,
        spki_full,
        algorithm,
    })
}

/// Convert an OID to the matching rcgen [`SignatureAlgorithm`] static.
fn signature_algorithm_from_oid(oid: &[u64]) -> Result<&'static SignatureAlgorithm, TlsError> {
    // RFC 8410 — Ed25519
    const ED25519: &[u64] = &[1, 3, 101, 112];
    // RFC 5758 — ECDSA-with-SHA256
    const ECDSA_SHA256: &[u64] = &[1, 2, 840, 10045, 4, 3, 2];
    // RFC 5758 — ECDSA-with-SHA384
    const ECDSA_SHA384: &[u64] = &[1, 2, 840, 10045, 4, 3, 3];
    // RFC 8017 — RSASSA-PKCS1-v1_5 with SHA-256
    const RSA_SHA256: &[u64] = &[1, 2, 840, 113549, 1, 1, 11];

    match oid {
        x if x == ED25519 => Ok(&PKCS_ED25519),
        x if x == ECDSA_SHA256 => Ok(&PKCS_ECDSA_P256_SHA256),
        x if x == ECDSA_SHA384 => Ok(&PKCS_ECDSA_P384_SHA384),
        x if x == RSA_SHA256 => Ok(&PKCS_RSA_SHA256),
        other => Err(TlsError::InvalidConfig(format!(
            "unsupported CSR signature algorithm OID: {other:?}"
        ))),
    }
}

/// Build an rcgen `DistinguishedName` from x509-parser's `X509Name`.
///
/// Only the well-known attribute types used by oxitls-rcgen are mapped; any
/// other RDN is preserved using `DnType::CustomDnType` and the raw OID.
fn dn_from_x509_name(
    name: &x509_parser::x509::X509Name<'_>,
) -> Result<DistinguishedName, TlsError> {
    let mut dn = DistinguishedName::new();
    for rdn in name.iter() {
        for attr in rdn.iter() {
            let raw_oid: Vec<u64> = attr
                .attr_type()
                .iter()
                .ok_or_else(|| TlsError::InvalidConfig("DN attribute OID missing".into()))?
                .collect();
            let dn_type = DnType::from_oid(&raw_oid);
            let value = attr
                .as_str()
                .map_err(|e| TlsError::InvalidConfig(format!("DN attribute value: {e}")))?
                .to_string();
            dn.push(dn_type, value);
        }
    }
    Ok(dn)
}

/// Collect requested extensions from a CSR, if the CSR carries the standard
/// PKCS #9 extensionRequest attribute. Returns `Ok(None)` if absent.
fn collect_requested_extensions<'a>(
    csr: &'a x509_parser::certification_request::X509CertificationRequest<'a>,
) -> Result<Option<Vec<x509_parser::extensions::ParsedExtension<'a>>>, TlsError> {
    match csr.requested_extensions() {
        Some(iter) => Ok(Some(iter.cloned().collect())),
        None => Ok(None),
    }
}

fn san_from_general_name(gn: &x509_parser::extensions::GeneralName<'_>) -> Option<SanType> {
    use x509_parser::extensions::GeneralName;
    match gn {
        GeneralName::DNSName(s) => (*s).to_string().try_into().ok().map(SanType::DnsName),
        GeneralName::RFC822Name(s) => (*s).to_string().try_into().ok().map(SanType::Rfc822Name),
        GeneralName::URI(s) => (*s).to_string().try_into().ok().map(SanType::URI),
        GeneralName::IPAddress(octets) => parse_ip_octets(octets).map(SanType::IpAddress),
        // OtherName / DirectoryName / etc. are intentionally dropped — they don't
        // round-trip through rcgen's SAN API cleanly and are rare in practice.
        _ => None,
    }
}

fn parse_ip_octets(octets: &[u8]) -> Option<std::net::IpAddr> {
    if let Ok(arr) = <&[u8; 4]>::try_from(octets) {
        Some(std::net::IpAddr::V4(std::net::Ipv4Addr::from(*arr)))
    } else if let Ok(arr) = <&[u8; 16]>::try_from(octets) {
        Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(*arr)))
    } else {
        None
    }
}

// ── PublicKeyData adapter for a parsed CSR's subject public key ──────────────

/// A read-only [`PublicKeyData`] view of the SubjectPublicKeyInfo BIT STRING
/// extracted from a parsed CSR. Used to drive rcgen's `signed_by` without
/// needing the CSR subject's private key (the CA never has it).
struct CsrPublicKey {
    raw: Vec<u8>,
    alg: &'static SignatureAlgorithm,
}

impl PublicKeyData for CsrPublicKey {
    fn der_bytes(&self) -> &[u8] {
        &self.raw
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        self.alg
    }
}
