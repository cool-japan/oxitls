//! High-level certificate generation helpers built on top of the keypair bridge.
//!
//! The main entry points are:
//! - [`generate_self_signed_ed25519`] / [`generate_self_signed_p256`] / [`generate_self_signed_p384`]
//!   / [`generate_self_signed_rsa2048`] / [`generate_self_signed_rsa4096`] for leaf certs
//! - [`generate_ca`] for root CA certificates
//! - [`generate_intermediate_ca`] for intermediate CA certificates
//! - [`CertChainBuilder`] for assembling full certificate chains
//! - [`CertificateParamsBuilder`] for fluent parameter construction

use rcgen::{
    BasicConstraints, CertificateParams, CrlDistributionPoint, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, GeneralSubtree, IsCa, KeyIdMethod, KeyUsagePurpose, NameConstraints,
    SanType, SerialNumber,
};

// ── AKI DER-encoding helpers ─────────────────────────────────────────────────

/// Encodes a DER length (BER definite short/long form for lens up to 65535).
fn encode_der_length(buf: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        buf.push(len as u8);
    } else if len <= 0xFF {
        buf.push(0x81);
        buf.push(len as u8);
    } else {
        // len <= 0xFFFF; key IDs are 20-32 bytes so this is unreachable in
        // practice, but included for correctness.
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    }
}

/// DER-encodes `AuthorityKeyIdentifier ::= SEQUENCE { keyIdentifier [0] IMPLICIT OCTET STRING }`.
///
/// RFC 5280 §4.2.1.1 defines the [0] IMPLICIT tag as 0x80 (context-class, primitive, tag=0).
fn encode_authority_key_identifier(key_id: &[u8]) -> Vec<u8> {
    // [0] IMPLICIT OCTET STRING for keyIdentifier
    let mut content = Vec::with_capacity(2 + key_id.len());
    content.push(0x80u8); // tag [0] IMPLICIT
    encode_der_length(&mut content, key_id.len());
    content.extend_from_slice(key_id);

    // Wrap in SEQUENCE (0x30)
    let mut result = Vec::with_capacity(2 + content.len());
    result.push(0x30u8); // SEQUENCE
    encode_der_length(&mut result, content.len());
    result.extend_from_slice(&content);
    result
}
// ── AIA DER-encoding helpers ─────────────────────────────────────────────────

/// Wraps `content` in a DER TLV with the given `tag`.
fn encode_tagged(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(2 + content.len());
    buf.push(tag);
    encode_der_length(&mut buf, content.len());
    buf.extend_from_slice(content);
    buf
}

/// Wraps a concatenated blob of DER TLV items in a DER SEQUENCE (0x30).
fn encode_sequence(items: &[&[u8]]) -> Vec<u8> {
    let total: usize = items.iter().map(|i| i.len()).sum();
    let mut inner = Vec::with_capacity(total);
    for item in items {
        inner.extend_from_slice(item);
    }
    encode_tagged(0x30, &inner)
}

/// DER-encodes the AIA extension value for a single OCSP responder URL.
///
/// Produces:
/// ```text
/// SEQUENCE {
///   SEQUENCE {
///     OID 1.3.6.1.5.5.7.48.1   -- id-ad-ocsp
///     [6] IMPLICIT IA5String    -- uniformResourceIdentifier
///   }
/// }
/// ```
fn encode_aia_ocsp(url: &str) -> Vec<u8> {
    let url_bytes = url.as_bytes();
    // OID 1.3.6.1.5.5.7.48.1 encoded as DER OID TLV.
    let oid_tlv: &[u8] = &[0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01];
    // [6] IMPLICIT IA5String for uniformResourceIdentifier.
    let uri_tlv = encode_tagged(0x86, url_bytes);
    // SEQUENCE { oid, uri }
    let inner_seq = encode_sequence(&[oid_tlv, &uri_tlv]);
    // Outer SEQUENCE { inner_seq }
    encode_sequence(&[&inner_seq])
}

use sha2::{Digest, Sha256};

use oxitls_core::TlsError;

use crate::keypair::{
    OxiEcdsaP256Key, OxiEcdsaP384Key, OxiEd25519Key, OxiRsa2048Key, OxiRsa4096Key,
};

// ── Public result types ──────────────────────────────────────────────────────

/// A self-signed or CA-signed certificate together with its signing key.
///
/// The `pkcs8_der` field contains the private key in PKCS#8 DER format, which
/// can be passed directly to rustls:
///
/// ```no_run
/// use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let certified_key = oxitls_rcgen::generate_self_signed_ed25519(&["localhost"])?;
/// let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
///     certified_key.pkcs8_der.clone(),
/// ));
/// # Ok(())
/// # }
/// ```
pub struct CertifiedKey {
    /// DER-encoded X.509 certificate.
    pub cert_der: Vec<u8>,
    /// PKCS#8 DER-encoded private key.
    pub pkcs8_der: Vec<u8>,
    /// PEM-encoded certificate.
    pub cert_pem: String,
}

impl CertifiedKey {
    /// Compute the SHA-256 fingerprint of the DER-encoded certificate.
    ///
    /// This is the same fingerprint shown by `openssl x509 -fingerprint -sha256`.
    pub fn fingerprint_sha256(&self) -> [u8; 32] {
        let digest = Sha256::digest(&self.cert_der);
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }

    /// Return the private key in PEM format (PKCS#8).
    ///
    /// The PEM block uses the `PRIVATE KEY` header (PKCS#8 encoding).
    pub fn key_pem(&self) -> String {
        use std::fmt::Write;
        let encoded = base64_encode(&self.pkcs8_der);
        let mut pem = String::new();
        let _ = writeln!(pem, "-----BEGIN PRIVATE KEY-----");
        for chunk in encoded.as_bytes().chunks(64) {
            let _ = writeln!(pem, "{}", std::str::from_utf8(chunk).unwrap_or(""));
        }
        let _ = write!(pem, "-----END PRIVATE KEY-----");
        pem
    }

    /// Parse the `notAfter` validity timestamp from the DER certificate.
    ///
    /// Returns `None` if the certificate cannot be parsed or if the timestamp
    /// format is not recognised.
    pub fn not_after(&self) -> Option<::time::OffsetDateTime> {
        use x509_parser::prelude::*;
        let (_, parsed) = X509Certificate::from_der(&self.cert_der).ok()?;
        let ts = parsed.validity().not_after;
        let epoch: i64 = ts.timestamp();
        ::time::OffsetDateTime::from_unix_timestamp(epoch).ok()
    }

    /// Export this certificate and private key as a PKCS#12 (PFX) archive.
    ///
    /// Uses the `p12` crate (pure Rust, no OpenSSL). The `password` is used to
    /// encrypt the key bag and authenticate the MAC. `friendly_name` is stored
    /// as the `localKeyID` attribute.
    ///
    /// # Errors
    /// Returns [`TlsError`] if key or cert DER encoding fails.
    pub fn to_pkcs12(&self, password: &str, friendly_name: &str) -> Result<Vec<u8>, TlsError> {
        let pfx = p12::PFX::new(
            &self.cert_der,
            &self.pkcs8_der,
            None, // no CA certs
            password,
            friendly_name,
        )
        .ok_or_else(|| TlsError::InvalidConfig("PKCS#12 construction failed".into()))?;
        Ok(pfx.to_der())
    }

    /// Convert to rustls pki-types for direct use with a `rustls::ClientConfig`
    /// or `rustls::ServerConfig`.
    ///
    /// Returns the certificate chain (leaf only, DER bytes) and the private key
    /// as a `PrivateKeyDer<'static>` encoded as PKCS#8 (rcgen always produces
    /// PKCS#8-wrapped keys).
    ///
    /// Unlike [`to_rustls_certified_key`][Self::to_rustls_certified_key], this
    /// method is infallible and does not require a `CryptoProvider`. Use it when
    /// you want to manage key loading yourself or pass the types to lower-level
    /// rustls configuration APIs.
    pub fn to_rustls_cert_and_key(
        &self,
    ) -> (
        Vec<rustls_pki_types::CertificateDer<'static>>,
        rustls_pki_types::PrivateKeyDer<'static>,
    ) {
        let cert_der = rustls_pki_types::CertificateDer::from(self.cert_der.clone());
        let key_der = rustls_pki_types::PrivateKeyDer::Pkcs8(
            rustls_pki_types::PrivatePkcs8KeyDer::from(self.pkcs8_der.clone()),
        );
        (vec![cert_der], key_der)
    }

    /// Convert to a `rustls::sign::CertifiedKey` for direct use with rustls
    /// server configurations.
    ///
    /// This creates a new rustls `CertifiedKey` by loading the private key
    /// through the Pure-Rust crypto provider.
    ///
    /// # Errors
    /// Returns [`TlsError`] if the key cannot be loaded by the provider.
    pub fn to_rustls_certified_key(&self) -> Result<rustls::sign::CertifiedKey, TlsError> {
        let provider = oxitls_adapter_rustls_rustcrypto::pure_provider();
        let key_der = rustls_pki_types::PrivateKeyDer::Pkcs8(
            rustls_pki_types::PrivatePkcs8KeyDer::from(self.pkcs8_der.clone()),
        );
        let signing_key = provider
            .key_provider
            .load_private_key(key_der)
            .map_err(|e| TlsError::InvalidConfig(format!("failed to load key: {e}")))?;

        let cert_der = rustls_pki_types::CertificateDer::from(self.cert_der.clone());

        Ok(rustls::sign::CertifiedKey::new(vec![cert_der], signing_key))
    }
}

impl std::fmt::Display for CertifiedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Subject: extract from DER via x509-parser
        let subject = {
            use x509_parser::prelude::*;
            X509Certificate::from_der(&self.cert_der)
                .ok()
                .map(|(_, c)| c.subject().to_string())
                .unwrap_or_else(|| "<unparseable>".to_string())
        };
        // Algorithm: extract from DER
        let algorithm = {
            use x509_parser::prelude::*;
            X509Certificate::from_der(&self.cert_der)
                .ok()
                .map(|(_, c)| c.signature_algorithm.algorithm.to_id_string())
                .unwrap_or_else(|| "<unknown>".to_string())
        };
        // SHA-256: hex-encoded fingerprint
        let fp = self.fingerprint_sha256();
        let fp_hex: String = fp
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":");
        // Not after: formatted or fallback
        let not_after_val = self
            .not_after()
            .map(|t| {
                let fmt = ::time::format_description::well_known::Rfc3339;
                t.format(&fmt).unwrap_or_else(|_| t.to_string())
            })
            .unwrap_or_else(|| "<unparseable>".to_string());

        write!(
            f,
            "Subject: {subject}\nAlgorithm: {algorithm}\nSHA-256: {fp_hex}\nNot after: {not_after_val}"
        )
    }
}

/// A CA certificate that can sign child certificates.
///
/// Wraps an rcgen `CertifiedIssuer` with the key material needed for
/// rustls, DER/PEM export, and fingerprint computation.
///
/// Distinguished from [`CertifiedKey`] at the type level to prevent
/// accidentally using a leaf certificate as a CA.
pub struct CaCertifiedKey {
    /// The CA certificate data (DER, PEM, PKCS#8 key).
    pub certified_key: CertifiedKey,
    /// Inner rcgen issuer for signing child certs.
    /// Stored as an opaque type-erased box because we support multiple key
    /// types (Ed25519, P-256) and the `CertifiedIssuer<'_, S>` type is
    /// parameterized over `S: SigningKey`.
    ///
    /// We store the params + key separately so we can reconstruct an `Issuer`
    /// on demand, avoiding lifetime issues with self-referential structs.
    pub(crate) ca_params: CertificateParams,
    /// The signing key as a trait object. We need to be able to call
    /// `signed_by` with it later.
    pub(crate) signer: CaSignerInner,
}

/// Internal enum that stores the concrete signing key so we can call rcgen's
/// `signed_by` with a concrete type (avoiding object-safety issues).
pub(crate) enum CaSignerInner {
    Ed25519(OxiEd25519Key),
    P256(OxiEcdsaP256Key),
    P384(OxiEcdsaP384Key),
    Rsa2048(OxiRsa2048Key),
    Rsa4096(OxiRsa4096Key),
}

impl CaCertifiedKey {
    /// Access the underlying [`CertifiedKey`] for DER/PEM/fingerprint access.
    pub fn as_certified_key(&self) -> &CertifiedKey {
        &self.certified_key
    }

    /// Sign a child certificate using the CA's signer and the given child key.
    ///
    /// This is a generic helper that works with any child key implementing
    /// `rcgen::SigningKey + rcgen::PublicKeyData`.
    pub(crate) fn sign_child<K>(
        &self,
        child_params: CertificateParams,
        child_key: &K,
    ) -> Result<(Vec<u8>, String), TlsError>
    where
        K: rcgen::SigningKey + rcgen::PublicKeyData,
    {
        macro_rules! sign_with {
            ($ca_key:expr) => {{
                let issuer = rcgen::Issuer::from_params(&self.ca_params, $ca_key);
                let cert = child_params
                    .signed_by(child_key, &issuer)
                    .map_err(|e| TlsError::InvalidConfig(e.to_string()))?;
                Ok((cert.der().to_vec(), cert.pem()))
            }};
        }
        match &self.signer {
            CaSignerInner::Ed25519(k) => sign_with!(k),
            CaSignerInner::P256(k) => sign_with!(k),
            CaSignerInner::P384(k) => sign_with!(k),
            CaSignerInner::Rsa2048(k) => sign_with!(k),
            CaSignerInner::Rsa4096(k) => sign_with!(k),
        }
    }
}

// ── Algorithm selector ────────────────────────────────────────────────────────

/// Signing algorithm selector for certificate generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningAlgorithm {
    /// Ed25519 (RFC 8410)
    Ed25519,
    /// ECDSA with NIST P-256 and SHA-256 (RFC 5758)
    EcdsaP256,
    /// ECDSA with NIST P-384 and SHA-384 (RFC 5758)
    EcdsaP384,
    /// RSA PKCS#1 v1.5 with SHA-256, 2048-bit modulus
    Rsa2048,
    /// RSA PKCS#1 v1.5 with SHA-256, 4096-bit modulus
    Rsa4096,
}

// ── CertificateParamsBuilder ─────────────────────────────────────────────────

/// Fluent builder for [`rcgen::CertificateParams`].
///
/// Provides a convenient API for constructing certificate parameters with
/// sensible defaults, without requiring knowledge of rcgen internals.
///
/// # Example
/// ```no_run
/// use oxitls_rcgen::CertificateParamsBuilder;
///
/// let params = CertificateParamsBuilder::new()
///     .with_common_name("My Server")
///     .with_dns_names(&["example.com", "*.example.com"])
///     .with_ip_addresses(&["192.168.1.1"])
///     .with_server_auth()
///     .build()
///     .expect("valid params");
/// ```
pub struct CertificateParamsBuilder {
    common_name: Option<String>,
    dns_names: Vec<String>,
    ip_addresses: Vec<std::net::IpAddr>,
    is_ca: IsCa,
    key_usages: Vec<KeyUsagePurpose>,
    extended_key_usages: Vec<ExtendedKeyUsagePurpose>,
    serial_number: Option<u64>,
    /// Optional explicit validity period.
    not_before: Option<::time::OffsetDateTime>,
    not_after: Option<::time::OffsetDateTime>,
    /// Optional name constraints (permitted/excluded subtrees).
    name_constraints: Option<NameConstraints>,
    /// Override SKI with explicit bytes instead of SHA-256(SPKI).
    subject_key_id: Option<Vec<u8>>,
    /// Embed an explicit AKI extension with these bytes as keyIdentifier.
    /// Takes precedence over `enable_aki_from_issuer` when both are set.
    authority_key_id: Option<Vec<u8>>,
    /// When true, emit the standard AKI extension derived from the issuer's SKI.
    enable_aki_from_issuer: bool,
    /// CRL Distribution Points URIs (OID 2.5.29.31).
    crl_distribution_points: Vec<String>,
    /// OCSP responder URL for the Authority Information Access extension
    /// (OID 1.3.6.1.5.5.7.1.1).
    ocsp_responder_url: Option<String>,
}

impl CertificateParamsBuilder {
    /// Create a new builder with empty parameters.
    pub fn new() -> Self {
        Self {
            common_name: None,
            dns_names: Vec::new(),
            ip_addresses: Vec::new(),
            is_ca: IsCa::NoCa,
            key_usages: Vec::new(),
            extended_key_usages: Vec::new(),
            serial_number: None,
            not_before: None,
            not_after: None,
            name_constraints: None,
            subject_key_id: None,
            authority_key_id: None,
            enable_aki_from_issuer: false,
            crl_distribution_points: Vec::new(),
            ocsp_responder_url: None,
        }
    }

    /// Set the Common Name (CN) of the subject.
    pub fn with_common_name(mut self, cn: impl Into<String>) -> Self {
        self.common_name = Some(cn.into());
        self
    }

    /// Add DNS names as Subject Alternative Names.
    pub fn with_dns_names(mut self, names: &[&str]) -> Self {
        self.dns_names.extend(names.iter().map(|s| s.to_string()));
        self
    }

    /// Add IP addresses as Subject Alternative Names.
    pub fn with_ip_addresses(mut self, addrs: &[&str]) -> Self {
        for addr in addrs {
            if let Ok(ip) = addr.parse::<std::net::IpAddr>() {
                self.ip_addresses.push(ip);
            }
        }
        self
    }

    /// Mark this certificate as a CA with unconstrained path length.
    pub fn with_ca(mut self) -> Self {
        self.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        self
    }

    /// Mark this certificate as a CA with a specific path length constraint.
    pub fn with_ca_path_length(mut self, path_len: u8) -> Self {
        self.is_ca = IsCa::Ca(BasicConstraints::Constrained(path_len));
        self
    }

    /// Add the `ServerAuth` extended key usage.
    pub fn with_server_auth(mut self) -> Self {
        self.extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);
        self
    }

    /// Add the `ClientAuth` extended key usage.
    pub fn with_client_auth(mut self) -> Self {
        self.extended_key_usages
            .push(ExtendedKeyUsagePurpose::ClientAuth);
        self
    }

    /// Add the `DigitalSignature` key usage.
    pub fn with_digital_signature(mut self) -> Self {
        self.key_usages.push(KeyUsagePurpose::DigitalSignature);
        self
    }

    /// Add the `KeyCertSign` key usage (required for CA certificates).
    pub fn with_key_cert_sign(mut self) -> Self {
        self.key_usages.push(KeyUsagePurpose::KeyCertSign);
        self
    }

    /// Add the `CrlSign` key usage.
    pub fn with_crl_sign(mut self) -> Self {
        self.key_usages.push(KeyUsagePurpose::CrlSign);
        self
    }

    /// Set all key usages at once, replacing any previously-set individual flags.
    ///
    /// This overwrites the key usage list set by individual calls such as
    /// [`with_digital_signature`][Self::with_digital_signature].
    pub fn with_key_usages(mut self, usages: Vec<KeyUsagePurpose>) -> Self {
        self.key_usages = usages;
        self
    }

    /// Set a specific serial number for the certificate.
    pub fn with_serial_number(mut self, serial: u64) -> Self {
        self.serial_number = Some(serial);
        self
    }

    /// Set an explicit validity period for the certificate.
    ///
    /// By default rcgen uses its own defaults. Providing explicit values is
    /// required for tests that check `not_after()` round-trip accuracy or that
    /// need to generate expired certificates.
    pub fn with_validity(
        mut self,
        not_before: ::time::OffsetDateTime,
        not_after: ::time::OffsetDateTime,
    ) -> Self {
        self.not_before = Some(not_before);
        self.not_after = Some(not_after);
        self
    }

    /// Add name constraints (permitted and excluded subtrees) to the certificate.
    ///
    /// This sets the `NameConstraints` extension (OID 2.5.29.30) on the
    /// certificate, which is only meaningful on CA certificates. The
    /// `permitted` list restricts which names the CA may issue for; `excluded`
    /// prohibits specific name forms even within the permitted subtrees.
    ///
    /// # Example
    /// ```no_run
    /// use oxitls_rcgen::CertificateParamsBuilder;
    /// use rcgen::GeneralSubtree;
    ///
    /// let params = CertificateParamsBuilder::new()
    ///     .with_ca()
    ///     .with_name_constraints(
    ///         vec![GeneralSubtree::DnsName("example.com".to_string())],
    ///         vec![],
    ///     )
    ///     .build()
    ///     .expect("valid CA params");
    /// ```
    pub fn with_name_constraints(
        mut self,
        permitted: Vec<GeneralSubtree>,
        excluded: Vec<GeneralSubtree>,
    ) -> Self {
        self.name_constraints = Some(NameConstraints {
            permitted_subtrees: permitted,
            excluded_subtrees: excluded,
        });
        self
    }

    /// Override the Subject Key Identifier with explicit bytes instead of the
    /// default SHA-256(SPKI) derivation.
    ///
    /// When not called the builder uses `SHA-256(subjectPublicKeyInfo)` as the
    /// SKI, which is the pre-existing behaviour (backward-compatible default).
    pub fn with_subject_key_id(mut self, bytes: Vec<u8>) -> Self {
        self.subject_key_id = Some(bytes);
        self
    }

    /// Embed an explicit Authority Key Identifier extension with `bytes` as the
    /// `keyIdentifier` field.
    ///
    /// The extension is DER-encoded as
    /// `AuthorityKeyIdentifier ::= SEQUENCE { keyIdentifier [0] IMPLICIT OCTET STRING }`.
    ///
    /// If both `with_authority_key_id` and `with_authority_key_id_from_issuer`
    /// are called, the explicit bytes take precedence and the rcgen issuer-derived
    /// AKI is **not** enabled.
    pub fn with_authority_key_id(mut self, bytes: Vec<u8>) -> Self {
        self.authority_key_id = Some(bytes);
        self
    }

    /// Enable the standard AKI extension derived from the issuer's
    /// `key_identifier_method` (i.e. the issuer's SKI value).
    ///
    /// Sets `CertificateParams::use_authority_key_identifier_extension = true`.
    /// When `with_authority_key_id` is also set it wins and this flag is
    /// ignored.
    pub fn with_authority_key_id_from_issuer(mut self) -> Self {
        self.enable_aki_from_issuer = true;
        self
    }

    /// Add a CRL Distribution Point URI (OID 2.5.29.31).
    ///
    /// Each call appends one URI to the distribution points list. Multiple
    /// URIs are encoded as separate `DistributionPoint` entries inside the
    /// `cRLDistributionPoints` extension.
    ///
    /// # Example
    /// ```no_run
    /// use oxitls_rcgen::CertificateParamsBuilder;
    ///
    /// let params = CertificateParamsBuilder::new()
    ///     .with_ca()
    ///     .with_crl_distribution_point("http://crl.example.com/root.crl")
    ///     .build()
    ///     .expect("valid params");
    /// ```
    pub fn with_crl_distribution_point(mut self, uri: impl Into<String>) -> Self {
        self.crl_distribution_points.push(uri.into());
        self
    }

    /// Set the OCSP responder URL for the Authority Information Access
    /// extension (OID 1.3.6.1.5.5.7.1.1).
    ///
    /// Encodes the URL as a `uniformResourceIdentifier` (`[6] IA5String`)
    /// under access method `id-ad-ocsp` (1.3.6.1.5.5.7.48.1).
    ///
    /// # Example
    /// ```no_run
    /// use oxitls_rcgen::CertificateParamsBuilder;
    ///
    /// let params = CertificateParamsBuilder::new()
    ///     .with_dns_names(&["example.com"])
    ///     .with_server_auth()
    ///     .with_ocsp_responder_url("http://ocsp.example.com")
    ///     .build()
    ///     .expect("valid params");
    /// ```
    pub fn with_ocsp_responder_url(mut self, url: impl Into<String>) -> Self {
        self.ocsp_responder_url = Some(url.into());
        self
    }

    /// Add the `CodeSigning` extended key usage (OID 1.3.6.1.5.5.7.3.3).
    pub fn with_code_signing(mut self) -> Self {
        self.extended_key_usages
            .push(ExtendedKeyUsagePurpose::CodeSigning);
        self
    }

    /// Add the `EmailProtection` extended key usage (OID 1.3.6.1.5.5.7.3.4).
    pub fn with_email_protection(mut self) -> Self {
        self.extended_key_usages
            .push(ExtendedKeyUsagePurpose::EmailProtection);
        self
    }

    /// Add the `OcspSigning` extended key usage (OID 1.3.6.1.5.5.7.3.9).
    pub fn with_ocsp_signing(mut self) -> Self {
        self.extended_key_usages
            .push(ExtendedKeyUsagePurpose::OcspSigning);
        self
    }

    /// Set all extended key usages at once, replacing any previously-set flags.
    ///
    /// This overwrites the extended key usage list set by individual calls such as
    /// [`with_server_auth`][Self::with_server_auth].
    pub fn with_extended_key_usages(mut self, usages: Vec<ExtendedKeyUsagePurpose>) -> Self {
        self.extended_key_usages = usages;
        self
    }

    /// Build the [`rcgen::CertificateParams`].
    ///
    /// Uses the provided SPKI bytes for computing the Subject Key Identifier.
    ///
    /// # Errors
    /// Returns [`TlsError`] if no SANs are configured for a non-CA certificate.
    pub fn build_with_spki(self, spki_for_kid: &[u8]) -> Result<CertificateParams, TlsError> {
        // Build SANs.
        let mut sans: Vec<SanType> = Vec::new();
        for name in &self.dns_names {
            let san: SanType = name
                .to_string()
                .try_into()
                .map(SanType::DnsName)
                .map_err(|e: rcgen::Error| TlsError::InvalidConfig(e.to_string()))?;
            sans.push(san);
        }
        for ip in &self.ip_addresses {
            sans.push(SanType::IpAddress(*ip));
        }

        // Non-CA certs need at least one SAN.
        if sans.is_empty() && !matches!(self.is_ca, IsCa::Ca(_)) {
            return Err(TlsError::InvalidConfig(
                "at least one SAN is required for leaf certificates".into(),
            ));
        }

        // Compute key identifier (SHA-256 of SPKI by default; overrideable).
        let default_kid: Vec<u8> = Sha256::digest(spki_for_kid).to_vec();
        let ski = self.subject_key_id.unwrap_or(default_kid);

        // Build distinguished name.
        let mut dn = DistinguishedName::new();
        if let Some(cn) = &self.common_name {
            dn.push(DnType::CommonName, cn.as_str());
        } else if let Some(first_dns) = self.dns_names.first() {
            dn.push(DnType::CommonName, first_dns.as_str());
        }

        let mut params = CertificateParams::default();
        params.subject_alt_names = sans;
        params.distinguished_name = dn;
        params.is_ca = self.is_ca;
        params.key_identifier_method = KeyIdMethod::PreSpecified(ski);

        if !self.key_usages.is_empty() {
            params.key_usages = self.key_usages;
        }
        if !self.extended_key_usages.is_empty() {
            params.extended_key_usages = self.extended_key_usages;
        }

        // rcgen 0.14 requires an explicit serial number.
        params.serial_number = Some(rcgen::SerialNumber::from(
            self.serial_number.unwrap_or(1u64),
        ));

        // Apply explicit validity period if set.
        if let Some(nb) = self.not_before {
            params.not_before = nb;
        }
        if let Some(na) = self.not_after {
            params.not_after = na;
        }

        // Apply name constraints if set.
        if let Some(nc) = self.name_constraints {
            params.name_constraints = Some(nc);
        }

        // AKI: explicit bytes take precedence over from-issuer flag.
        if let Some(aki_bytes) = &self.authority_key_id {
            let aki_der = encode_authority_key_identifier(aki_bytes);
            let custom_ext = rcgen::CustomExtension::from_oid_content(&[2, 5, 29, 35], aki_der);
            params.custom_extensions.push(custom_ext);
        } else if self.enable_aki_from_issuer {
            params.use_authority_key_identifier_extension = true;
        }

        // CRL Distribution Points (OID 2.5.29.31): use rcgen's native field.
        if !self.crl_distribution_points.is_empty() {
            params.crl_distribution_points = self
                .crl_distribution_points
                .iter()
                .map(|uri| CrlDistributionPoint {
                    uris: vec![uri.clone()],
                })
                .collect();
        }

        // Authority Information Access (OID 1.3.6.1.5.5.7.1.1): hand-rolled DER.
        if let Some(url) = &self.ocsp_responder_url {
            let ext_der = encode_aia_ocsp(url);
            let ext =
                rcgen::CustomExtension::from_oid_content(&[1, 3, 6, 1, 5, 5, 7, 1, 1], ext_der);
            params.custom_extensions.push(ext);
        }

        Ok(params)
    }

    /// Convenience: build with no SPKI (key identifier will be based on empty input).
    ///
    /// Prefer [`build_with_spki`](Self::build_with_spki) when you have the key.
    pub fn build(self) -> Result<CertificateParams, TlsError> {
        self.build_with_spki(&[])
    }
}

impl Default for CertificateParamsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ── CertChainBuilder ─────────────────────────────────────────────────────────

/// Builder for assembling a certificate chain (leaf + intermediates + root).
///
/// The chain is ordered leaf-first, followed by intermediate CAs, then the
/// root. This is the order expected by rustls and most TLS implementations.
///
/// # Example
/// ```no_run
/// use oxitls_rcgen::CertChainBuilder;
///
/// # fn example() -> Result<(), oxitls_core::TlsError> {
/// # let leaf_der: Vec<u8> = vec![];
/// # let intermediate_der: Vec<u8> = vec![];
/// # let root_der: Vec<u8> = vec![];
/// let chain = CertChainBuilder::new()
///     .with_leaf(leaf_der)
///     .with_intermediate(intermediate_der)
///     .with_root(root_der)
///     .build();
///
/// assert_eq!(chain.len(), 3);
/// # Ok(())
/// # }
/// ```
pub struct CertChainBuilder {
    leaf: Option<Vec<u8>>,
    intermediates: Vec<Vec<u8>>,
    root: Option<Vec<u8>>,
}

impl CertChainBuilder {
    /// Create a new empty chain builder.
    pub fn new() -> Self {
        Self {
            leaf: None,
            intermediates: Vec::new(),
            root: None,
        }
    }

    /// Set the leaf (end-entity) certificate DER.
    pub fn with_leaf(mut self, cert_der: Vec<u8>) -> Self {
        self.leaf = Some(cert_der);
        self
    }

    /// Add an intermediate CA certificate DER.
    ///
    /// Intermediates are ordered from closest to the leaf to closest to the root.
    pub fn with_intermediate(mut self, cert_der: Vec<u8>) -> Self {
        self.intermediates.push(cert_der);
        self
    }

    /// Set the root CA certificate DER.
    pub fn with_root(mut self, cert_der: Vec<u8>) -> Self {
        self.root = Some(cert_der);
        self
    }

    /// Build the certificate chain as a Vec of DER-encoded certificates.
    ///
    /// Order: leaf, intermediates (in order added), root.
    pub fn build(self) -> Vec<Vec<u8>> {
        let mut chain = Vec::new();
        if let Some(leaf) = self.leaf {
            chain.push(leaf);
        }
        chain.extend(self.intermediates);
        if let Some(root) = self.root {
            chain.push(root);
        }
        chain
    }

    /// Build the chain as `rustls_pki_types::CertificateDer` values.
    pub fn build_rustls(&self) -> Vec<rustls_pki_types::CertificateDer<'static>> {
        let mut chain = Vec::new();
        if let Some(leaf) = &self.leaf {
            chain.push(rustls_pki_types::CertificateDer::from(leaf.clone()));
        }
        for intermediate in &self.intermediates {
            chain.push(rustls_pki_types::CertificateDer::from(intermediate.clone()));
        }
        if let Some(root) = &self.root {
            chain.push(rustls_pki_types::CertificateDer::from(root.clone()));
        }
        chain
    }
}

impl Default for CertChainBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ── Internal helpers ─────────────────────────────────────────────────────────

/// Simple base64 encoder (no external dependencies).
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        result.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        result.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(ALPHABET[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(ALPHABET[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

/// Build a `CertificateParams` suitable for a server TLS certificate.
fn build_params(
    subject_alt_names: &[&str],
    spki_for_kid: &[u8],
) -> Result<CertificateParams, TlsError> {
    let sans: Vec<SanType> = subject_alt_names
        .iter()
        .map(|s| match s.parse::<std::net::IpAddr>() {
            Ok(ip) => Ok(SanType::IpAddress(ip)),
            Err(_) => s
                .to_string()
                .try_into()
                .map(SanType::DnsName)
                .map_err(|e: rcgen::Error| TlsError::InvalidConfig(e.to_string())),
        })
        .collect::<Result<_, _>>()?;

    if sans.is_empty() {
        return Err(TlsError::InvalidConfig(
            "at least one SAN is required".into(),
        ));
    }

    let kid: Vec<u8> = Sha256::digest(spki_for_kid).to_vec();

    let mut dn = DistinguishedName::new();
    let cn = subject_alt_names.first().copied().unwrap_or("localhost");
    dn.push(DnType::CommonName, cn);

    let mut params = CertificateParams::default();
    params.subject_alt_names = sans;
    params.distinguished_name = dn;
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.key_identifier_method = KeyIdMethod::PreSpecified(kid);
    // rcgen 0.14 requires an explicit serial number.
    params.serial_number = Some(SerialNumber::from(1u64));

    Ok(params)
}

/// Build leaf **client** certificate params (ClientAuth EKU, no CA).
fn build_client_params(
    subject_alt_names: &[&str],
    spki_for_kid: &[u8],
) -> Result<CertificateParams, TlsError> {
    let sans: Vec<SanType> = subject_alt_names
        .iter()
        .map(|s| match s.parse::<std::net::IpAddr>() {
            Ok(ip) => Ok(SanType::IpAddress(ip)),
            Err(_) => s
                .to_string()
                .try_into()
                .map(SanType::DnsName)
                .map_err(|e: rcgen::Error| TlsError::InvalidConfig(e.to_string())),
        })
        .collect::<Result<_, _>>()?;

    if sans.is_empty() {
        return Err(TlsError::InvalidConfig(
            "at least one SAN is required".into(),
        ));
    }

    let kid: Vec<u8> = Sha256::digest(spki_for_kid).to_vec();

    let mut dn = DistinguishedName::new();
    let cn = subject_alt_names.first().copied().unwrap_or("client");
    dn.push(DnType::CommonName, cn);

    let mut params = CertificateParams::default();
    params.subject_alt_names = sans;
    params.distinguished_name = dn;
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    // ClientAuth EKU is required for WebPkiClientVerifier acceptance.
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    params.key_identifier_method = KeyIdMethod::PreSpecified(kid);
    // rcgen 0.14 requires an explicit serial number.
    params.serial_number = Some(SerialNumber::from(2u64));

    Ok(params)
}

/// Build CA certificate params.
fn build_ca_params(
    subject_cn: &str,
    spki_for_kid: &[u8],
    path_length: Option<u8>,
) -> CertificateParams {
    let kid: Vec<u8> = Sha256::digest(spki_for_kid).to_vec();

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, subject_cn);

    let mut params = CertificateParams::default();
    params.distinguished_name = dn;
    params.is_ca = match path_length {
        Some(len) => IsCa::Ca(BasicConstraints::Constrained(len)),
        None => IsCa::Ca(BasicConstraints::Unconstrained),
    };
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params.key_identifier_method = KeyIdMethod::PreSpecified(kid);
    // rcgen 0.14 requires an explicit serial number.
    params.serial_number = Some(SerialNumber::from(1u64));

    params
}

// ── Public API: Self-signed leaf certs ───────────────────────────────────────

/// Generate a self-signed TLS certificate using an Ed25519 key pair.
///
/// # Arguments
/// * `subject_alt_names` — one or more DNS names or IP addresses; the first
///   entry is also used as the certificate's Common Name.
///
/// # Errors
/// Returns [`TlsError`] on key generation or certificate serialization failure.
pub fn generate_self_signed_ed25519(subject_alt_names: &[&str]) -> Result<CertifiedKey, TlsError> {
    let key = OxiEd25519Key::generate()?;
    let spki = rcgen::PublicKeyData::subject_public_key_info(&key);
    let params = build_params(subject_alt_names, &spki)?;

    let cert = params
        .self_signed(&key)
        .map_err(|e| TlsError::InvalidConfig(e.to_string()))?;

    Ok(CertifiedKey {
        cert_der: cert.der().to_vec(),
        pkcs8_der: key.pkcs8_der().to_vec(),
        cert_pem: cert.pem(),
    })
}

/// Generate a self-signed TLS certificate using an ECDSA P-256 key pair.
///
/// # Arguments
/// * `subject_alt_names` — one or more DNS names or IP addresses; the first
///   entry is also used as the certificate's Common Name.
///
/// # Errors
/// Returns [`TlsError`] on key generation or certificate serialization failure.
pub fn generate_self_signed_p256(subject_alt_names: &[&str]) -> Result<CertifiedKey, TlsError> {
    let key = OxiEcdsaP256Key::generate()?;
    let spki = rcgen::PublicKeyData::subject_public_key_info(&key);
    let params = build_params(subject_alt_names, &spki)?;

    let cert = params
        .self_signed(&key)
        .map_err(|e| TlsError::InvalidConfig(e.to_string()))?;

    Ok(CertifiedKey {
        cert_der: cert.der().to_vec(),
        pkcs8_der: key.pkcs8_der().to_vec(),
        cert_pem: cert.pem(),
    })
}

/// Generate a self-signed TLS certificate using an ECDSA P-384 key pair.
///
/// # Arguments
/// * `subject_alt_names` — one or more DNS names or IP addresses.
///
/// # Errors
/// Returns [`TlsError`] on key generation or certificate serialization failure.
pub fn generate_self_signed_p384(subject_alt_names: &[&str]) -> Result<CertifiedKey, TlsError> {
    let key = OxiEcdsaP384Key::generate()?;
    let spki = rcgen::PublicKeyData::subject_public_key_info(&key);
    let params = build_params(subject_alt_names, &spki)?;

    let cert = params
        .self_signed(&key)
        .map_err(|e| TlsError::InvalidConfig(e.to_string()))?;

    Ok(CertifiedKey {
        cert_der: cert.der().to_vec(),
        pkcs8_der: key.pkcs8_der().to_vec(),
        cert_pem: cert.pem(),
    })
}

/// Generate a self-signed TLS certificate using an RSA-2048 key pair.
///
/// # Arguments
/// * `subject_alt_names` — one or more DNS names or IP addresses.
///
/// # Errors
/// Returns [`TlsError`] on key generation or certificate serialization failure.
pub fn generate_self_signed_rsa2048(subject_alt_names: &[&str]) -> Result<CertifiedKey, TlsError> {
    let key = OxiRsa2048Key::generate()?;
    let spki = rcgen::PublicKeyData::subject_public_key_info(&key);
    let params = build_params(subject_alt_names, &spki)?;

    let cert = params
        .self_signed(&key)
        .map_err(|e| TlsError::InvalidConfig(e.to_string()))?;

    Ok(CertifiedKey {
        cert_der: cert.der().to_vec(),
        pkcs8_der: key.pkcs8_der().to_vec(),
        cert_pem: cert.pem(),
    })
}

/// Generate a self-signed TLS certificate using an RSA-4096 key pair.
///
/// Key generation takes 2–5 seconds on modern hardware.
///
/// # Arguments
/// * `subject_alt_names` — one or more DNS names or IP addresses.
///
/// # Errors
/// Returns [`TlsError`] on key generation or certificate serialization failure.
pub fn generate_self_signed_rsa4096(subject_alt_names: &[&str]) -> Result<CertifiedKey, TlsError> {
    let key = OxiRsa4096Key::generate()?;
    let spki = rcgen::PublicKeyData::subject_public_key_info(&key);
    let params = build_params(subject_alt_names, &spki)?;

    let cert = params
        .self_signed(&key)
        .map_err(|e| TlsError::InvalidConfig(e.to_string()))?;

    Ok(CertifiedKey {
        cert_der: cert.der().to_vec(),
        pkcs8_der: key.pkcs8_der().to_vec(),
        cert_pem: cert.pem(),
    })
}

/// Generate a self-signed TLS certificate using a pre-loaded RSA-2048 key.
///
/// Unlike [`generate_self_signed_rsa2048`], this function skips key generation
/// and uses the provided key directly, which is useful in tests where a
/// pre-generated key fixture avoids the cost of pure-Rust RSA key generation.
///
/// # Arguments
/// * `subject_alt_names` — one or more DNS names or IP addresses.
/// * `key` — an already-constructed [`OxiRsa2048Key`].
///
/// # Errors
/// Returns [`TlsError`] on certificate serialization failure.
pub fn self_signed_from_rsa2048_key(
    subject_alt_names: &[&str],
    key: OxiRsa2048Key,
) -> Result<CertifiedKey, TlsError> {
    let spki = rcgen::PublicKeyData::subject_public_key_info(&key);
    let params = build_params(subject_alt_names, &spki)?;

    let cert = params
        .self_signed(&key)
        .map_err(|e| TlsError::InvalidConfig(e.to_string()))?;

    Ok(CertifiedKey {
        cert_der: cert.der().to_vec(),
        pkcs8_der: key.pkcs8_der().to_vec(),
        cert_pem: cert.pem(),
    })
}

/// Generate a self-signed TLS certificate using a pre-loaded RSA-4096 key.
///
/// Unlike [`generate_self_signed_rsa4096`], this function skips key generation
/// and uses the provided key directly, which is useful in tests where a
/// pre-generated key fixture avoids the cost of pure-Rust RSA key generation.
///
/// # Arguments
/// * `subject_alt_names` — one or more DNS names or IP addresses.
/// * `key` — an already-constructed [`OxiRsa4096Key`].
///
/// # Errors
/// Returns [`TlsError`] on certificate serialization failure.
pub fn self_signed_from_rsa4096_key(
    subject_alt_names: &[&str],
    key: OxiRsa4096Key,
) -> Result<CertifiedKey, TlsError> {
    let spki = rcgen::PublicKeyData::subject_public_key_info(&key);
    let params = build_params(subject_alt_names, &spki)?;

    let cert = params
        .self_signed(&key)
        .map_err(|e| TlsError::InvalidConfig(e.to_string()))?;

    Ok(CertifiedKey {
        cert_der: cert.der().to_vec(),
        pkcs8_der: key.pkcs8_der().to_vec(),
        cert_pem: cert.pem(),
    })
}

/// Generate a self-signed TLS certificate with the chosen signing algorithm.
///
/// Convenience wrapper over the individual `generate_self_signed_*` functions.
pub fn generate_self_signed(
    subject_alt_names: &[&str],
    alg: SigningAlgorithm,
) -> Result<CertifiedKey, TlsError> {
    match alg {
        SigningAlgorithm::Ed25519 => generate_self_signed_ed25519(subject_alt_names),
        SigningAlgorithm::EcdsaP256 => generate_self_signed_p256(subject_alt_names),
        SigningAlgorithm::EcdsaP384 => generate_self_signed_p384(subject_alt_names),
        SigningAlgorithm::Rsa2048 => generate_self_signed_rsa2048(subject_alt_names),
        SigningAlgorithm::Rsa4096 => generate_self_signed_rsa4096(subject_alt_names),
    }
}

// ── Public API: CA certificate generation ────────────────────────────────────

/// Generate a root CA certificate.
///
/// The CA certificate has `IsCa::Ca(BasicConstraints::Unconstrained)` and
/// `KeyUsage: KeyCertSign | CrlSign | DigitalSignature`.
///
/// # Arguments
/// * `subject_cn` — the Common Name for the CA (e.g. "My Root CA")
/// * `alg` — the signing algorithm to use
///
/// # Errors
/// Returns [`TlsError`] on key generation or certificate signing failure.
pub fn generate_ca(subject_cn: &str, alg: SigningAlgorithm) -> Result<CaCertifiedKey, TlsError> {
    macro_rules! build_ca_with_key {
        ($key:expr, $variant:ident) => {{
            let key = $key;
            let spki = rcgen::PublicKeyData::subject_public_key_info(&key);
            let params = build_ca_params(subject_cn, &spki, None);
            let cert = params
                .clone()
                .self_signed(&key)
                .map_err(|e| TlsError::InvalidConfig(e.to_string()))?;
            let certified_key = CertifiedKey {
                cert_der: cert.der().to_vec(),
                pkcs8_der: key.pkcs8_der().to_vec(),
                cert_pem: cert.pem(),
            };
            Ok(CaCertifiedKey {
                certified_key,
                ca_params: params,
                signer: CaSignerInner::$variant(key),
            })
        }};
    }

    match alg {
        SigningAlgorithm::Ed25519 => build_ca_with_key!(OxiEd25519Key::generate()?, Ed25519),
        SigningAlgorithm::EcdsaP256 => build_ca_with_key!(OxiEcdsaP256Key::generate()?, P256),
        SigningAlgorithm::EcdsaP384 => build_ca_with_key!(OxiEcdsaP384Key::generate()?, P384),
        SigningAlgorithm::Rsa2048 => build_ca_with_key!(OxiRsa2048Key::generate()?, Rsa2048),
        SigningAlgorithm::Rsa4096 => build_ca_with_key!(OxiRsa4096Key::generate()?, Rsa4096),
    }
}

/// Generate an intermediate CA certificate signed by a parent CA.
///
/// The intermediate CA has `IsCa::Ca(BasicConstraints::Constrained(0))` by
/// default (path length 0 = can sign leaf certs but not further
/// intermediates).
///
/// # Arguments
/// * `subject_cn` — the Common Name for the intermediate CA
/// * `alg` — the signing algorithm for the intermediate's own key pair
/// * `parent` — the parent CA that signs this intermediate
///
/// # Errors
/// Returns [`TlsError`] on key generation or certificate signing failure.
pub fn generate_intermediate_ca(
    subject_cn: &str,
    alg: SigningAlgorithm,
    parent: &CaCertifiedKey,
) -> Result<CaCertifiedKey, TlsError> {
    macro_rules! build_intermediate_with_key {
        ($key:expr, $variant:ident) => {{
            let key = $key;
            let spki = rcgen::PublicKeyData::subject_public_key_info(&key);
            let params = build_ca_params(subject_cn, &spki, Some(0));
            let (cert_der, cert_pem) = parent.sign_child(params.clone(), &key)?;
            let certified_key = CertifiedKey {
                cert_der,
                pkcs8_der: key.pkcs8_der().to_vec(),
                cert_pem,
            };
            Ok(CaCertifiedKey {
                certified_key,
                ca_params: params,
                signer: CaSignerInner::$variant(key),
            })
        }};
    }

    match alg {
        SigningAlgorithm::Ed25519 => {
            build_intermediate_with_key!(OxiEd25519Key::generate()?, Ed25519)
        }
        SigningAlgorithm::EcdsaP256 => {
            build_intermediate_with_key!(OxiEcdsaP256Key::generate()?, P256)
        }
        SigningAlgorithm::EcdsaP384 => {
            build_intermediate_with_key!(OxiEcdsaP384Key::generate()?, P384)
        }
        SigningAlgorithm::Rsa2048 => {
            build_intermediate_with_key!(OxiRsa2048Key::generate()?, Rsa2048)
        }
        SigningAlgorithm::Rsa4096 => {
            build_intermediate_with_key!(OxiRsa4096Key::generate()?, Rsa4096)
        }
    }
}

/// Generate a **client** leaf certificate signed by a CA.
///
/// The certificate is issued with the `ClientAuthentication` Extended Key Usage
/// (`id-kp-clientAuth`, OID `1.3.6.1.5.5.7.3.2`) so that
/// `rustls::server::WebPkiClientVerifier` accepts it during mTLS handshakes.
///
/// # Arguments
/// * `subject_alt_names` — DNS names (or IP strings) for the Subject Alternative Name extension
/// * `alg` — the signing algorithm for the client's key pair
/// * `ca` — the CA that signs this leaf certificate
///
/// # Errors
/// Returns [`TlsError`] on key generation or certificate signing failure.
pub fn generate_ca_signed_client_cert(
    subject_alt_names: &[&str],
    alg: SigningAlgorithm,
    ca: &CaCertifiedKey,
) -> Result<CertifiedKey, TlsError> {
    macro_rules! build_client_with_key {
        ($key:expr) => {{
            let key = $key;
            let spki = rcgen::PublicKeyData::subject_public_key_info(&key);
            let params = build_client_params(subject_alt_names, &spki)?;
            let (cert_der, cert_pem) = ca.sign_child(params, &key)?;
            Ok(CertifiedKey {
                cert_der,
                pkcs8_der: key.pkcs8_der().to_vec(),
                cert_pem,
            })
        }};
    }

    match alg {
        SigningAlgorithm::Ed25519 => build_client_with_key!(OxiEd25519Key::generate()?),
        SigningAlgorithm::EcdsaP256 => build_client_with_key!(OxiEcdsaP256Key::generate()?),
        SigningAlgorithm::EcdsaP384 => build_client_with_key!(OxiEcdsaP384Key::generate()?),
        SigningAlgorithm::Rsa2048 => build_client_with_key!(OxiRsa2048Key::generate()?),
        SigningAlgorithm::Rsa4096 => build_client_with_key!(OxiRsa4096Key::generate()?),
    }
}

/// Generate a leaf certificate signed by a CA (root or intermediate).
///
/// # Arguments
/// * `subject_alt_names` — DNS names or IP addresses for the leaf certificate
/// * `alg` — the signing algorithm for the leaf's own key pair
/// * `ca` — the CA that signs this leaf certificate
///
/// # Errors
/// Returns [`TlsError`] on key generation or certificate signing failure.
pub fn generate_ca_signed_leaf(
    subject_alt_names: &[&str],
    alg: SigningAlgorithm,
    ca: &CaCertifiedKey,
) -> Result<CertifiedKey, TlsError> {
    macro_rules! build_leaf_with_key {
        ($key:expr) => {{
            let key = $key;
            let spki = rcgen::PublicKeyData::subject_public_key_info(&key);
            let params = build_params(subject_alt_names, &spki)?;
            let (cert_der, cert_pem) = ca.sign_child(params, &key)?;
            Ok(CertifiedKey {
                cert_der,
                pkcs8_der: key.pkcs8_der().to_vec(),
                cert_pem,
            })
        }};
    }

    match alg {
        SigningAlgorithm::Ed25519 => build_leaf_with_key!(OxiEd25519Key::generate()?),
        SigningAlgorithm::EcdsaP256 => build_leaf_with_key!(OxiEcdsaP256Key::generate()?),
        SigningAlgorithm::EcdsaP384 => build_leaf_with_key!(OxiEcdsaP384Key::generate()?),
        SigningAlgorithm::Rsa2048 => build_leaf_with_key!(OxiRsa2048Key::generate()?),
        SigningAlgorithm::Rsa4096 => build_leaf_with_key!(OxiRsa4096Key::generate()?),
    }
}
