//! RFC 7250 raw public key verifiers for rustls.
//!
//! Implements [`RawPublicKeyServerVerifier`] (client side — verifies the
//! server's raw public key) and [`RawPublicKeyClientVerifier`] (server side —
//! verifies the client's raw public key) as rustls `danger` traits.
//!
//! In RFC 7250 / TLS raw-public-key mode the `Certificate` message carries a
//! bare SubjectPublicKeyInfo (SPKI) DER blob instead of a full X.509 chain.
//! Rustls passes that blob to `verify_server_cert` / `verify_client_cert` as
//! `end_entity: &CertificateDer<'_>` — exactly the bytes we pin against.
//!
//! Both verifiers:
//! - Return `true` from `requires_raw_public_keys()` so rustls negotiates RPK.
//! - Pin against a caller-supplied list of trusted SPKI DER blobs.
//! - Delegate handshake-signature verification to
//!   [`rustls::crypto::verify_tls13_signature_with_raw_key`], which operates
//!   on raw SPKI bytes instead of parsed X.509 certs.
//! - Return an error for TLS 1.2 (raw keys are specified for TLS 1.3 only in
//!   RFC 7250 / RFC 8446 §4.4.2).
//!
//! # Helper free-functions
//!
//! - [`server_raw_public_key_resolver`] — wraps a `CertifiedKey` in
//!   [`rustls::server::AlwaysResolvesServerRawPublicKeys`].
//! - [`client_raw_public_key_resolver`] — wraps a `CertifiedKey` in
//!   [`rustls::client::AlwaysResolvesClientRawPublicKeys`].

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::verify_tls13_signature_with_raw_key;
use rustls::pki_types::{CertificateDer, ServerName, SubjectPublicKeyInfoDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::DistinguishedName;
use rustls::{CertificateError, DigitallySignedStruct, Error, SignatureScheme};

// ── Server verifier (used by the TLS client) ─────────────────────────────────

/// A [`ServerCertVerifier`] that pins the server's raw public key (SPKI DER).
///
/// Returned from `requires_raw_public_keys() → true` so rustls negotiates RPK
/// mode. During `verify_server_cert`, `end_entity` carries the SPKI DER sent
/// by the server; we compare it byte-for-byte against `trusted_spki`.
#[derive(Debug)]
pub struct RawPublicKeyServerVerifier {
    trusted_spki: Vec<SubjectPublicKeyInfoDer<'static>>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl RawPublicKeyServerVerifier {
    /// Create a new verifier.
    ///
    /// `trusted_spki` is the list of acceptable server SPKI DER blobs.
    /// `provider` is the `CryptoProvider` used for handshake-signature
    /// verification — obtain it with
    /// [`crate::pure_provider()`].
    pub fn new(
        trusted_spki: Vec<SubjectPublicKeyInfoDer<'static>>,
        provider: Arc<rustls::crypto::CryptoProvider>,
    ) -> Self {
        Self {
            trusted_spki,
            provider,
        }
    }
}

impl ServerCertVerifier for RawPublicKeyServerVerifier {
    fn requires_raw_public_keys(&self) -> bool {
        true
    }

    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        // In RPK mode `end_entity` carries the raw SPKI DER sent by the server.
        // Pin check: accept if any trusted entry matches byte-for-byte.
        let presented: &[u8] = end_entity.as_ref();
        let matched = self
            .trusted_spki
            .iter()
            .any(|pin| pin.as_ref() == presented);

        if matched {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        // Raw public keys are TLS 1.3 only (RFC 7250 §3.3 / RFC 8446 §4.4.2).
        Err(Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        // In RPK mode `cert` contains the raw SPKI DER — reinterpret it.
        let spki = SubjectPublicKeyInfoDer::from(cert.as_ref().to_vec());
        verify_tls13_signature_with_raw_key(
            message,
            &spki,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ── Client verifier (used by the TLS server) ─────────────────────────────────

/// A [`ClientCertVerifier`] that pins the client's raw public key (SPKI DER).
///
/// Used on the server side to authenticate clients in mutual-RPK mode.
/// Returns `true` from `requires_raw_public_keys()` and
/// `client_auth_mandatory()` — client authentication is required.
#[derive(Debug)]
pub struct RawPublicKeyClientVerifier {
    trusted_spki: Vec<SubjectPublicKeyInfoDer<'static>>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl RawPublicKeyClientVerifier {
    /// Create a new verifier.
    ///
    /// `trusted_spki` is the list of acceptable client SPKI DER blobs.
    /// `provider` is the `CryptoProvider` used for handshake-signature
    /// verification.
    pub fn new(
        trusted_spki: Vec<SubjectPublicKeyInfoDer<'static>>,
        provider: Arc<rustls::crypto::CryptoProvider>,
    ) -> Self {
        Self {
            trusted_spki,
            provider,
        }
    }
}

impl ClientCertVerifier for RawPublicKeyClientVerifier {
    fn requires_raw_public_keys(&self) -> bool {
        true
    }

    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        // No CA hints for raw-public-key mode.
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        let presented: &[u8] = end_entity.as_ref();
        let matched = self
            .trusted_spki
            .iter()
            .any(|pin| pin.as_ref() == presented);

        if matched {
            Ok(ClientCertVerified::assertion())
        } else {
            Err(Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        // Raw public keys are TLS 1.3 only.
        Err(Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        let spki = SubjectPublicKeyInfoDer::from(cert.as_ref().to_vec());
        verify_tls13_signature_with_raw_key(
            message,
            &spki,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ── Resolver helpers ──────────────────────────────────────────────────────────

/// Wrap a [`rustls::sign::CertifiedKey`] in a server resolver that always
/// presents a raw public key (RFC 7250).
///
/// The `CertifiedKey.cert` field must contain exactly one entry — the raw
/// SPKI DER to present to the client. Build it with:
///
/// ```ignore
/// let spki_der = spki_from_cert_der(&cert_der);  // your extraction helper
/// let signing_key = provider.key_provider.load_private_key(pkcs8_key)?;
/// let ck = Arc::new(rustls::sign::CertifiedKey::new(
///     vec![rustls::pki_types::CertificateDer::from(spki_der)],
///     signing_key,
/// ));
/// let resolver = server_raw_public_key_resolver(ck);
/// ```
pub fn server_raw_public_key_resolver(
    certified_key: Arc<rustls::sign::CertifiedKey>,
) -> Arc<dyn rustls::server::ResolvesServerCert> {
    Arc::new(rustls::server::AlwaysResolvesServerRawPublicKeys::new(
        certified_key,
    ))
}

/// Wrap a [`rustls::sign::CertifiedKey`] in a client resolver that always
/// presents a raw public key (RFC 7250) for mTLS.
///
/// Same construction as [`server_raw_public_key_resolver`]: the
/// `CertifiedKey.cert` field must contain the SPKI DER.
pub fn client_raw_public_key_resolver(
    certified_key: Arc<rustls::sign::CertifiedKey>,
) -> Arc<dyn rustls::client::ResolvesClientCert> {
    Arc::new(rustls::client::AlwaysResolvesClientRawPublicKeys::new(
        certified_key,
    ))
}
