//! Certificate-pinning server verifier.
//!
//! `CertPinVerifier` wraps an inner [`rustls::client::danger::ServerCertVerifier`]
//! and additionally checks that the leaf certificate's SHA-256 fingerprint
//! matches one of the caller-supplied pinned fingerprints. A mismatched
//! fingerprint causes immediate failure regardless of the chain's
//! PKI validity.
//!
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error, SignatureScheme};
use sha2::{Digest, Sha256};

/// A server certificate verifier that enforces SHA-256 leaf-certificate
/// fingerprint pinning in addition to normal PKI verification.
///
/// If none of the pinned fingerprints match the leaf certificate, the
/// handshake is rejected with
/// [`rustls::CertificateError::ApplicationVerificationFailure`].
pub struct CertPinVerifier {
    pinned: Vec<[u8; 32]>,
    inner: Arc<dyn ServerCertVerifier>,
}

impl std::fmt::Debug for CertPinVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertPinVerifier")
            .field("pinned_count", &self.pinned.len())
            .finish_non_exhaustive()
    }
}

impl CertPinVerifier {
    /// Create a new `CertPinVerifier`.
    ///
    /// `pinned` is the set of acceptable SHA-256 fingerprints of leaf
    /// certificates (computed over the full DER encoding).
    ///
    /// `inner` is the underlying verifier that performs normal PKI
    /// validation after the pin check passes.
    pub fn new(pinned: Vec<[u8; 32]>, inner: Arc<dyn ServerCertVerifier>) -> Self {
        Self { pinned, inner }
    }
}

impl ServerCertVerifier for CertPinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        // Compute the SHA-256 fingerprint of the leaf DER.
        let digest = Sha256::digest(end_entity.as_ref());
        let mut fingerprint = [0u8; 32];
        fingerprint.copy_from_slice(&digest);

        // Reject if none of the pinned fingerprints match.
        if !self.pinned.contains(&fingerprint) {
            return Err(Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }

        // Delegate to inner verifier for PKI validation.
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}
