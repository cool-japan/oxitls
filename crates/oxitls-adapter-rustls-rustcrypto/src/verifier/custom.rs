//! Custom server certificate verifier with an inner verifier and a predicate.
//!
//! `CustomServerVerifier` runs the inner PKI verifier first, then calls a
//! caller-supplied predicate with the leaf cert and its chain. The predicate
//! can approve, modify, or reject the certificate at the application layer.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error, SignatureScheme};

/// The signature of the custom verification predicate.
///
/// Called **after** the inner verifier has succeeded. Returns
/// `Ok(ServerCertVerified::assertion())` to accept or `Err(rustls::Error)`
/// to reject.
pub type CertPredicate = dyn Fn(&CertificateDer<'_>, &[CertificateDer<'_>]) -> Result<ServerCertVerified, Error>
    + Send
    + Sync;

/// A server certificate verifier that delegates to an inner verifier and then
/// calls a custom predicate for additional application-level checks.
pub struct CustomServerVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    predicate: Box<CertPredicate>,
}

impl std::fmt::Debug for CustomServerVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CustomServerVerifier")
            .finish_non_exhaustive()
    }
}

impl CustomServerVerifier {
    /// Create a new `CustomServerVerifier`.
    ///
    /// `inner` performs standard PKI validation. `predicate` is invoked only
    /// when `inner` succeeds and may apply additional constraints.
    pub fn new(inner: Arc<dyn ServerCertVerifier>, predicate: Box<CertPredicate>) -> Self {
        Self { inner, predicate }
    }
}

impl ServerCertVerifier for CustomServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        // Run inner verification first.
        self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;
        // Then apply the custom predicate.
        (self.predicate)(end_entity, intermediates)
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
