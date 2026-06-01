//! CRL-aware server certificate verifier.
//!
//! Wraps a [`rustls::client::WebPkiServerVerifier`] built with CRL checking
//! enabled and delegates all `ServerCertVerifier` method calls to it.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error, RootCertStore, SignatureScheme};

use crate::pure_provider;

/// A server certificate verifier that checks revocation against caller-supplied
/// CRLs using [`rustls::client::WebPkiServerVerifier`].
pub struct CrlAwareServerVerifier {
    inner: Arc<WebPkiServerVerifier>,
}

impl std::fmt::Debug for CrlAwareServerVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CrlAwareServerVerifier")
            .field("inner", &self.inner)
            .finish()
    }
}

impl CrlAwareServerVerifier {
    /// Build a new verifier from a root cert store and a list of CRLs.
    ///
    /// # Errors
    ///
    /// Returns [`oxitls_core::TlsError`] if the verifier cannot be built
    /// (e.g. empty root store or unparseable CRL DER).
    pub fn new(
        roots: RootCertStore,
        crls: Vec<CertificateRevocationListDer<'static>>,
    ) -> Result<Self, oxitls_core::TlsError> {
        let inner = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), pure_provider())
            .with_crls(crls)
            .build()
            .map_err(|e| oxitls_core::TlsError::InvalidConfig(format!("CRL verifier: {e}")))?;
        Ok(Self { inner })
    }
}

impl ServerCertVerifier for CrlAwareServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
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
