//! Dangerous certificate verifiers for testing and development only.
//!
//! **WARNING**: Do not use these in production. They weaken TLS security
//! guarantees and should only appear in test configurations.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error, SignatureScheme};

/// WARNING: for testing/development use only.
///
/// A certificate verifier that accepts any server certificate where the TLS
/// chain validates but the hostname does not match the presented certificate's
/// SAN. All other verification errors (expiry, revocation, signature failures,
/// etc.) are propagated normally.
///
/// Install via [`crate::tls13::ClientBuilder::with_danger_accept_invalid_hostnames`].
#[derive(Debug)]
pub(crate) struct DangerHostnameIgnoreVerifier {
    inner: Arc<WebPkiServerVerifier>,
}

impl DangerHostnameIgnoreVerifier {
    /// Create a new verifier wrapping the given `WebPkiServerVerifier`.
    pub(crate) fn new(inner: Arc<WebPkiServerVerifier>) -> Self {
        Self { inner }
    }
}

impl ServerCertVerifier for DangerHostnameIgnoreVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        match self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(verified) => Ok(verified),
            Err(Error::InvalidCertificate(rustls::CertificateError::NotValidForName))
            | Err(Error::InvalidCertificate(rustls::CertificateError::NotValidForNameContext {
                ..
            })) => {
                // Swallow hostname mismatch (either variant); propagate all other errors.
                Ok(ServerCertVerified::assertion())
            }
            Err(other) => Err(other),
        }
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
