#![no_main]
// Fuzz the OCSP staple verification path via `OcspClientVerifier::verify_server_cert`
// -- the actual attacker-facing entry point exercised during a TLS handshake.
// The OCSP staple bytes (`ocsp_response`) are supplied by whatever server the
// client connects to and are parsed by this crate's own DER/CertID/signature
// logic (check_ocsp_staple / determine_signer_spki / cert_id_matches /
// evaluate_responses in verifier/ocsp_client.rs) well before any trust
// decision is made -- exactly the surface the project's confirmed OCSP
// security fixes (CertID binding, thisUpdate/nextUpdate freshness, leaf-only
// issuer fallback) all lived in.
//
// The leaf/issuer certificate pair and server name are fixed and generated
// once (real DER, produced by oxitls-rcgen); only the OCSP response bytes are
// fuzzed. This lets the fuzzer spend its whole input budget exploring the
// hand-rolled OCSP parsing/matching logic instead of also having to discover
// a syntactically valid X.509 certificate from scratch.
//
// The goal is to assert that no amount of malformed OCSP-response input
// causes a panic. `OcspClientPolicy::SoftFail` is used so that "cannot verify"
// outcomes return `Ok` rather than `Err` -- the fuzz target only cares about
// panics, not about the specific accept/reject decision (that is covered by
// the crate's unit and integration tests).
//
// Run with:
//   cargo fuzz run ocsp_staple_parser

use std::sync::{Arc, OnceLock};

use libfuzzer_sys::fuzz_target;
use oxitls_adapter_rustls_rustcrypto::verifier::{OcspClientPolicy, OcspClientVerifier};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as RustlsError, SignatureScheme};

/// Inner verifier that unconditionally accepts the chain, so the fuzz target
/// isolates the OCSP staple parsing/policy decision from full chain-of-trust
/// validation (which is rustls's own, separately-fuzzed/audited code).
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

/// Fixed (leaf_der, issuer_der) pair, generated once from a single CA so the
/// leaf's issuer DN and signature genuinely chain to the issuer DER passed
/// alongside it -- letting the fuzzer explore the CertID-matching and
/// delegated-signer code paths that a mismatched, independently-generated
/// pair never could.
static CERT_PAIR: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();

fn leaf_and_issuer() -> (&'static [u8], &'static [u8]) {
    let (leaf, issuer) = CERT_PAIR.get_or_init(|| {
        let ca = oxitls_rcgen::generate_ca(
            "OCSP Fuzz Root CA",
            oxitls_rcgen::SigningAlgorithm::EcdsaP256,
        )
        .expect("ca gen");
        let leaf = oxitls_rcgen::generate_ca_signed_leaf(
            &["ocsp-fuzz.example"],
            oxitls_rcgen::SigningAlgorithm::EcdsaP256,
            &ca,
        )
        .expect("leaf gen");
        (leaf.cert_der, ca.certified_key.cert_der)
    });
    (leaf.as_slice(), issuer.as_slice())
}

fuzz_target!(|data: &[u8]| {
    let (leaf_der, issuer_der) = leaf_and_issuer();
    let leaf = CertificateDer::from(leaf_der.to_vec());
    let intermediates = [CertificateDer::from(issuer_der.to_vec())];
    let server_name = ServerName::try_from("ocsp-fuzz.example").expect("valid server name");
    let now = UnixTime::since_unix_epoch(std::time::Duration::from_secs(1_748_304_000));

    let verifier = OcspClientVerifier::new(Arc::new(AlwaysOk), OcspClientPolicy::SoftFail);

    // `data` becomes the raw OCSP staple bytes -- fully attacker-controlled.
    // Must never panic; SoftFail means any unverifiable/malformed staple
    // resolves to `Ok` (a `Revoked` status, if the fuzzer ever manages to
    // forge a structurally-valid-but-wrongly-signed one, would still need to
    // pass signature verification first -- BadSignature is unconditional --
    // so the practical result space here is `Ok` or a `BadSignature`-driven
    // `Err`, never a crash).
    let _ = verifier.verify_server_cert(&leaf, &intermediates, &server_name, data, now);
});
