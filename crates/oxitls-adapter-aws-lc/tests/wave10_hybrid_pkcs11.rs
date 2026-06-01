//! Hybrid HSM+FIPS architecture test.
//!
//! Demonstrates that a custom `rustls::sign::SigningKey` implementation
//! (representing a PKCS#11-backed HSM key in production) can be combined
//! with the `aws_lc_provider()` CryptoProvider for FIPS-compliant bulk crypto.
//!
//! # Architecture
//!
//! In this test we use `TestP256SigningKey` (a pure-Rust P-256 implementation)
//! as a stand-in for a real `Pkcs11SigningKey`. In production, replace
//! `TestP256SigningKey` with `oxitls_adapter_pkcs11::Pkcs11SigningKey` backed
//! by SoftHSM2 or a hardware HSM to achieve:
//! - PKCS#11 key operations (private key never leaves the HSM)
//! - aws-lc-rs bulk crypto (AES-GCM, ChaCha20-Poly1305, ECDHE — FIPS 140-2)
//!
//! # Key insight
//!
//! rustls decouples the `CryptoProvider` (bulk crypto + KEX) from the
//! `SigningKey` (certificate private key). Any `SigningKey` impl works with
//! any `CryptoProvider`. This test proves the seam is real: the custom
//! signing key is called during the TLS 1.3 CertificateVerify handshake step,
//! confirmed via `AtomicBool`.
//!
//! # Run
//!
//! ```bash
//! cargo nextest run -p oxitls-adapter-aws-lc --features aws-lc \
//!     --test wave10_hybrid_pkcs11
//! ```

#[cfg(feature = "aws-lc")]
mod tests {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    use oxitls_adapter_aws_lc::aws_lc_provider;
    use p256::{
        ecdsa::{signature::Signer as EcdsaSigner, Signature, SigningKey as P256SigningKey},
        pkcs8::DecodePrivateKey,
        SecretKey,
    };
    use rustls::{
        server::ResolvesServerCert,
        sign::{CertifiedKey, Signer, SigningKey, SingleCertAndKey},
        ClientConfig, RootCertStore, ServerConfig, SignatureAlgorithm, SignatureScheme,
    };
    use rustls_pki_types::{CertificateDer, ServerName};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    // ── TestP256Signer ─────────────────────────────────────────────────────────

    /// Single-use signer for one ECDSA P-256 CertificateVerify message.
    ///
    /// Wraps a cloned P-256 private key and records each invocation of
    /// `sign()` so tests can assert the HSM path was exercised.
    #[derive(Debug)]
    struct TestP256Signer {
        key: P256SigningKey,
        scheme: SignatureScheme,
        /// Flipped to `true` the first time `sign()` is called.
        did_sign: Arc<AtomicBool>,
    }

    impl Signer for TestP256Signer {
        fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
            self.did_sign.store(true, Ordering::Relaxed);
            let sig: Signature = self.key.sign(message);
            // rustls expects DER-encoded ASN.1 ECDSA signature (SEQUENCE { r, s }).
            Ok(sig.to_der().as_bytes().to_vec())
        }

        fn scheme(&self) -> SignatureScheme {
            self.scheme
        }
    }

    // ── TestP256SigningKey ──────────────────────────────────────────────────────

    /// Stand-in for a PKCS#11-backed signing key.
    ///
    /// In production this struct holds a PKCS#11 session handle + key handle.
    /// Here it holds a pure-Rust P-256 key so the test can run without an HSM.
    #[derive(Debug)]
    struct TestP256SigningKey {
        key: P256SigningKey,
        did_sign: Arc<AtomicBool>,
    }

    impl TestP256SigningKey {
        /// Construct from a PKCS#8 DER-encoded P-256 private key.
        ///
        /// Mirrors the PKCS#11 object-handle-based constructor in production.
        fn from_pkcs8_der(pkcs8_der: &[u8]) -> Result<Self, p256::pkcs8::Error> {
            let secret_key = SecretKey::from_pkcs8_der(pkcs8_der)?;
            Ok(Self {
                key: P256SigningKey::from(secret_key),
                did_sign: Arc::new(AtomicBool::new(false)),
            })
        }

        /// Returns a shared reference to the sign-invocation flag.
        fn did_sign_handle(&self) -> Arc<AtomicBool> {
            Arc::clone(&self.did_sign)
        }
    }

    impl SigningKey for TestP256SigningKey {
        fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
            if offered.contains(&SignatureScheme::ECDSA_NISTP256_SHA256) {
                Some(Box::new(TestP256Signer {
                    key: self.key.clone(),
                    scheme: SignatureScheme::ECDSA_NISTP256_SHA256,
                    did_sign: Arc::clone(&self.did_sign),
                }))
            } else {
                None
            }
        }

        fn algorithm(&self) -> SignatureAlgorithm {
            SignatureAlgorithm::ECDSA
        }
    }

    // ── test ───────────────────────────────────────────────────────────────────

    /// Full TLS handshake: both sides use aws-lc-rs for bulk crypto, but the
    /// server's signing key is the custom `TestP256SigningKey` — not a DER key
    /// loaded through `with_single_cert`.
    ///
    /// This proves the PKCS#11 hybrid seam works end-to-end.
    #[tokio::test]
    async fn hybrid_p256_signing_key_with_aws_lc_provider_succeeds() {
        // ── 1. Generate cert + extract matching key ──────────────────────────
        //
        // generate_self_signed_p256 produces ONE keypair; we pull out the
        // pkcs8_der to reconstruct `P256SigningKey` so they match.
        let ck_rcgen = oxitls_rcgen::generate_self_signed_p256(&["localhost"])
            .expect("rcgen p256 self-signed cert");

        let cert_der = CertificateDer::from(ck_rcgen.cert_der.clone());

        // Reconstruct signing key from the same DER bytes — this is the
        // equivalent of `Pkcs11SigningKey::load(slot, label)` in production.
        let signing_key = TestP256SigningKey::from_pkcs8_der(&ck_rcgen.pkcs8_der)
            .expect("p256 key from pkcs8 der");
        let did_sign = signing_key.did_sign_handle();

        // ── 2. Build CertifiedKey with custom signing key ────────────────────
        //
        // `SingleCertAndKey` implements `ResolvesServerCert` and returns our
        // custom `SigningKey` to rustls.  The private key DER is *never* passed
        // to `with_single_cert`; rustls only ever calls `choose_scheme` → `sign`.
        let certified_key = CertifiedKey::new(
            vec![cert_der.clone()],
            Arc::new(signing_key) as Arc<dyn SigningKey>,
        );

        // ── 3. Server: aws_lc_provider() + custom cert resolver ──────────────
        let server_config = ServerConfig::builder_with_provider(aws_lc_provider())
            .with_safe_default_protocol_versions()
            .expect("server protocol versions")
            .with_no_client_auth()
            .with_cert_resolver(
                Arc::new(SingleCertAndKey::from(certified_key)) as Arc<dyn ResolvesServerCert>
            );
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        // ── 4. Client: aws_lc_provider() + trust the test cert ───────────────
        let mut root_store = RootCertStore::empty();
        root_store
            .add(cert_der)
            .expect("add test cert to root store");
        let client_config = ClientConfig::builder_with_provider(aws_lc_provider())
            .with_safe_default_protocol_versions()
            .expect("client protocol versions")
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_config));

        // ── 5. Loopback TCP + TLS handshake ──────────────────────────────────
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let port = listener.local_addr().expect("local addr").port();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("tcp accept");
            let mut tls = acceptor.accept(stream).await.expect("tls accept");
            // Drain any data the client might send; we just need the handshake.
            tokio::io::copy(&mut tls, &mut tokio::io::sink()).await.ok();
        });

        let tcp = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("tcp connect");
        let server_name = ServerName::try_from("localhost")
            .expect("server name parse")
            .to_owned();
        let _tls = connector
            .connect(server_name, tcp)
            .await
            .expect("tls handshake via custom signing key + aws-lc-rs provider");

        server.abort();

        // ── 6. Assert the custom signer was invoked ───────────────────────────
        //
        // TLS 1.3 always sends CertificateVerify, so our custom `sign()` must
        // have been called at least once.  This proves the PKCS#11 seam fired.
        assert!(
            did_sign.load(Ordering::Relaxed),
            "TestP256Signer::sign() was never called — custom signing key not used"
        );
    }
}
