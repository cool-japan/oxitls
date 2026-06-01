//! Full OCSP stapling integration tests (Wave 9).
//!
//! Verifies that oxitls correctly delivers a server-stapled OCSP response
//! to the client's certificate verifier during the TLS 1.3 handshake.
//!
//! Three tests:
//! 1. `ocsp_staple_delivered_to_client_verifier` — positive: staple bytes flow
//!    server → wire → client verifier's `ocsp_response` argument.
//! 2. `no_ocsp_configured_means_empty_bytes` — negative: no staple configured →
//!    verifier sees empty slice.
//! 3. `static_ocsp_resolver_returns_configured_bytes` — pure unit test on
//!    `StaticOcspResolver::ocsp_response()`.

#[cfg(feature = "pure")]
mod tests {
    use std::sync::{Arc, Mutex};

    use rcgen::{CertificateParams, KeyPair};
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{
        ClientConfig, DigitallySignedStruct, Error as RustlsError, RootCertStore, SignatureScheme,
    };
    use rustls_pki_types::PrivateKeyDer;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::TlsConnector;

    use oxitls::tls13::server::StaticOcspResolver;
    use oxitls::tls13::ServerBuilder;
    use oxitls::OcspResponseResolver;

    // ── SpyServerVerifier ─────────────────────────────────────────────────────

    /// Wraps a real [`ServerCertVerifier`] and captures whatever OCSP bytes
    /// are passed to `verify_server_cert` before delegating to the inner
    /// verifier for the actual chain validation.
    #[derive(Debug)]
    struct SpyServerVerifier {
        inner: Arc<dyn ServerCertVerifier>,
        captured_ocsp: Arc<Mutex<Vec<u8>>>,
    }

    impl SpyServerVerifier {
        /// Construct the spy and return a handle to the captured-bytes cell.
        fn new(inner: Arc<dyn ServerCertVerifier>) -> (Self, Arc<Mutex<Vec<u8>>>) {
            let captured = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    inner,
                    captured_ocsp: Arc::clone(&captured),
                },
                captured,
            )
        }
    }

    impl ServerCertVerifier for SpyServerVerifier {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            intermediates: &[CertificateDer<'_>],
            server_name: &ServerName<'_>,
            ocsp_response: &[u8],
            now: UnixTime,
        ) -> Result<ServerCertVerified, RustlsError> {
            // Capture before delegating so we record even if inner rejects.
            let mut guard = self.captured_ocsp.lock().unwrap_or_else(|e| e.into_inner());
            *guard = ocsp_response.to_vec();
            drop(guard);
            self.inner.verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            )
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

    // ── Loopback helpers ──────────────────────────────────────────────────────

    /// Build a self-signed Ed25519 cert + private key.
    fn gen_cert() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        let kp = KeyPair::generate().expect("KeyPair::generate");
        let cert = CertificateParams::new(vec!["localhost".into()])
            .expect("CertificateParams::new")
            .self_signed(&kp)
            .expect("self_signed");
        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(kp.serialize_der().into());
        (cert_der, key_der)
    }

    /// Build a `WebPkiServerVerifier` that trusts a single DER cert.
    fn webpki_verifier_for(cert_der: &CertificateDer<'static>) -> Arc<dyn ServerCertVerifier> {
        let provider = oxitls_adapter_rustls_rustcrypto::pure_provider();
        let mut roots = RootCertStore::empty();
        roots.add(cert_der.clone()).expect("add root cert");
        rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
            .build()
            .expect("WebPkiServerVerifier::build")
    }

    /// Build a `ClientConfig` that installs the given verifier via the
    /// `dangerous()` path.  This bypasses `ClientBuilder` intentionally so
    /// we can inject our `SpyServerVerifier` without adding a new public API.
    fn client_config_with_verifier(verifier: Arc<dyn ServerCertVerifier>) -> Arc<ClientConfig> {
        let provider = oxitls_adapter_rustls_rustcrypto::pure_provider();
        let config = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3 not supported by provider")
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        Arc::new(config)
    }

    // ── Test 1: positive ──────────────────────────────────────────────────────

    /// Server staples `b"fake-ocsp-data"`.
    /// Client verifier (spy) MUST receive those exact bytes in
    /// `verify_server_cert(ocsp_response)`.
    #[tokio::test]
    async fn ocsp_staple_delivered_to_client_verifier() {
        let fake_ocsp = b"fake-ocsp-data";

        let (cert_der, key_der) = gen_cert();
        let server_cfg = ServerBuilder::new()
            .with_der_cert_and_key(vec![cert_der.clone()], key_der)
            .with_ocsp_response(fake_ocsp.to_vec())
            .build()
            .expect("server config build");
        let acceptor = oxitls::tls13::server::tokio_acceptor(server_cfg);

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("local_addr");

        let server_task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("accept");
            let mut tls = acceptor.accept(tcp).await.expect("tls accept");
            // Echo one byte so the handshake completes before we drop.
            let mut buf = [0u8; 1];
            tls.read_exact(&mut buf).await.expect("server read");
            tls.write_all(&buf).await.expect("server write");
            tls.flush().await.expect("server flush");
        });

        let inner = webpki_verifier_for(&cert_der);
        let (spy, captured) = SpyServerVerifier::new(inner);
        let client_cfg = client_config_with_verifier(Arc::new(spy));

        let connector = TlsConnector::from(client_cfg);
        let tcp = TcpStream::connect(addr).await.expect("connect");
        let server_name = ServerName::try_from("localhost").expect("server name");
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .expect("tls connect");

        // Trigger the echo so the server task can finish cleanly.
        tls.write_all(&[0x01]).await.expect("client write");
        tls.flush().await.expect("client flush");
        let mut reply = [0u8; 1];
        tls.read_exact(&mut reply).await.expect("client read");

        let ocsp_seen = captured.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert_eq!(
            ocsp_seen.as_slice(),
            fake_ocsp,
            "OCSP staple bytes delivered to verifier must match what the server configured"
        );

        server_task.await.expect("server task");
    }

    // ── Test 2: negative ──────────────────────────────────────────────────────

    /// Server does NOT configure any OCSP response.
    /// Client verifier (spy) MUST see an empty slice in `ocsp_response`.
    #[tokio::test]
    async fn no_ocsp_configured_means_empty_bytes() {
        let (cert_der, key_der) = gen_cert();
        let server_cfg = ServerBuilder::new()
            .with_der_cert_and_key(vec![cert_der.clone()], key_der)
            // Intentionally NO with_ocsp_response() call.
            .build()
            .expect("server config build");
        let acceptor = oxitls::tls13::server::tokio_acceptor(server_cfg);

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("local_addr");

        let server_task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("accept");
            let mut tls = acceptor.accept(tcp).await.expect("tls accept");
            let mut buf = [0u8; 1];
            tls.read_exact(&mut buf).await.expect("server read");
            tls.write_all(&buf).await.expect("server write");
            tls.flush().await.expect("server flush");
        });

        let inner = webpki_verifier_for(&cert_der);
        let (spy, captured) = SpyServerVerifier::new(inner);
        let client_cfg = client_config_with_verifier(Arc::new(spy));

        let connector = TlsConnector::from(client_cfg);
        let tcp = TcpStream::connect(addr).await.expect("connect");
        let server_name = ServerName::try_from("localhost").expect("server name");
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .expect("tls connect");

        tls.write_all(&[0x02]).await.expect("client write");
        tls.flush().await.expect("client flush");
        let mut reply = [0u8; 1];
        tls.read_exact(&mut reply).await.expect("client read");

        let ocsp_seen = captured.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert!(
            ocsp_seen.is_empty(),
            "no OCSP configured: verifier must see empty slice, got {:?}",
            ocsp_seen
        );

        server_task.await.expect("server task");
    }

    // ── Test 3: unit test on StaticOcspResolver ───────────────────────────────

    /// `StaticOcspResolver` always returns the bytes it was constructed with.
    #[test]
    fn static_ocsp_resolver_returns_configured_bytes() {
        let bytes: Vec<u8> = vec![0x30, 0x03, 0x0a, 0x01, 0x00];
        let resolver = StaticOcspResolver(bytes.clone());
        let returned = resolver
            .ocsp_response()
            .expect("StaticOcspResolver must return Some(_)");
        assert_eq!(
            returned, bytes,
            "StaticOcspResolver must return exactly the bytes it was constructed with"
        );
    }

    /// `StaticOcspResolver::ocsp_response` is idempotent: two calls return equal bytes.
    #[test]
    fn static_ocsp_resolver_idempotent() {
        let bytes: Vec<u8> = b"OCSP-DER-blob".to_vec();
        let resolver = StaticOcspResolver(bytes.clone());
        let first = resolver.ocsp_response().expect("first call");
        let second = resolver.ocsp_response().expect("second call");
        assert_eq!(first, second, "StaticOcspResolver must be idempotent");
    }
}
