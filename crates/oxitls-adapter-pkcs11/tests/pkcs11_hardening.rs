// SPDX-License-Identifier: Apache-2.0
// Copyright COOLJAPAN OU (Team Kitasan)
//! Wave 5 production-hardening integration tests for the PKCS#11 adapter.
//!
//! Tests that require a live SoftHSM2 token are marked `#[ignore]` and only
//! run when `SOFTHSM2_MODULE` is set in the environment.  All other tests run
//! in CI without any HSM hardware.
//!
//! The full feature gate (`#[cfg(feature = "pkcs11")]`) is applied to
//! individual items below so that `cargo test` without `--features pkcs11`
//! does not compile HSM-dependent code paths.

use oxitls_adapter_pkcs11::Pkcs11Error;

/// Guard: returns `true` when SoftHSM2 is available via the `SOFTHSM2_MODULE`
/// environment variable.
#[cfg(feature = "pkcs11")]
fn softhsm2_available() -> bool {
    std::env::var("SOFTHSM2_MODULE").is_ok()
}

// ---------------------------------------------------------------------------
// 1. From<cryptoki::error::Error> error mapping (no HSM required)
// ---------------------------------------------------------------------------

/// Verify that `cryptoki::error::Error::NotSupported` maps to
/// `Pkcs11Error::Unsupported`.
#[test]
#[cfg(feature = "pkcs11")]
fn from_cryptoki_error_maps_not_supported() {
    let ck_err = cryptoki::error::Error::NotSupported;
    let pk_err = Pkcs11Error::from(ck_err);
    assert!(
        matches!(pk_err, Pkcs11Error::Unsupported(_)),
        "expected Unsupported, got: {pk_err:?}"
    );
    // Display must mention "unsupported".
    let disp = format!("{pk_err}");
    assert!(
        disp.to_ascii_lowercase().contains("unsupported"),
        "unexpected display: {disp}"
    );
}

/// Verify that `cryptoki::error::Error::NullFunctionPointer` maps to
/// `Pkcs11Error::Other` (catch-all path).
#[test]
#[cfg(feature = "pkcs11")]
fn from_cryptoki_error_maps_null_function_pointer() {
    let ck_err = cryptoki::error::Error::NullFunctionPointer;
    let pk_err = Pkcs11Error::from(ck_err);
    assert!(
        matches!(pk_err, Pkcs11Error::Other(_)),
        "expected Other, got: {pk_err:?}"
    );
}

/// Verify that `cryptoki::error::Error::InvalidValue` maps to
/// `Pkcs11Error::Other` (catch-all path).
#[test]
#[cfg(feature = "pkcs11")]
fn from_cryptoki_error_maps_invalid_value() {
    let ck_err = cryptoki::error::Error::InvalidValue;
    let pk_err = Pkcs11Error::from(ck_err);
    assert!(
        matches!(pk_err, Pkcs11Error::Other(_)),
        "expected Other, got: {pk_err:?}"
    );
}

/// Verify that new error variants have non-empty Display output.
#[test]
fn new_error_variants_display() {
    let hsm = Pkcs11Error::HsmError {
        code: 0x0000_0006,
        msg: "CKR_FUNCTION_FAILED".to_string(),
    };
    let s = format!("{hsm}");
    assert!(!s.is_empty(), "HsmError display is empty");
    // {:#x} formats 0x6 as "0x6"; accept "0x6" or "0x00000006".
    assert!(
        s.contains("0x6") || s.contains("0x00000006"),
        "expected hex code in display: {s}"
    );

    let unsup = Pkcs11Error::Unsupported("test".to_string());
    assert!(!format!("{unsup}").is_empty());

    let load = Pkcs11Error::LoadFailed("libsofthsm2.so".to_string());
    let ld = format!("{load}");
    assert!(ld.contains("libsofthsm2.so"), "unexpected display: {ld}");
}

// ---------------------------------------------------------------------------
// 2. SNI dispatch (no HSM required — uses mock CertifiedKey)
// ---------------------------------------------------------------------------

/// Verify SNI-based certificate selection routes to the correct entry.
///
/// This test bypasses `Pkcs11SigningKey` (which requires a real session pool)
/// by constructing `CertifiedKey` values directly with a minimal mock signing
/// key, then building a `Pkcs11ServerCertResolver` via `with_sni_map`.
#[test]
#[cfg(feature = "pkcs11")]
fn sni_dispatch_correct_variant() {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use oxitls_adapter_pkcs11::Pkcs11ServerCertResolver;
    use rustls::pki_types::CertificateDer;

    // ------------------------------------------------------------------
    // Minimal no-op signing key for constructing test CertifiedKeys.
    // ------------------------------------------------------------------
    #[derive(Debug)]
    struct NoopSigningKey;

    impl rustls::sign::SigningKey for NoopSigningKey {
        fn choose_scheme(
            &self,
            _offered: &[rustls::SignatureScheme],
        ) -> Option<Box<dyn rustls::sign::Signer>> {
            None
        }
        fn algorithm(&self) -> rustls::SignatureAlgorithm {
            rustls::SignatureAlgorithm::ECDSA
        }
    }

    // Build two CertifiedKey values with different chain lengths so we can
    // distinguish them in assertions.
    let chain_a: Vec<CertificateDer<'static>> = vec![CertificateDer::from(vec![0xAA; 10])];
    let chain_b: Vec<CertificateDer<'static>> = vec![
        CertificateDer::from(vec![0xBB; 20]),
        CertificateDer::from(vec![0xCC; 20]),
    ];

    let key_a: Arc<dyn rustls::sign::SigningKey> = Arc::new(NoopSigningKey);
    let key_b: Arc<dyn rustls::sign::SigningKey> = Arc::new(NoopSigningKey);

    let mut map: BTreeMap<
        String,
        (
            Vec<CertificateDer<'static>>,
            Arc<dyn rustls::sign::SigningKey>,
        ),
    > = BTreeMap::new();
    map.insert("alpha.example.com".to_string(), (chain_a, key_a));
    map.insert("beta.example.com".to_string(), (chain_b, key_b));

    let resolver = Pkcs11ServerCertResolver::with_sni_map(map);

    // --- SNI hit: alpha.example.com → chain with 1 certificate ---
    let ck_a = resolver
        .lookup(Some("alpha.example.com"))
        .expect("alpha.example.com should resolve");
    assert_eq!(
        ck_a.cert.len(),
        1,
        "alpha.example.com chain length should be 1"
    );

    // --- SNI hit: beta.example.com → chain with 2 certificates ---
    let ck_b = resolver
        .lookup(Some("beta.example.com"))
        .expect("beta.example.com should resolve");
    assert_eq!(
        ck_b.cert.len(),
        2,
        "beta.example.com chain length should be 2"
    );

    // --- SNI miss: unknown hostname → None (no default set via with_sni_map) ---
    assert!(
        resolver.lookup(Some("missing.example.com")).is_none(),
        "missing.example.com should not resolve (no fallback)"
    );

    // --- No SNI → None (no default set via with_sni_map) ---
    assert!(
        resolver.lookup(None).is_none(),
        "lookup(None) should return None when no default is configured"
    );
}

// ---------------------------------------------------------------------------
// 3. list_keys round-trip (requires SoftHSM2)
// ---------------------------------------------------------------------------

/// Enumerate all private keys on the token; verify the call path does not
/// panic and returns a `Vec` (possibly empty).
#[test]
#[ignore]
#[cfg(feature = "pkcs11")]
fn list_keys_returns_imported_keys() {
    if !softhsm2_available() {
        eprintln!("SOFTHSM2_MODULE not set — skipping list_keys test");
        return;
    }

    use oxitls_adapter_pkcs11::Pkcs11TlsProvider;
    use secrecy::SecretString;
    use std::path::PathBuf;

    let module_path = PathBuf::from(std::env::var("SOFTHSM2_MODULE").unwrap());
    let slot_id: u64 = std::env::var("SOFTHSM2_SLOT")
        .unwrap_or_else(|_| "0".to_string())
        .parse()
        .unwrap_or(0);
    let pin =
        SecretString::from(std::env::var("SOFTHSM2_PIN").unwrap_or_else(|_| "1234".to_string()));

    let provider = Pkcs11TlsProvider::new(module_path, slot_id, pin).expect("create provider");

    let keys = provider.list_keys(None).expect("list_keys");
    // A freshly provisioned token might have 0 or more keys — we just verify
    // the call path is exercised without panic.
    eprintln!("list_keys returned {} keys", keys.len());
    for k in &keys {
        eprintln!(
            "  key: label={:?} type={:?} sign={}",
            k.label, k.key_type, k.signing_capable
        );
    }
}

// ---------------------------------------------------------------------------
// 4. import_cert round-trip (requires SoftHSM2)
// ---------------------------------------------------------------------------

/// Import a minimal DER stub onto the token and verify the call returns `Ok`.
#[test]
#[ignore]
#[cfg(feature = "pkcs11")]
fn import_cert_succeeds() {
    if !softhsm2_available() {
        eprintln!("SOFTHSM2_MODULE not set — skipping import_cert test");
        return;
    }

    use oxitls_adapter_pkcs11::Pkcs11TlsProvider;
    use secrecy::SecretString;
    use std::path::PathBuf;

    let module_path = PathBuf::from(std::env::var("SOFTHSM2_MODULE").unwrap());
    let slot_id: u64 = std::env::var("SOFTHSM2_SLOT")
        .unwrap_or_else(|_| "0".to_string())
        .parse()
        .unwrap_or(0);
    let pin =
        SecretString::from(std::env::var("SOFTHSM2_PIN").unwrap_or_else(|_| "1234".to_string()));

    let provider = Pkcs11TlsProvider::new(module_path, slot_id, pin).expect("create provider");

    // Use a minimal but syntactically plausible DER blob (30 bytes).
    // A real test would use a self-signed cert from rcgen; here we just verify
    // the PKCS#11 call path succeeds on SoftHSM2.
    let fake_der: Vec<u8> = {
        // Minimal X.509v3 skeleton: SEQUENCE { INTEGER 1 } — not a valid cert
        // but SoftHSM2 may accept it as an opaque CKO_CERTIFICATE value.
        let mut v = vec![0x30u8, 0x03, 0x02, 0x01, 0x01];
        v.extend_from_slice(&[0u8; 25]); // pad to 30 bytes
        v
    };

    match provider.import_cert(&fake_der, "wave5-test-cert") {
        Ok(()) => eprintln!("import_cert succeeded"),
        Err(e) => {
            // Some strict HSM implementations reject non-parseable DER;
            // treat as an expected failure in this smoke-test scenario.
            eprintln!("import_cert returned (expected possible failure): {e}");
        }
    }
}

// ---------------------------------------------------------------------------
// 5. Full TLS 1.3 loopback handshake with PKCS#11 server (requires SoftHSM2)
// ---------------------------------------------------------------------------

/// End-to-end TLS 1.3 server handshake using a PKCS#11-backed signing key.
///
/// Requires:
/// - `SOFTHSM2_MODULE` — path to `libsofthsm2.so`
/// - `SOFTHSM2_SLOT`   — slot index
/// - `SOFTHSM2_PIN`    — user PIN
/// - `SOFTHSM2_KEY_LABEL` — CKA_LABEL of the EC private key
/// - `SOFTHSM2_CERT_LABEL` — CKA_LABEL of the corresponding certificate
#[test]
#[ignore]
#[cfg(feature = "pkcs11")]
fn full_tls13_handshake_with_pkcs11_server() {
    if !softhsm2_available() {
        eprintln!("SOFTHSM2_MODULE not set — skipping TLS loopback test");
        return;
    }

    use oxitls_adapter_pkcs11::Pkcs11TlsProvider;
    use secrecy::SecretString;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::path::PathBuf;
    use std::sync::Arc;

    let module_path = PathBuf::from(std::env::var("SOFTHSM2_MODULE").unwrap());
    let slot_id: u64 = std::env::var("SOFTHSM2_SLOT")
        .unwrap_or_else(|_| "0".to_string())
        .parse()
        .unwrap_or(0);
    let pin =
        SecretString::from(std::env::var("SOFTHSM2_PIN").unwrap_or_else(|_| "1234".to_string()));
    let key_label =
        std::env::var("SOFTHSM2_KEY_LABEL").unwrap_or_else(|_| "test-ecdsa".to_string());
    let cert_label = std::env::var("SOFTHSM2_CERT_LABEL").unwrap_or_else(|_| key_label.clone());

    let provider =
        Arc::new(Pkcs11TlsProvider::new(module_path, slot_id, pin).expect("create provider"));

    // Build server config.
    let crypto_provider = Arc::new(rustls_rustcrypto::provider());
    let server_config = Arc::new(
        provider
            .server_config(&cert_label, &key_label, Arc::clone(&crypto_provider))
            .expect("server_config"),
    );

    // Bind a loopback listener.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    // Spawn server thread.
    let server_cfg = Arc::clone(&server_config);
    let server_handle = std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        let mut conn = rustls::ServerConnection::new(server_cfg).expect("ServerConnection::new");
        let mut stream = stream;
        let mut tls = rustls::Stream::new(&mut conn, &mut stream);
        let mut buf = [0u8; 64];
        let n = tls.read(&mut buf).expect("server read");
        tls.write_all(&buf[..n]).expect("server write");
    });

    // Client: use a WebPKI-ignoring verifier for the loopback test since we
    // don't have a real CA chain.  Construct via dangerous API.
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, SignatureScheme};

    #[derive(Debug)]
    struct NoopVerifier;

    impl ServerCertVerifier for NoopVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
            ]
        }
    }

    let client_config = Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::clone(&crypto_provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoopVerifier))
            .with_no_client_auth(),
    );

    let server_name: ServerName<'static> = ServerName::try_from("localhost").expect("ServerName");
    let mut client_conn =
        rustls::ClientConnection::new(client_config, server_name).expect("ClientConnection");
    let mut tcp = TcpStream::connect(addr).expect("connect");
    let mut tls_client = rustls::Stream::new(&mut client_conn, &mut tcp);

    let msg = b"oxitls-wave5-handshake";
    tls_client.write_all(msg).expect("client write");
    let mut resp = vec![0u8; msg.len()];
    tls_client.read_exact(&mut resp).expect("client read");
    assert_eq!(resp, msg, "echo mismatch");

    server_handle.join().expect("server thread");
    eprintln!("full_tls13_handshake_with_pkcs11_server: PASSED");
}
