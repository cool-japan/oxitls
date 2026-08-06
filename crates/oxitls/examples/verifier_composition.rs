//! Layered `ServerCertVerifier` composition example.
//!
//! `OcspClientVerifier`, `SctVerifier`, and `CertPinVerifier` are all
//! decorators: each wraps an inner `rustls::client::danger::ServerCertVerifier`
//! and adds one more check before delegating trust-chain validation onward.
//! Composing them builds a verification pipeline:
//!
//! ```text
//! WebPkiServerVerifier (chain-of-trust)
//!   -> CertPinVerifier        (leaf must match a pinned SHA-256 fingerprint)
//!   -> SctVerifier            (leaf must carry Certificate Transparency SCTs)
//!   -> OcspClientVerifier     (staple, if present, must be valid + fresh)
//! ```
//!
//! This is also the composition that would have surfaced the leaf-only-chain
//! OCSP bug fixed in this release (`OcspClientVerifier` no longer synthesises
//! a CA-signed end-entity as its own issuer): with no intermediates in the
//! chain, a stapled OCSP response now correctly falls back to a
//! policy-governed "unverifiable" outcome instead of an unconditional
//! signature-forgery rejection.
//!
//! ```text
//! cargo run --example verifier_composition
//! ```

use std::sync::Arc;

use rustls::client::danger::ServerCertVerifier;
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::ServerName;
use rustls::RootCertStore;
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

use oxitls::tls13::ServerBuilder;
use oxitls_adapter_rustls_rustcrypto::pure_provider;
use oxitls_adapter_rustls_rustcrypto::verifier::{
    CertPinVerifier, CtLogList, OcspClientPolicy, OcspClientVerifier, SctPolicy, SctVerifier,
};
use oxitls_rcgen::generate_self_signed_p256;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ── 1. Generate a development certificate and start a plain TLS 1.3 server ──
    // (No OCSP staple or embedded SCTs -- see the policy choices below for how
    // the composed verifier is configured to tolerate that in this demo.)
    let certified_key = generate_self_signed_p256(&["localhost"])?;
    let fingerprint = certified_key.fingerprint_sha256();
    let cert_der = certified_key.cert_der.clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified_key.pkcs8_der));

    let server_cfg = ServerBuilder::new()
        .with_der_cert_and_key(vec![cert_der.clone().into()], key_der)
        .build()?;
    let acceptor = oxitls::tls13::server::tokio_acceptor(server_cfg);

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept");
        let mut tls = acceptor.accept(tcp).await.expect("server-side handshake");
        let mut buf = vec![0u8; 1024];
        let n = tls.read(&mut buf).await.expect("read");
        tls.write_all(&buf[..n]).await.expect("echo");
        tls.flush().await.expect("flush");
        tls.shutdown().await.expect("shutdown");
    });

    // ── 2. Build the base chain-of-trust verifier (standard WebPKI) ─────────
    let mut roots = RootCertStore::empty();
    roots.add(cert_der.clone().into())?;
    let provider = pure_provider();
    let webpki_verifier: Arc<dyn ServerCertVerifier> =
        WebPkiServerVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&provider))
            .build()?;

    // ── 3. Layer 1: certificate pinning ──────────────────────────────────────
    // Only accept the leaf whose SHA-256 fingerprint matches exactly.
    let pin_verifier: Arc<dyn ServerCertVerifier> =
        Arc::new(CertPinVerifier::new(vec![fingerprint], webpki_verifier));

    // ── 4. Layer 2: Certificate Transparency (SCT) verification ─────────────
    // `Permissive` with an empty log list only warns on a missing/unverifiable
    // SCT list rather than rejecting the handshake -- appropriate here since
    // our development cert carries no embedded SCTs. A production deployment
    // would use `oxitls_adapter_rustls_rustcrypto::known_ct_logs().clone()`
    // and likely `SctPolicy::Strict` for a public-facing client.
    let sct_verifier: Arc<dyn ServerCertVerifier> = Arc::new(SctVerifier::new(
        pin_verifier,
        SctPolicy::Permissive {
            min_distinct_logs: 0,
        },
        CtLogList::empty(),
    ));

    // ── 5. Layer 3 (outermost): OCSP staple verification ────────────────────
    // `SoftFail` accepts the handshake when no staple is present (as here);
    // a `Revoked` status or a cryptographically invalid signature is always
    // rejected regardless of policy. `HardRequire` would additionally reject
    // a *missing* staple.
    let composed_verifier: Arc<dyn ServerCertVerifier> = Arc::new(OcspClientVerifier::new(
        sct_verifier,
        OcspClientPolicy::SoftFail,
    ));

    // ── 6. Wire the composed verifier into a real `ClientConfig` ────────────
    let client_cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(composed_verifier)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(client_cfg));
    let tcp = TcpStream::connect(addr).await?;
    let server_name = ServerName::try_from("localhost")?;
    let mut tls = connector.connect(server_name, tcp).await?;

    println!(
        "Handshake succeeded through the full composed verifier chain: \
         WebPKI -> CertPin -> SCT -> OCSP"
    );

    tls.write_all(b"composed verifier chain ok").await?;
    tls.flush().await?;
    let mut buf = vec![0u8; 1024];
    let n = tls.read(&mut buf).await?;
    println!("Echoed back: {}", String::from_utf8_lossy(&buf[..n]));

    Ok(())
}
