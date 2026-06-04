//! Wave 14: RFC 8879 TLS certificate compression tests.
//!
//! Cert compression is TLS 1.3 only; rustls ignores it for TLS 1.2.

#![cfg(feature = "cert-compression")]

use oxitls_adapter_rustls_rustcrypto::cert_compression::{
    OxiArcZlibCompressor, OxiArcZlibDecompressor,
};
use rustls::compress::{CertCompressor, CertDecompressor, CompressionLevel};

// ── Unit tests ────────────────────────────────────────────────────────────────

/// Round-trip compress/decompress at Interactive level.
#[test]
fn zlib_roundtrip_interactive() {
    let data = b"This is a fake certificate chain for testing. ".repeat(100);
    let compressed = OxiArcZlibCompressor
        .compress(data.to_vec(), CompressionLevel::Interactive)
        .expect("compress");
    assert!(
        compressed.len() < data.len(),
        "compressed should be shorter"
    );
    let mut recovered = vec![0u8; data.len()];
    OxiArcZlibDecompressor
        .decompress(&compressed, &mut recovered)
        .expect("decompress");
    assert_eq!(recovered.as_slice(), data.as_slice());
}

/// Round-trip compress/decompress at Amortized level.
#[test]
fn zlib_roundtrip_amortized() {
    let data = b"Certificate data for amortized compression test. ".repeat(50);
    let compressed = OxiArcZlibCompressor
        .compress(data.to_vec(), CompressionLevel::Amortized)
        .expect("compress");
    let mut recovered = vec![0u8; data.len()];
    OxiArcZlibDecompressor
        .decompress(&compressed, &mut recovered)
        .expect("decompress");
    assert_eq!(recovered.as_slice(), data.as_slice());
}

/// Length mismatch is rejected with DecompressionFailed.
#[test]
fn zlib_length_mismatch_rejected() {
    let data = b"Some data".repeat(10);
    let compressed = OxiArcZlibCompressor
        .compress(data.to_vec(), CompressionLevel::Interactive)
        .expect("compress");
    // Pre-allocate the WRONG size (off by one).
    let mut wrong = vec![0u8; data.len() + 1];
    let result = OxiArcZlibDecompressor.decompress(&compressed, &mut wrong);
    assert!(result.is_err(), "should reject length mismatch");
}

/// Garbage input is rejected.
#[test]
fn zlib_garbage_input_rejected() {
    let mut output = vec![0u8; 100];
    let result = OxiArcZlibDecompressor.decompress(b"not zlib data", &mut output);
    assert!(result.is_err(), "should reject garbage input");
}

/// Verify the compressor/decompressor report CertificateCompressionAlgorithm::Zlib.
#[test]
fn algorithm_is_zlib() {
    use rustls::CertificateCompressionAlgorithm;
    assert_eq!(
        OxiArcZlibCompressor.algorithm(),
        CertificateCompressionAlgorithm::Zlib
    );
    assert_eq!(
        OxiArcZlibDecompressor.algorithm(),
        CertificateCompressionAlgorithm::Zlib
    );
}

// ── Integration test: TLS 1.3 loopback with cert compression on both sides ───

use std::sync::Arc;

use rcgen::{CertificateParams, KeyPair};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use oxitls::tls13::{ClientBuilder, ServerBuilder};

/// Generate a self-signed certificate with SAN `localhost` via rcgen/ring.
fn make_self_signed() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let kp = KeyPair::generate().expect("keygen failed");
    let cert = CertificateParams::new(vec!["localhost".to_string()])
        .expect("cert params")
        .self_signed(&kp)
        .expect("self-sign failed");
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(kp.serialize_der().into());
    (cert_der, key_der)
}

/// Spawn a one-shot TLS echo server with cert compression enabled.
async fn spawn_echo_server(
    cfg: rustls::ServerConfig,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener bind");
    let addr = listener.local_addr().expect("local addr");
    let handle = tokio::spawn(async move {
        if let Ok((tcp, _)) = listener.accept().await {
            if let Ok(mut tls) = acceptor.accept(tcp).await {
                let mut buf = [0u8; 1];
                let _ = tls.read_exact(&mut buf).await;
                let _ = tls.write_all(&buf).await;
                let _ = tls.flush().await;
            }
        }
    });
    (addr, handle)
}

/// TLS 1.3 loopback handshake with cert compression enabled on both client and server.
///
/// Verifies that a round-trip with `with_cert_compression()` on both sides succeeds
/// and data is transferred correctly.
#[tokio::test]
async fn tls13_cert_compression_loopback() {
    let (cert_der, key_der) = make_self_signed();

    let server_cfg = ServerBuilder::new()
        .with_der_cert_and_key(vec![cert_der.clone()], key_der)
        .with_cert_compression()
        .build()
        .expect("server config");

    let (addr, server_handle) = spawn_echo_server(server_cfg).await;

    let client_cfg = ClientBuilder::new()
        .with_trusted_cert_der(cert_der.to_vec())
        .expect("trust cert")
        .with_cert_compression()
        .build()
        .expect("client config");

    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_cfg));
    let tcp = TcpStream::connect(addr).await.expect("tcp connect");
    let server_name = rustls_pki_types::ServerName::try_from("localhost")
        .expect("server name")
        .to_owned();

    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .expect("TLS handshake with cert compression");

    tls.write_all(b"x").await.expect("write");
    tls.flush().await.expect("flush");

    let mut buf = [0u8; 1];
    tls.read_exact(&mut buf).await.expect("read");
    assert_eq!(buf, *b"x");

    server_handle.await.expect("server task");
}
