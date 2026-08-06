//! TLS 1.3 server example.
//!
//! Demonstrates the minimal `ServerBuilder` fluent API: load a certificate
//! and private key (here, a freshly generated self-signed development cert;
//! in production, load real PEM/DER material from disk via
//! `with_pem_cert_and_key`) and accept TLS 1.3 connections, echoing whatever
//! the client sends.
//!
//! Run standalone:
//!
//! ```text
//! cargo run --example tls13_server
//! ```
//!
//! It listens on an OS-assigned loopback port and prints both the address
//! and the certificate's SHA-256 fingerprint, then serves connections until
//! interrupted (Ctrl-C). See `tls13_client.rs` for a client that connects to
//! a server built the same way.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use oxitls::tls13::ServerBuilder;
use oxitls_rcgen::generate_self_signed_p256;
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ── 1. Generate a development certificate (Pure Rust, no ring/OpenSSL) ──
    let certified_key = generate_self_signed_p256(&["localhost"])?;
    let fingerprint = certified_key.fingerprint_sha256();
    let cert_der = certified_key.cert_der.clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified_key.pkcs8_der));

    // ── 2. Build the TLS 1.3 server config ───────────────────────────────────
    let server_cfg = ServerBuilder::new()
        .with_der_cert_and_key(vec![cert_der.into()], key_der)
        .build()?;
    let acceptor = oxitls::tls13::server::tokio_acceptor(server_cfg);

    // ── 3. Listen and accept connections ─────────────────────────────────────
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    println!("oxitls TLS 1.3 echo server listening on {addr}");
    println!("Certificate SHA-256 fingerprint: {}", hex(&fingerprint));
    println!("(Ctrl-C to stop; run the tls13_client example against this server)");

    loop {
        let (tcp, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let mut tls = match acceptor.accept(tcp).await {
                Ok(tls) => tls,
                Err(e) => {
                    eprintln!("handshake with {peer} failed: {e}");
                    return;
                }
            };
            let mut buf = vec![0u8; 4096];
            let n = match tls.read(&mut buf).await {
                Ok(n) => n,
                Err(e) => {
                    eprintln!("read from {peer} failed: {e}");
                    return;
                }
            };
            let reply = format!("echo: {}", String::from_utf8_lossy(&buf[..n]));
            if let Err(e) = tls.write_all(reply.as_bytes()).await {
                eprintln!("write to {peer} failed: {e}");
                return;
            }
            let _ = tls.flush().await;
            let _ = tls.shutdown().await;
        });
    }
}

/// Format a byte slice as lowercase hex (no external hex crate needed for a
/// one-line example helper).
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
