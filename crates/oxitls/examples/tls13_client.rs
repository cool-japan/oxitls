//! TLS 1.3 client example.
//!
//! Demonstrates the minimal `ClientBuilder` fluent API: trust a single
//! certificate (as issued by a real CA or, as here, a self-signed
//! development cert) and connect over TLS 1.3.
//!
//! This example is fully self-contained -- it starts its own loopback TLS
//! server (see `tls13_server.rs` for the same server logic as a standalone
//! example) so it can run with no external network access or setup:
//!
//! ```text
//! cargo run --example tls13_client
//! ```

use std::sync::Arc;

use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

use oxitls::tls13::{ClientBuilder, ServerBuilder};
use oxitls_rcgen::generate_self_signed_p256;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ── 1. Generate a development certificate (Pure Rust, no ring/OpenSSL) ──
    let certified_key = generate_self_signed_p256(&["localhost"])?;
    let cert_der = certified_key.cert_der.clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified_key.pkcs8_der));

    // ── 2. Start a minimal TLS 1.3 echo server on a loopback port ───────────
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
        let n = tls.read(&mut buf).await.expect("read request");
        // Echo the request back, prefixed, so the client can see a real
        // application-layer round trip over the encrypted channel.
        let reply = format!("echo: {}", String::from_utf8_lossy(&buf[..n]));
        tls.write_all(reply.as_bytes()).await.expect("write reply");
        tls.flush().await.expect("flush");
        tls.shutdown().await.expect("shutdown");
    });

    // ── 3. Build a TLS 1.3 client that trusts our development cert ──────────
    let client_cfg = ClientBuilder::new()
        .with_trusted_cert_der(cert_der)?
        .build()?;

    // ── 4. Connect and send a request over TLS ───────────────────────────────
    let connector = TlsConnector::from(Arc::new(client_cfg));
    let tcp = TcpStream::connect(addr).await?;
    let server_name = ServerName::try_from("localhost")?;
    let mut tls = connector.connect(server_name, tcp).await?;

    println!("TLS 1.3 handshake complete, connected to {addr}");

    tls.write_all(b"GET / HTTP/1.0 (oxitls example)\r\n")
        .await?;
    tls.flush().await?;

    let mut response = vec![0u8; 1024];
    let n = tls.read(&mut response).await?;
    println!(
        "Server response: {}",
        String::from_utf8_lossy(&response[..n])
    );

    Ok(())
}
