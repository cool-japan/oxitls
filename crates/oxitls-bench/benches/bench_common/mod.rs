//! Shared fixtures and helpers for oxitls benchmark binaries.
//!
//! Each bench binary includes this via `mod bench_common;`.  The module is
//! NOT a benchmark target itself (only top-level `benches/*.rs` files become
//! criterion binaries).

#![allow(dead_code)]

use std::sync::{Arc, OnceLock};

use rustls::{ClientConfig, ServerConfig};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

// ── Cert fixture ─────────────────────────────────────────────────────────────

/// A pre-generated cert/key pair that can be reused across benchmark iterations.
///
/// Stored in a `OnceLock` so the (potentially slow) key-gen step only happens
/// once per benchmark binary process.
pub struct CertFixture {
    /// DER-encoded leaf (server) certificate.
    pub leaf_cert_der: CertificateDer<'static>,
    /// PKCS#8 DER private key matching `leaf_cert_der`.
    pub leaf_key_der: PrivateKeyDer<'static>,
    /// Root store that trusts `leaf_cert_der` directly (self-signed).
    pub root_store: rustls::RootCertStore,
}

static CERT_FIXTURE: OnceLock<CertFixture> = OnceLock::new();

/// Return (or initialise) the global `CertFixture`.
///
/// Uses Ed25519 for fast key generation in benchmark setup.
pub fn cert_fixture() -> &'static CertFixture {
    CERT_FIXTURE.get_or_init(|| {
        let ck = oxitls_rcgen::generate_self_signed_ed25519(&["localhost"])
            .expect("bench fixture: cert gen failed");
        let leaf_cert_der = CertificateDer::from(ck.cert_der.clone());
        let leaf_key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.pkcs8_der.clone()));
        let mut root_store = rustls::RootCertStore::empty();
        root_store
            .add(leaf_cert_der.clone())
            .expect("bench fixture: add root failed");
        CertFixture {
            leaf_cert_der,
            leaf_key_der,
            root_store,
        }
    })
}

// ── Provider helpers ─────────────────────────────────────────────────────────

/// Pure-Rust (RustCrypto) crypto provider.
pub fn pure_crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    oxitls_adapter_rustls_rustcrypto::pure_provider()
}

// NOTE: ring and aws-lc-rs are available as dev-dependencies for AEAD-level
// comparisons (see aead.rs), but they cannot serve as rustls CryptoProviders
// here because that requires enabling rustls' `ring` / `aws_lc_rs` features,
// which would change the feature profile of the entire workspace.  TLS handshake
// benchmarks therefore use only the pure-Rust provider.

// ── Config helpers ───────────────────────────────────────────────────────────

/// Build a TLS 1.3-only `ClientConfig` trusting `root_store`.
pub fn make_client_config(
    provider: Arc<rustls::crypto::CryptoProvider>,
    root_store: rustls::RootCertStore,
) -> ClientConfig {
    ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_root_certificates(root_store)
        .with_no_client_auth()
}

/// Build a `ClientConfig` restricted to the given protocol versions.
pub fn make_client_config_with_versions(
    provider: Arc<rustls::crypto::CryptoProvider>,
    root_store: rustls::RootCertStore,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> ClientConfig {
    ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .expect("protocol versions")
        .with_root_certificates(root_store)
        .with_no_client_auth()
}

/// Build a `ServerConfig` with a single leaf certificate.
pub fn make_server_config(
    provider: Arc<rustls::crypto::CryptoProvider>,
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> ServerConfig {
    ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("server config")
}

/// Build a `ServerConfig` restricted to the given protocol versions.
pub fn make_server_config_with_versions(
    provider: Arc<rustls::crypto::CryptoProvider>,
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> ServerConfig {
    ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("server config")
}

// ── In-process synchronous TLS handshake ─────────────────────────────────────

/// Drive a full TLS handshake in-process over an in-memory transport.
///
/// Returns `(ClientConnection, ServerConnection)` after both sides have
/// completed the handshake exchange.  Uses plain `Vec<u8>` buffers as
/// the "network" layer — no sockets required.
///
/// Panics if the handshake does not complete within 20 read/write rounds.
pub fn sync_handshake(
    client_cfg: Arc<ClientConfig>,
    server_cfg: Arc<ServerConfig>,
    server_name: &str,
) -> (rustls::ClientConnection, rustls::ServerConnection) {
    use rustls::{ClientConnection, ServerConnection};
    use rustls_pki_types::ServerName;

    let server_name: ServerName<'static> = ServerName::try_from(server_name.to_string())
        .expect("valid server name")
        .to_owned();

    let mut client = ClientConnection::new(client_cfg, server_name).expect("client connection");
    let mut server = ServerConnection::new(server_cfg).expect("server connection");

    let mut rounds = 0u32;
    loop {
        rounds += 1;
        if rounds > 20 {
            panic!("sync_handshake: did not complete after 20 rounds");
        }

        let mut buf = Vec::with_capacity(16 * 1024);

        if client.wants_write() {
            client.write_tls(&mut buf).expect("client write_tls");
            let mut slice = buf.as_slice();
            server.read_tls(&mut slice).expect("server read_tls");
            server
                .process_new_packets()
                .expect("server process_new_packets");
            buf.clear();
        }

        if server.wants_write() {
            server.write_tls(&mut buf).expect("server write_tls");
            let mut slice = buf.as_slice();
            client.read_tls(&mut slice).expect("client read_tls");
            client
                .process_new_packets()
                .expect("client process_new_packets");
            buf.clear();
        }

        if !client.is_handshaking() && !server.is_handshaking() {
            break;
        }
    }

    (client, server)
}

/// Send `data` from client to server through an already-completed TLS session.
///
/// Interleaves TLS record writes and reads to avoid deadlock on large payloads.
/// Returns the decrypted bytes received by the server.
pub fn tls_send_client_to_server(
    client: &mut rustls::ClientConnection,
    server: &mut rustls::ServerConnection,
    data: &[u8],
) -> Vec<u8> {
    use std::io::Write;

    // Write application data into the client.
    {
        let mut writer = client.writer();
        writer.write_all(data).expect("client writer write_all");
    }

    // Flush TLS records client → server.
    let mut record_buf = Vec::with_capacity(18 * 1024);
    while client.wants_write() {
        client.write_tls(&mut record_buf).expect("client write_tls");
        let mut slice = record_buf.as_slice();
        server.read_tls(&mut slice).expect("server read_tls");
        server
            .process_new_packets()
            .expect("server process_new_packets");
        record_buf.clear();
    }

    // Drain decrypted data from the server.
    let mut received = Vec::with_capacity(data.len());
    {
        let mut reader = server.reader();
        let mut tmp = [0u8; 16 * 1024];
        loop {
            match std::io::Read::read(&mut reader, &mut tmp) {
                Ok(0) => break,
                Ok(n) => received.extend_from_slice(&tmp[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("server reader error: {e}"),
            }
        }
    }
    received
}
