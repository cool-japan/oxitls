//! Integration tests for `OxiTicketer` — server-side session-ticket resumption
//! backed by AES-256-GCM.
//!
//! Tests cover:
//! 1. Encrypt → decrypt round-trip.
//! 2. Tampered ciphertext → `None`.
//! 3. Key rotation: old ticket still decryptable with previous key.
//! 4. Lifetime accessor.
//! 5. Wire into a live TLS handshake via `ServerBuilder::with_ticketer`.
//! 6. 2nd connection reuses a cached session ticket (resumed handshake).

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use oxitls::ticketer::OxiTicketer;
use oxitls::tls13::ServerBuilder;
use oxitls_rcgen::generate_self_signed_ed25519;
use rustls::server::ProducesTickets;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

// ── Counting ticketer wrapper ─────────────────────────────────────────────────

/// Wraps `OxiTicketer` and counts `decrypt()` invocations so tests can assert
/// that a session ticket was actually resubmitted on a resumed connection.
#[derive(Debug)]
struct CountingTicketer {
    inner: OxiTicketer,
    decrypt_calls: AtomicU32,
}

impl CountingTicketer {
    fn new() -> Result<Self, oxitls::TlsError> {
        Ok(Self {
            inner: OxiTicketer::new()?,
            decrypt_calls: AtomicU32::new(0),
        })
    }

    fn decrypt_call_count(&self) -> u32 {
        self.decrypt_calls.load(Ordering::SeqCst)
    }
}

impl ProducesTickets for CountingTicketer {
    fn enabled(&self) -> bool {
        self.inner.enabled()
    }

    fn lifetime(&self) -> u32 {
        self.inner.lifetime()
    }

    fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>> {
        self.inner.encrypt(plain)
    }

    fn decrypt(&self, ticket: &[u8]) -> Option<Vec<u8>> {
        let result = self.inner.decrypt(ticket);
        if result.is_some() {
            self.decrypt_calls.fetch_add(1, Ordering::SeqCst);
        }
        result
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[test]
fn ticketer_enabled() {
    let t = OxiTicketer::new().expect("new ticketer");
    assert!(t.enabled());
}

#[test]
fn ticketer_default_lifetime() {
    let t = OxiTicketer::new().expect("new ticketer");
    assert_eq!(t.lifetime(), 6 * 60 * 60);
}

#[test]
fn ticketer_custom_lifetime() {
    let t = OxiTicketer::new_with_lifetime(3600).expect("new ticketer");
    assert_eq!(t.lifetime(), 3600);
}

#[test]
fn ticketer_encrypt_decrypt_roundtrip() {
    let t = OxiTicketer::new().expect("new ticketer");
    let plain = b"session state bytes";
    let enc = t.encrypt(plain).expect("encrypt must succeed");
    let dec = t.decrypt(&enc).expect("decrypt must succeed");
    assert_eq!(dec, plain);
}

#[test]
fn ticketer_tampered_ticket_rejected() {
    let t = OxiTicketer::new().expect("new ticketer");
    let plain = b"session state";
    let mut enc = t.encrypt(plain).expect("encrypt");
    // Flip the last byte of the ciphertext (which overlaps the GCM tag).
    let last = enc.len() - 1;
    enc[last] ^= 0xff;
    let result = t.decrypt(&enc);
    assert!(result.is_none(), "tampered ticket must not decrypt");
}

#[test]
fn ticketer_wrong_version_byte_rejected() {
    let t = OxiTicketer::new().expect("new ticketer");
    let plain = b"data";
    let mut enc = t.encrypt(plain).expect("encrypt");
    // Corrupt the version byte.
    enc[0] ^= 0xff;
    let result = t.decrypt(&enc);
    assert!(result.is_none(), "wrong version byte must not decrypt");
}

#[test]
fn ticketer_too_short_ticket_rejected() {
    let t = OxiTicketer::new().expect("new ticketer");
    let result = t.decrypt(b"short");
    assert!(result.is_none(), "short ticket must not decrypt");
}

#[test]
fn ticketer_key_rotation_old_ticket_still_decryptable() {
    let t = OxiTicketer::new().expect("new ticketer");
    let plain = b"old session";
    let enc_before_rotate = t.encrypt(plain).expect("encrypt");

    // Rotate: current → previous, new current generated.
    t.rotate().expect("rotate");

    // Ticket encrypted before rotation should still decrypt via previous key.
    let dec = t
        .decrypt(&enc_before_rotate)
        .expect("old ticket must still decrypt after rotation");
    assert_eq!(dec, plain, "decrypted data must match original");
}

#[test]
fn ticketer_new_ticket_after_rotation_decryptable() {
    let t = OxiTicketer::new().expect("new ticketer");
    t.rotate().expect("rotate");
    let plain = b"new session after rotate";
    let enc = t.encrypt(plain).expect("encrypt after rotate");
    let dec = t.decrypt(&enc).expect("decrypt new ticket after rotate");
    assert_eq!(dec, plain);
}

#[test]
fn ticketer_double_rotation_pre_rotate_ticket_rejected() {
    let t = OxiTicketer::new().expect("new ticketer");
    let plain = b"very old session";
    let enc_very_old = t.encrypt(plain).expect("encrypt");

    t.rotate().expect("first rotate");
    t.rotate().expect("second rotate");

    // After two rotations the very-old key is completely gone.
    let result = t.decrypt(&enc_very_old);
    assert!(
        result.is_none(),
        "ticket from two rotations ago must no longer decrypt"
    );
}

// ── Live handshake test ───────────────────────────────────────────────────────

#[tokio::test]
async fn ticketer_wired_into_server_config() {
    // Generate a self-signed cert via oxitls-rcgen (no ring).
    let ck = generate_self_signed_ed25519(&["localhost"]).expect("cert gen");
    let cert_der = CertificateDer::from(ck.cert_der.clone());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.pkcs8_der.clone()));

    let ticketer = Arc::new(OxiTicketer::new().expect("ticketer"));

    let server_cfg = ServerBuilder::new()
        .with_der_cert_and_key(vec![cert_der.clone()], key_der)
        .with_ticketer(ticketer)
        .build()
        .expect("server config");

    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local addr");

    let server_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept");
        let mut tls = acceptor.accept(tcp).await.expect("tls accept");
        // Echo one byte back.
        let mut buf = [0u8; 1];
        tls.read_exact(&mut buf).await.expect("server read");
        tls.write_all(&buf).await.expect("server write");
        tls.flush().await.expect("flush");
    });

    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(cert_der).expect("add root cert");

    let provider = oxitls_adapter_rustls_rustcrypto::pure_provider();
    let client_cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("version config")
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(client_cfg));
    let domain = ServerName::try_from("localhost")
        .expect("valid server name")
        .to_owned();

    let stream = TcpStream::connect(addr).await.expect("tcp connect");
    let mut tls = connector
        .connect(domain, stream)
        .await
        .expect("tls connect");

    tls.write_all(&[0x55]).await.expect("client write");
    tls.flush().await.expect("flush");
    let mut reply = [0u8; 1];
    tls.read_exact(&mut reply).await.expect("client read");
    assert_eq!(reply[0], 0x55);

    server_task.await.expect("server task");
}

// ── 2nd-connection resumption test ───────────────────────────────────────────

#[tokio::test]
async fn second_connection_resumes_via_ticket() {
    // ── Setup ────────────────────────────────────────────────────────────────
    let ck = generate_self_signed_ed25519(&["localhost"]).expect("cert gen");
    let cert_der = CertificateDer::from(ck.cert_der.clone());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.pkcs8_der.clone()));

    // Use CountingTicketer to observe decrypt() calls on the 2nd connection.
    let ticketer = Arc::new(CountingTicketer::new().expect("counting ticketer"));
    let ticketer_ref = Arc::clone(&ticketer);

    let server_cfg = ServerBuilder::new()
        .with_der_cert_and_key(vec![cert_der.clone()], key_der)
        .with_ticketer(ticketer_ref)
        .build()
        .expect("server config");

    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));

    // Build a client config with an in-memory session store so the TLS 1.3
    // session ticket issued in the 1st handshake is cached and resubmitted on
    // the 2nd.
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(cert_der).expect("add root cert");

    let provider = oxitls_adapter_rustls_rustcrypto::pure_provider();
    let client_cfg = Arc::new(
        rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("version config")
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    );

    let domain = ServerName::try_from("localhost")
        .expect("valid domain")
        .to_owned();

    // ── First connection — full handshake, server issues a ticket ────────────
    {
        // Bind listener for first connection.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let server_task = {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let (tcp, _) = listener.accept().await.expect("accept");
                let mut tls = acceptor.accept(tcp).await.expect("tls accept");
                let mut buf = [0u8; 1];
                tls.read_exact(&mut buf).await.expect("server read");
                tls.write_all(&buf).await.expect("server write");
                tls.flush().await.expect("flush");
            })
        };

        let tcp = TcpStream::connect(addr).await.expect("tcp connect");
        let connector = TlsConnector::from(Arc::clone(&client_cfg));
        let mut tls = connector
            .connect(domain.clone(), tcp)
            .await
            .expect("1st connect");

        tls.write_all(&[0x01]).await.expect("client write");
        tls.flush().await.expect("flush");
        let mut reply = [0u8; 1];
        tls.read_exact(&mut reply).await.expect("client read");
        assert_eq!(reply[0], 0x01);

        server_task.await.expect("server task 1");

        // Drop tls to give rustls a chance to flush post-handshake messages
        // (NewSessionTicket) into the session store before the connection closes.
        drop(tls);
    }

    // Give the runtime a tick so any lingering post-handshake I/O finishes.
    tokio::task::yield_now().await;

    // Decrypt counter must still be 0 after the first (full) handshake.
    assert_eq!(
        ticketer.decrypt_call_count(),
        0,
        "first connection must not call decrypt()"
    );

    // ── Second connection — should reuse the cached session ticket ────────────
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind 2");
        let addr = listener.local_addr().expect("local addr 2");

        let server_task = {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let (tcp, _) = listener.accept().await.expect("accept");
                let mut tls = acceptor.accept(tcp).await.expect("tls accept");
                let mut buf = [0u8; 1];
                tls.read_exact(&mut buf).await.expect("server read");
                tls.write_all(&buf).await.expect("server write");
                tls.flush().await.expect("flush");
            })
        };

        let tcp = TcpStream::connect(addr).await.expect("tcp connect 2");
        let connector = TlsConnector::from(Arc::clone(&client_cfg));
        let mut tls = connector
            .connect(domain.clone(), tcp)
            .await
            .expect("2nd connect");

        tls.write_all(&[0x02]).await.expect("client write 2");
        tls.flush().await.expect("flush 2");
        let mut reply = [0u8; 1];
        tls.read_exact(&mut reply).await.expect("client read 2");
        assert_eq!(reply[0], 0x02);

        server_task.await.expect("server task 2");
        drop(tls);
    }

    tokio::task::yield_now().await;

    // The 2nd connection should have caused decrypt() to be called at least once.
    assert!(
        ticketer.decrypt_call_count() >= 1,
        "second connection must call decrypt() at least once (session ticket resumption); \
         got {} decrypt calls",
        ticketer.decrypt_call_count()
    );
}
