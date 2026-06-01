//! Post-quantum hybrid KEX integration tests.
//!
//! These tests validate the X25519MLKEM768 implementation end-to-end.
//! All tests are gated on the `post-quantum` feature.

#![cfg(feature = "post-quantum")]

use oxitls_adapter_rustls_rustcrypto::{pure_provider_with_pq, X25519MLKEM768};

// ── Constants matching the wire layout ───────────────────────────────────────

const CLIENT_SHARE_LEN: usize = 1216; // 1184 (ML-KEM encap key) + 32 (X25519)
const SERVER_SHARE_LEN: usize = 1120; // 1088 (ML-KEM ciphertext) + 32 (X25519)
const SHARED_SECRET_LEN: usize = 64; // 32 (ML-KEM ss) + 32 (X25519 ss)

// ── Unit tests ────────────────────────────────────────────────────────────────

/// Verify that the client and server key shares have the expected wire lengths.
#[test]
fn hybrid_share_sizes() {
    // Client: start() produces a CLIENT_SHARE_LEN pub key.
    let client_kx = X25519MLKEM768.start().expect("start() should not fail");
    assert_eq!(
        client_kx.pub_key().len(),
        CLIENT_SHARE_LEN,
        "client key share should be {CLIENT_SHARE_LEN} bytes"
    );

    // Server: start_and_complete(client_share) produces SERVER_SHARE_LEN pub key
    // and a SHARED_SECRET_LEN shared secret.
    let client_pub = client_kx.pub_key().to_vec();
    let completed = X25519MLKEM768
        .start_and_complete(&client_pub)
        .expect("start_and_complete() should not fail");
    assert_eq!(
        completed.pub_key.len(),
        SERVER_SHARE_LEN,
        "server key share should be {SERVER_SHARE_LEN} bytes"
    );
    assert_eq!(
        completed.secret.secret_bytes().len(),
        SHARED_SECRET_LEN,
        "shared secret should be {SHARED_SECRET_LEN} bytes"
    );
}

/// Verify that the client and server derive the same shared secret.
#[test]
fn hybrid_kex_roundtrip_secrets_match() {
    // Client generates its key share.
    let client_kx = X25519MLKEM768.start().expect("client start() failed");
    let client_pub = client_kx.pub_key().to_vec();

    // Server encapsulates and returns its share.
    let server_result = X25519MLKEM768
        .start_and_complete(&client_pub)
        .expect("server start_and_complete() failed");
    let server_pub = server_result.pub_key.clone();
    let server_secret = server_result.secret.secret_bytes().to_vec();

    // Client completes using the server's share.
    let client_secret = client_kx
        .complete(&server_pub)
        .expect("client complete() failed");

    assert_eq!(
        client_secret.secret_bytes().len(),
        SHARED_SECRET_LEN,
        "client secret length mismatch"
    );
    assert_eq!(
        server_secret.len(),
        SHARED_SECRET_LEN,
        "server secret length mismatch"
    );
    assert_eq!(
        client_secret.secret_bytes(),
        server_secret.as_slice(),
        "client and server shared secrets must match"
    );
}

/// Verify that a truncated peer share is rejected with an error.
#[test]
fn hybrid_rejects_truncated_peer_share() {
    let truncated = vec![0u8; 100];
    let result = X25519MLKEM768.start_and_complete(&truncated);
    assert!(
        result.is_err(),
        "start_and_complete() with 100-byte input should return Err"
    );
}

/// Verify that an empty peer share is rejected.
#[test]
fn hybrid_rejects_empty_peer_share() {
    let result = X25519MLKEM768.start_and_complete(&[]);
    assert!(
        result.is_err(),
        "start_and_complete() with empty input should return Err"
    );
}

/// Verify that X25519MLKEM768 is only offered for TLS 1.3.
#[test]
fn hybrid_only_for_tls13() {
    assert!(
        X25519MLKEM768.usable_for_version(rustls::ProtocolVersion::TLSv1_3),
        "X25519MLKEM768 should be usable for TLSv1_3"
    );
    assert!(
        !X25519MLKEM768.usable_for_version(rustls::ProtocolVersion::TLSv1_2),
        "X25519MLKEM768 should not be usable for TLSv1_2"
    );
}

/// Full TLS 1.3 loopback handshake using pure_provider_with_pq().
///
/// This test sets up a TCP loopback with the PQ provider on both client and
/// server, performs a TLS 1.3 handshake, and asserts that it completes
/// successfully.  Because X25519MLKEM768 is at index 0 in the provider's
/// kx_groups, it will be the preferred group — verifiable via the
/// `negotiated_key_exchange_group()` API.
#[tokio::test]
async fn full_tls13_handshake_negotiates_hybrid() {
    use oxitls_adapter_rustls_rustcrypto::{RustcryptoAcceptor, RustcryptoConnector};
    use oxitls_rcgen::generate_self_signed_p256;
    use rustls::{ClientConfig, RootCertStore, ServerConfig};
    use rustls_pki_types::{PrivatePkcs8KeyDer, ServerName};
    use std::sync::Arc;
    use tokio::net::{TcpListener, TcpStream};

    // Generate a self-signed P-256 cert for localhost (pure Rust, no ring).
    let ck = generate_self_signed_p256(&["localhost"]).expect("cert gen failed");

    let cert_der = rustls_pki_types::CertificateDer::from(ck.cert_der.clone());
    let key_der =
        rustls_pki_types::PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.pkcs8_der.clone()));

    // PQ provider for both sides.
    let provider = pure_provider_with_pq();

    // Build server config.
    let srv_cfg = ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("protocol version selection failed")
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .expect("server cert config failed");

    // Build client config.
    let mut root_store = RootCertStore::empty();
    root_store.add(cert_der).expect("add cert failed");
    let cli_cfg = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("protocol version selection failed")
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // Bind ephemeral port.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind failed");
    let port = listener.local_addr().expect("local_addr").port();

    let acceptor = RustcryptoAcceptor::new(Arc::new(srv_cfg));
    let connector = RustcryptoConnector::new(Arc::new(cli_cfg));

    // Server task.
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept tcp failed");
        let tls = acceptor.accept(stream).await.expect("tls accept failed");
        // Check the negotiated group on the server side.
        let (_, server_conn) = tls.get_ref();
        let negotiated = server_conn.negotiated_key_exchange_group();
        assert!(
            negotiated.is_some(),
            "server should have a negotiated key exchange group"
        );
        // The negotiated group should be X25519MLKEM768 (0x11ec).
        if let Some(group) = negotiated {
            assert_eq!(
                group.name(),
                rustls::NamedGroup::X25519MLKEM768,
                "server should negotiate X25519MLKEM768"
            );
        }
        tokio::io::copy(&mut { tls }, &mut tokio::io::sink())
            .await
            .ok();
    });

    // Client connects.
    let tcp = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("tcp connect failed");
    let server_name = ServerName::try_from("localhost")
        .expect("server name parse")
        .to_owned();
    let tls_stream = connector
        .connect(server_name, tcp)
        .await
        .expect("tls connect failed");

    // Verify the negotiated group on the client side.
    let (_, client_conn) = tls_stream.get_ref();
    let negotiated = client_conn.negotiated_key_exchange_group();
    assert!(
        negotiated.is_some(),
        "client should have a negotiated key exchange group"
    );
    if let Some(group) = negotiated {
        assert_eq!(
            group.name(),
            rustls::NamedGroup::X25519MLKEM768,
            "client should negotiate X25519MLKEM768"
        );
    }

    server.abort();
}
