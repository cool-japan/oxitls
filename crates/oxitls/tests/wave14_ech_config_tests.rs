//! Wave 14: ECHConfigList generation tests.
//!
//! Tests cover the Enable path for ECH (real config, not GREASE). A full
//! EchStatus::Accepted end-to-end test is not included because rustls 0.23.40
//! does not provide a server-side ECH acceptor; that path requires either an
//! external ECH-capable server or a future rustls version with ECH server support.

#![cfg(feature = "ech")]

use oxitls::{generate_ech_config_list, tls13::ClientBuilder};
use oxitls_adapter_rustls_rustcrypto::pure_hpke_suites;

/// A self-generated ECHConfig is accepted by the oxitls ClientBuilder (Enable mode).
#[test]
fn ech_generated_config_accepted_by_builder() {
    let suite = pure_hpke_suites()[0]; // X25519/HKDF-SHA256/AES-128-GCM
    let cfg = generate_ech_config_list(suite, 0, "public.example.com", 0)
        .expect("generate_ech_config_list should succeed");

    // The minted bytes must be accepted as a valid ECHConfigList.
    let result = ClientBuilder::new().with_ech_config_list(cfg.config_list);
    assert!(
        result.is_ok(),
        "with_ech_config_list rejected a self-minted config: {:?}",
        result.err()
    );
}

/// The generated config parses back correctly — field round-trip test.
#[test]
fn ech_generated_config_roundtrips() {
    use rustls::internal::msgs::codec::{Codec, Reader};
    use rustls::internal::msgs::handshake::EchConfigPayload;

    let suite = pure_hpke_suites()[0];
    let cfg = generate_ech_config_list(suite, 42, "roundtrip.example.com", 128).expect("generate");

    // Skip the outer 2-byte list length prefix, then parse one ECHConfig.
    assert!(cfg.config_list.len() > 2, "config_list too short");
    let inner = &cfg.config_list[2..]; // skip u16 list-length prefix
    let mut reader = Reader::init(inner);
    let payload = EchConfigPayload::read(&mut reader).expect("parse EchConfigPayload");

    match payload {
        EchConfigPayload::V18(contents) => {
            assert_eq!(
                contents.key_config.config_id, 42,
                "config_id must round-trip"
            );
            // Verify public key bytes are embedded: encode the key_config's public key field
            // and strip the 2-byte length prefix to get the raw bytes for comparison.
            let mut encoded_pk = Vec::new();
            contents.key_config.public_key.encode(&mut encoded_pk);
            // encoded_pk = [len_hi, len_lo, ...key_bytes...]
            let key_bytes = &encoded_pk[2..];
            assert_eq!(
                key_bytes,
                cfg.public_key.as_slice(),
                "public_key in config must match returned public_key"
            );
            assert_eq!(
                contents.public_name.as_ref(),
                "roundtrip.example.com",
                "public_name must round-trip"
            );
            assert_eq!(
                contents.maximum_name_length, 128,
                "maximum_name_length must round-trip"
            );
            assert_eq!(
                contents.key_config.symmetric_cipher_suites.len(),
                1,
                "expect exactly 1 cipher suite"
            );
        }
        other => panic!("unexpected EchConfigPayload variant: {:?}", other),
    }
}

/// Both X25519 and P-256 KEMs mint+parse successfully.
#[test]
fn ech_generated_config_x25519_and_p256() {
    for suite in pure_hpke_suites() {
        let cfg =
            generate_ech_config_list(*suite, 0, "example.com", 0).expect("generate for suite");
        let result = ClientBuilder::new().with_ech_config_list(cfg.config_list);
        assert!(
            result.is_ok(),
            "suite {:?} minted config rejected by builder",
            suite.suite()
        );
    }
}

/// Private key bytes are non-empty and non-zero (sanity check on key generation).
#[test]
fn ech_generated_config_private_key_not_trivial() {
    let suite = pure_hpke_suites()[0];
    let cfg = generate_ech_config_list(suite, 1, "pk.example.com", 0).expect("generate");
    assert!(!cfg.private_key.is_empty(), "private_key must be non-empty");
    assert!(
        cfg.private_key.iter().any(|&b| b != 0),
        "private_key must not be all zeros"
    );
    assert!(!cfg.public_key.is_empty(), "public_key must be non-empty");
    assert_eq!(cfg.config_id, 1);
}
