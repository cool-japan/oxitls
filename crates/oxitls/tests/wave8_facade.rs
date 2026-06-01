//! Facade integration tests: ticketer rotation + OCSP stapling smoke test.

#[cfg(feature = "pure")]
mod tests {
    use oxitls::ticketer::OxiTicketer;
    use rustls::server::ProducesTickets;

    #[test]
    fn ticketer_rotation_decrypt_with_previous_key() {
        let t = OxiTicketer::new().expect("OxiTicketer::new");
        let plaintext = b"session-data";

        // Encrypt before rotation.
        let ticket_before = t.encrypt(plaintext).expect("encrypt before rotate");

        // Rotate: current → previous, new current generated.
        t.rotate().expect("rotate");

        // Old ticket should still decrypt via the previous key.
        let decrypted = t.decrypt(&ticket_before);
        assert!(
            decrypted.is_some(),
            "ticket encrypted before rotation should decrypt via previous key"
        );
        assert_eq!(decrypted.unwrap(), plaintext);

        // New ticket (encrypted after rotation) should also decrypt.
        let ticket_after = t.encrypt(plaintext).expect("encrypt after rotate");
        let decrypted_after = t.decrypt(&ticket_after);
        assert!(decrypted_after.is_some());
    }

    #[test]
    fn ticketer_rotation_second_rotation_drops_original_key() {
        let t = OxiTicketer::new().expect("OxiTicketer::new");
        let plaintext = b"ephemeral";

        let ticket_gen0 = t.encrypt(plaintext).expect("encrypt gen0");
        t.rotate().expect("rotate to gen1"); // gen0 → previous, gen1 = current

        let can_decrypt_after_first_rotate = t.decrypt(&ticket_gen0).is_some();

        t.rotate().expect("rotate to gen2"); // gen1 → previous, gen2 = current; gen0 discarded

        let can_decrypt_after_second_rotate = t.decrypt(&ticket_gen0).is_some();

        assert!(
            can_decrypt_after_first_rotate,
            "gen0 should decrypt after one rotation (previous key)"
        );
        assert!(
            !can_decrypt_after_second_rotate,
            "gen0 should NOT decrypt after two rotations (key discarded)"
        );
    }

    #[test]
    fn server_builder_with_anti_replay_wires_replay_protection() {
        use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

        use oxitls::tls13::ServerBuilder;
        use oxitls_rcgen::generate_self_signed_ed25519;

        let ck = generate_self_signed_ed25519(&["localhost"]).expect("cert gen");
        let certs = vec![CertificateDer::from(ck.cert_der.clone())];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.pkcs8_der.clone()));

        // Build the server config with anti-replay enabled. The default OxiTicketer
        // is created internally and wrapped with AntiReplayTicketer.
        let server_cfg = ServerBuilder::new()
            .with_der_cert_and_key(certs, key)
            .with_anti_replay()
            .expect("with_anti_replay")
            .build()
            .expect("server build");

        // Verify that the installed ticketer enforces single-use semantics.
        let ticket = server_cfg
            .ticketer
            .encrypt(b"session-payload")
            .expect("encrypt via builder-wired ticketer");

        let first = server_cfg.ticketer.decrypt(&ticket);
        let replay = server_cfg.ticketer.decrypt(&ticket);

        assert!(
            first.is_some(),
            "first decrypt through builder-wired anti-replay ticketer must succeed"
        );
        assert!(
            replay.is_none(),
            "replay within window through builder-wired anti-replay ticketer must be blocked"
        );
    }

    #[test]
    fn ocsp_resolver_smoke_build() {
        use std::sync::Arc;

        use oxitls::tls13::{server::StaticOcspResolver, ServerBuilder};

        // A minimal DER-encoded OCSP response placeholder (ASN.1 SEQUENCE containing
        // an INTEGER 0 — enough for rustls to accept as a bytes blob).
        let ocsp_bytes: Vec<u8> = vec![0x30, 0x03, 0x0a, 0x01, 0x00];
        let resolver = Arc::new(StaticOcspResolver(ocsp_bytes));

        // Build a server that would use the OCSP resolver — just verify it
        // doesn't panic on construction. (No cert installed, so build() will
        // fail with InvalidConfig, not a crash.)
        let result = ServerBuilder::new()
            .with_ocsp_response_resolver(resolver)
            .build();

        match result {
            Err(oxitls::TlsError::InvalidConfig(_)) => {
                // Expected: no cert/key configured.
            }
            other => panic!("unexpected result from build with no cert: {:?}", other),
        }
    }
}
