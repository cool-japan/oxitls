//! Post-quantum hybrid key exchange: X25519MLKEM768.
//!
//! This module implements the X25519MLKEM768 hybrid key exchange group as
//! specified in <https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/>.
//!
//! Wire layout (PQ-first throughout):
//! - Client share: ML-KEM-768 encap key (1184 B) ‖ X25519 pub (32 B) = 1216 B
//! - Server share: ML-KEM-768 ciphertext (1088 B) ‖ X25519 pub (32 B) = 1120 B
//! - Shared secret: ML-KEM-768 ss (32 B) ‖ X25519 ss (32 B) = 64 B
//!
//! Only compiled when the `post-quantum` feature is enabled.

#![cfg(feature = "post-quantum")]

use ml_kem::{
    Decapsulate, DecapsulationKey768, Encapsulate, EncapsulationKey768, Kem, KeyExport, MlKem768,
};
use oxitls_core::OsRng;
use rustls::{
    crypto::{ActiveKeyExchange, CompletedKeyExchange, SharedSecret, SupportedKxGroup},
    Error, NamedGroup, PeerMisbehaved, ProtocolVersion,
};
use x25519_dalek::{EphemeralSecret, PublicKey};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Length of an ML-KEM-768 encapsulation key (public key for the KEM).
const MLKEM768_ENCAP_KEY_LEN: usize = 1184;

/// Length of an ML-KEM-768 ciphertext produced by encapsulate.
const MLKEM768_CIPHERTEXT_LEN: usize = 1088;

/// Length of an X25519 public key.
const X25519_PUB_LEN: usize = 32;

/// Total client key share = ML-KEM encap key ‖ X25519 public key.
const CLIENT_SHARE_LEN: usize = MLKEM768_ENCAP_KEY_LEN + X25519_PUB_LEN;

/// Total server key share = ML-KEM ciphertext ‖ X25519 public key.
const SERVER_SHARE_LEN: usize = MLKEM768_CIPHERTEXT_LEN + X25519_PUB_LEN;

// ── SupportedKxGroup impl ─────────────────────────────────────────────────────

/// The X25519MLKEM768 hybrid key exchange group.
///
/// Wire value: 0x11ec per
/// <https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml>.
///
/// Use [`X25519MLKEM768`] (the static) rather than constructing this directly.
#[derive(Debug)]
pub(crate) struct X25519MlKem768;

/// Static reference to the X25519MLKEM768 supported KX group.
///
/// Insert at index 0 of `CryptoProvider::kx_groups` via
/// [`pure_provider_with_pq`][crate::pure_provider_with_pq] to offer PQ-hybrid
/// key exchange in TLS 1.3 handshakes.
pub static X25519MLKEM768: &dyn SupportedKxGroup = &X25519MlKem768;

impl SupportedKxGroup for X25519MlKem768 {
    /// Starts a key exchange as the TLS client.
    ///
    /// Generates one ML-KEM-768 keypair and one X25519 ephemeral key,
    /// then concatenates (PQ-first) into a 1216-byte client key share.
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        // Generate ML-KEM-768 decapsulation + encapsulation keypair.
        let (dk, ek): (DecapsulationKey768, EncapsulationKey768) = MlKem768::generate_keypair();

        // Serialize encapsulation key to bytes (1184 B).
        let ek_bytes = ek.to_bytes();

        // Generate X25519 ephemeral keypair.
        let x25519_priv = EphemeralSecret::random_from_rng(OsRng);
        let x25519_pub = PublicKey::from(&x25519_priv);

        // Build client share: ML-KEM encap key ‖ X25519 pub.
        let mut combined_pub = Vec::with_capacity(CLIENT_SHARE_LEN);
        combined_pub.extend_from_slice(ek_bytes.as_ref());
        combined_pub.extend_from_slice(x25519_pub.as_bytes());

        debug_assert_eq!(combined_pub.len(), CLIENT_SHARE_LEN);

        Ok(Box::new(ActiveX25519MlKem768 {
            dk,
            x25519_priv,
            combined_pub,
        }))
    }

    /// Starts and completes the key exchange as the TLS server.
    ///
    /// Parses the client's 1216-byte hybrid key share, encapsulates to the
    /// ML-KEM public key, performs X25519 DH, and returns the concatenated
    /// 64-byte shared secret together with a 1120-byte server key share.
    fn start_and_complete(&self, peer_pub_key: &[u8]) -> Result<CompletedKeyExchange, Error> {
        if peer_pub_key.len() != CLIENT_SHARE_LEN {
            return Err(Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare));
        }

        // Split: first 1184 bytes = ML-KEM encap key, last 32 = X25519 pub.
        let (peer_ek_bytes, peer_x25519_bytes) = peer_pub_key.split_at(MLKEM768_ENCAP_KEY_LEN);

        // Reconstruct the peer's ML-KEM encapsulation key.
        let peer_ek_array = ml_kem::array::Array::try_from(peer_ek_bytes)
            .map_err(|_| Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare))?;
        let peer_ek = EncapsulationKey768::new(&peer_ek_array)
            .map_err(|_| Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare))?;

        // ML-KEM encapsulate → (ciphertext, shared_secret).
        let (ct, mlkem_ss) = peer_ek.encapsulate();

        // Generate our X25519 ephemeral key and compute X25519 DH.
        let x25519_priv = EphemeralSecret::random_from_rng(OsRng);
        let x25519_pub = PublicKey::from(&x25519_priv);

        let peer_x25519_array: [u8; X25519_PUB_LEN] = peer_x25519_bytes
            .try_into()
            .map_err(|_| Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare))?;
        let x25519_ss = x25519_priv.diffie_hellman(&PublicKey::from(peer_x25519_array));

        // Build server share: ML-KEM ciphertext ‖ X25519 pub.
        let mut pub_key = Vec::with_capacity(SERVER_SHARE_LEN);
        pub_key.extend_from_slice(ct.as_ref());
        pub_key.extend_from_slice(x25519_pub.as_bytes());

        debug_assert_eq!(pub_key.len(), SERVER_SHARE_LEN);

        // Combined shared secret: ML-KEM ss ‖ X25519 ss.
        let mut secret_bytes = Vec::with_capacity(64);
        secret_bytes.extend_from_slice(mlkem_ss.as_ref());
        secret_bytes.extend_from_slice(x25519_ss.as_bytes());

        debug_assert_eq!(secret_bytes.len(), 64);

        Ok(CompletedKeyExchange {
            group: NamedGroup::X25519MLKEM768,
            pub_key,
            secret: SharedSecret::from(secret_bytes),
        })
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }

    fn ffdhe_group(&self) -> Option<rustls::ffdhe_groups::FfdheGroup<'static>> {
        None
    }

    fn fips(&self) -> bool {
        false
    }

    /// X25519MLKEM768 is only valid for TLS 1.3.
    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }
}

// ── ActiveKeyExchange impl ────────────────────────────────────────────────────

/// In-progress key exchange state for the TLS client role.
struct ActiveX25519MlKem768 {
    /// ML-KEM-768 decapsulation key (private; used to complete the exchange).
    dk: DecapsulationKey768,
    /// X25519 ephemeral private key.
    x25519_priv: EphemeralSecret,
    /// Combined 1216-byte client key share: ML-KEM encap key ‖ X25519 pub.
    combined_pub: Vec<u8>,
}

impl ActiveKeyExchange for ActiveX25519MlKem768 {
    /// Completes the key exchange on the client side.
    ///
    /// Parses the server's 1120-byte share, decapsulates the ML-KEM ciphertext
    /// and computes X25519 DH to produce the 64-byte combined shared secret.
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        if peer_pub_key.len() != SERVER_SHARE_LEN {
            return Err(Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare));
        }

        let this = *self;

        // Split: first 1088 bytes = ML-KEM ciphertext, last 32 = X25519 pub.
        let (ct_bytes, peer_x25519_bytes) = peer_pub_key.split_at(MLKEM768_CIPHERTEXT_LEN);

        // ML-KEM decapsulate.
        let mlkem_ss = this
            .dk
            .decapsulate_slice(ct_bytes)
            .map_err(|_| Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare))?;

        // X25519 DH.
        let peer_x25519_array: [u8; X25519_PUB_LEN] = peer_x25519_bytes
            .try_into()
            .map_err(|_| Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare))?;
        let x25519_ss = this
            .x25519_priv
            .diffie_hellman(&PublicKey::from(peer_x25519_array));

        // Combined shared secret: ML-KEM ss ‖ X25519 ss.
        let mut secret_bytes = Vec::with_capacity(64);
        secret_bytes.extend_from_slice(mlkem_ss.as_ref());
        secret_bytes.extend_from_slice(x25519_ss.as_bytes());

        debug_assert_eq!(secret_bytes.len(), 64);

        Ok(SharedSecret::from(secret_bytes))
    }

    /// Returns the classical (X25519) component for HRR optimisation.
    ///
    /// Rustls uses this to send both the hybrid and classical shares in the
    /// initial `ClientHello`, so a server that doesn't support PQ hybrid can
    /// still avoid a `HelloRetryRequest`.
    fn hybrid_component(&self) -> Option<(NamedGroup, &[u8])> {
        // X25519 pub key is the last 32 bytes of combined_pub.
        let x25519_pub = &self.combined_pub[MLKEM768_ENCAP_KEY_LEN..];
        Some((NamedGroup::X25519, x25519_pub))
    }

    /// Completes only the X25519 half (called when the server chose plain X25519).
    fn complete_hybrid_component(
        self: Box<Self>,
        peer_pub_key: &[u8],
    ) -> Result<SharedSecret, Error> {
        let this = *self;
        let peer_array: [u8; X25519_PUB_LEN] = peer_pub_key
            .try_into()
            .map_err(|_| Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare))?;
        let ss = this
            .x25519_priv
            .diffie_hellman(&PublicKey::from(peer_array));
        Ok(SharedSecret::from(ss.as_bytes() as &[u8]))
    }

    fn pub_key(&self) -> &[u8] {
        &self.combined_pub
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }

    fn ffdhe_group(&self) -> Option<rustls::ffdhe_groups::FfdheGroup<'static>> {
        None
    }
}
