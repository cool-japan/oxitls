//! AEAD suite abstraction for RFC 9180 HPKE.
//!
//! Provides a `AeadSuite` trait with two implementations:
//! - `AeadAes128Gcm`  — AES-128-GCM  (AEAD_ID = 0x0001)
//! - `AeadChacha20`   — ChaCha20Poly1305 (AEAD_ID = 0x0003)
//!
//! Both operations return ct||tag on encrypt, and strip the tag on decrypt.

// ── Trait ────────────────────────────────────────────────────────────────────

/// A zero-cost AEAD suite marker that carries compile-time constants and
/// provides encrypt/decrypt.  All methods are inherently non-`self` so that
/// the zero-sized implementors never need instantiation.
pub trait AeadSuite: 'static + Send + Sync {
    /// HPKE AEAD algorithm ID (2-byte big-endian value).
    const AEAD_ID: u16;
    /// Key length in bytes.
    const NK: usize;
    /// Nonce length in bytes (always 12 for GCM / ChaCha20Poly1305).
    #[allow(dead_code)]
    const NN: usize;
    /// Tag length in bytes (always 16).
    #[allow(dead_code)]
    const NT: usize;

    /// Encrypt `pt` under `key` with 12-byte `nonce` and `aad`.
    ///
    /// Returns `ct || tag` (length = `pt.len() + NT`).
    fn seal(key: &[u8], nonce: &[u8; 12], aad: &[u8], pt: &[u8]) -> Result<Vec<u8>, rustls::Error>;

    /// Decrypt `ct` (which is `ciphertext || tag`) under `key` with 12-byte `nonce` and `aad`.
    ///
    /// Returns plaintext (length = `ct.len() - NT`).
    fn open(key: &[u8], nonce: &[u8; 12], aad: &[u8], ct: &[u8]) -> Result<Vec<u8>, rustls::Error>;
}

// ── AES-128-GCM ──────────────────────────────────────────────────────────────

/// Zero-sized type representing the AES-128-GCM AEAD suite.
pub struct AeadAes128Gcm;

impl AeadSuite for AeadAes128Gcm {
    const AEAD_ID: u16 = 0x0001;
    const NK: usize = 16;
    const NN: usize = 12;
    const NT: usize = 16;

    fn seal(key: &[u8], nonce: &[u8; 12], aad: &[u8], pt: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        use aes_gcm::aead::Aead;
        use aes_gcm::{Aes128Gcm, KeyInit, Nonce};

        let cipher = Aes128Gcm::new_from_slice(key)
            .map_err(|_| rustls::Error::General("HPKE AES-128-GCM: invalid key length".into()))?;

        let nonce_arr = Nonce::from_slice(nonce.as_slice());
        cipher
            .encrypt(nonce_arr, aes_gcm::aead::Payload { msg: pt, aad })
            .map_err(|_| rustls::Error::General("HPKE AES-128-GCM: encryption failed".into()))
    }

    fn open(key: &[u8], nonce: &[u8; 12], aad: &[u8], ct: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        use aes_gcm::aead::Aead;
        use aes_gcm::{Aes128Gcm, KeyInit, Nonce};

        let cipher = Aes128Gcm::new_from_slice(key)
            .map_err(|_| rustls::Error::General("HPKE AES-128-GCM: invalid key length".into()))?;

        let nonce_arr = Nonce::from_slice(nonce.as_slice());
        cipher
            .decrypt(nonce_arr, aes_gcm::aead::Payload { msg: ct, aad })
            .map_err(|_| {
                rustls::Error::General(
                    "HPKE AES-128-GCM: decryption failed (bad tag or data)".into(),
                )
            })
    }
}

// ── ChaCha20-Poly1305 ─────────────────────────────────────────────────────────

/// Zero-sized type representing the ChaCha20Poly1305 AEAD suite.
pub struct AeadChacha20;

impl AeadSuite for AeadChacha20 {
    const AEAD_ID: u16 = 0x0003;
    const NK: usize = 32;
    const NN: usize = 12;
    const NT: usize = 16;

    fn seal(key: &[u8], nonce: &[u8; 12], aad: &[u8], pt: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        use chacha20poly1305::aead::Aead;
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};

        let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| {
            rustls::Error::General("HPKE ChaCha20Poly1305: invalid key length".into())
        })?;

        let nonce_arr = Nonce::from_slice(nonce.as_slice());
        cipher
            .encrypt(nonce_arr, chacha20poly1305::aead::Payload { msg: pt, aad })
            .map_err(|_| rustls::Error::General("HPKE ChaCha20Poly1305: encryption failed".into()))
    }

    fn open(key: &[u8], nonce: &[u8; 12], aad: &[u8], ct: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        use chacha20poly1305::aead::Aead;
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};

        let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| {
            rustls::Error::General("HPKE ChaCha20Poly1305: invalid key length".into())
        })?;

        let nonce_arr = Nonce::from_slice(nonce.as_slice());
        cipher
            .decrypt(nonce_arr, chacha20poly1305::aead::Payload { msg: ct, aad })
            .map_err(|_| {
                rustls::Error::General(
                    "HPKE ChaCha20Poly1305: decryption failed (bad tag or data)".into(),
                )
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zero_key_aes128() -> [u8; 16] {
        [0u8; 16]
    }

    fn zero_key_chacha20() -> [u8; 32] {
        [0u8; 32]
    }

    #[test]
    fn aes128gcm_roundtrip() {
        let key = zero_key_aes128();
        let nonce = [0u8; 12];
        let aad = b"test-aad";
        let pt = b"hello world";

        let ct = AeadAes128Gcm::seal(&key, &nonce, aad, pt).expect("seal");
        assert_eq!(ct.len(), pt.len() + AeadAes128Gcm::NT);

        let recovered = AeadAes128Gcm::open(&key, &nonce, aad, &ct).expect("open");
        assert_eq!(recovered, pt);
    }

    #[test]
    fn aes128gcm_bad_tag_rejected() {
        let key = zero_key_aes128();
        let nonce = [0u8; 12];
        let mut ct = AeadAes128Gcm::seal(&key, &nonce, b"", b"pt").expect("seal");
        // Flip last byte (in the tag)
        let last = ct.len() - 1;
        ct[last] ^= 0xff;
        assert!(AeadAes128Gcm::open(&key, &nonce, b"", &ct).is_err());
    }

    #[test]
    fn chacha20_roundtrip() {
        let key = zero_key_chacha20();
        let nonce = [0u8; 12];
        let aad = b"aad";
        let pt = b"secret message";

        let ct = AeadChacha20::seal(&key, &nonce, aad, pt).expect("seal");
        assert_eq!(ct.len(), pt.len() + AeadChacha20::NT);

        let recovered = AeadChacha20::open(&key, &nonce, aad, &ct).expect("open");
        assert_eq!(recovered, pt);
    }

    #[test]
    fn chacha20_bad_tag_rejected() {
        let key = zero_key_chacha20();
        let nonce = [0u8; 12];
        let mut ct = AeadChacha20::seal(&key, &nonce, b"", b"pt").expect("seal");
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert!(AeadChacha20::open(&key, &nonce, b"", &ct).is_err());
    }
}
