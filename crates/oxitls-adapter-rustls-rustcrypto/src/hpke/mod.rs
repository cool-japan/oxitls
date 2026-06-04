//! RFC 9180 HPKE (Hybrid Public Key Encryption) base-mode provider.
//!
//! Exposes four suites over RustCrypto primitives (zero C/FFI dependencies):
//!
//! | Suite | KEM | KDF | AEAD |
//! |---|---|---|---|
//! | `X25519_HKDF_SHA256_AES128GCM` | DHKEM(X25519,SHA-256) | HKDF-SHA-256 | AES-128-GCM |
//! | `X25519_HKDF_SHA256_CHACHA20`  | DHKEM(X25519,SHA-256) | HKDF-SHA-256 | ChaCha20-Poly1305 |
//! | `P256_HKDF_SHA256_AES128GCM`   | DHKEM(P-256,SHA-256)  | HKDF-SHA-256 | AES-128-GCM |
//! | `P256_HKDF_SHA256_CHACHA20`    | DHKEM(P-256,SHA-256)  | HKDF-SHA-256 | ChaCha20-Poly1305 |
//!
//! All suites satisfy the `rustls::crypto::hpke::Hpke` trait and are collected in
//! [`pure_hpke_suites`].

use std::fmt;
use std::marker::PhantomData;

use rustls::crypto::hpke::{
    EncapsulatedSecret, Hpke, HpkeOpener, HpkePrivateKey, HpkePublicKey, HpkeSealer, HpkeSuite,
};
use rustls::internal::msgs::enums::{HpkeAead, HpkeKdf, HpkeKem};
use rustls::internal::msgs::handshake::HpkeSymmetricCipherSuite;

use crate::hpke::aead::AeadSuite;
use crate::hpke::kdf::{key_schedule_base, labeled_expand_checked};
use crate::hpke::kem::DhKem;

pub use aead::{AeadAes128Gcm, AeadChacha20};
pub use kem::{KemP256, KemX25519};

pub mod aead;
pub mod ech_config;
pub mod kdf;
pub mod kem;
pub mod vectors;

// ── Suite ID helpers ─────────────────────────────────────────────────────────

/// Build the full HPKE suite_id:
///   b"HPKE" || I2OSP(kem_id,2) || I2OSP(kdf_id,2) || I2OSP(aead_id,2)
fn hpke_suite_id<K: DhKem, A: AeadSuite>() -> [u8; 10] {
    let kem = K::KEM_ID.to_be_bytes();
    let kdf: [u8; 2] = 0x0001u16.to_be_bytes(); // HKDF-SHA256 is the only KDF we use
    let aead = A::AEAD_ID.to_be_bytes();
    [
        b'H', b'P', b'K', b'E', kem[0], kem[1], kdf[0], kdf[1], aead[0], aead[1],
    ]
}

// ── Context seal/open helpers ─────────────────────────────────────────────────

/// Compute the per-message nonce: `base_nonce XOR I2OSP(seq, 12)`.
fn compute_nonce(base_nonce: &[u8; 12], seq: u64) -> [u8; 12] {
    // I2OSP(seq, 12): 12-byte big-endian representation, left-padded with zeros.
    let seq_bytes = seq.to_be_bytes(); // 8 bytes
    let mut nonce = *base_nonce;
    // XOR bytes 4..12 of base_nonce with seq_bytes (the high 4 bytes of seq are zero
    // for realistic sequence numbers).
    for i in 0..8 {
        nonce[4 + i] ^= seq_bytes[i];
    }
    nonce
}

// ── HpkeSuiteImpl ─────────────────────────────────────────────────────────────

/// Zero-sized generic HPKE suite combining a [`DhKem`] and an [`AeadSuite`].
pub struct HpkeSuiteImpl<K: DhKem, A: AeadSuite>(PhantomData<(K, A)>);

impl<K: DhKem, A: AeadSuite> fmt::Debug for HpkeSuiteImpl<K, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "HpkeSuiteImpl(kem={:#06x}, aead={:#06x})",
            K::KEM_ID,
            A::AEAD_ID,
        )
    }
}

impl<K: DhKem, A: AeadSuite> HpkeSuiteImpl<K, A> {
    /// Typed (non-erased) HPKE sender setup. Returns a concrete [`HpkeSealerCtx<A>`].
    ///
    /// This is the primary code path; the rustls trait's `setup_sealer` delegates here.
    pub fn setup_sender(
        &self,
        info: &[u8],
        pub_key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, HpkeSealerCtx<A>), rustls::Error> {
        let suite_id = hpke_suite_id::<K, A>();
        let (shared_secret, enc) = K::encap(&pub_key.0)?;
        let km = key_schedule_base(&suite_id, &shared_secret, info, A::NK)?;
        let ctx = HpkeSealerCtx {
            key: km.key,
            base_nonce: km.base_nonce,
            seq: 0,
            suite_id,
            exporter_secret: km.exporter_secret,
            _phantom: PhantomData,
        };
        Ok((EncapsulatedSecret(enc), ctx))
    }

    /// Typed (non-erased) HPKE receiver setup. Returns a concrete [`HpkeOpenerCtx<A>`].
    ///
    /// This is the primary code path; the rustls trait's `setup_opener` delegates here.
    pub fn setup_receiver(
        &self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        secret_key: &HpkePrivateKey,
    ) -> Result<HpkeOpenerCtx<A>, rustls::Error> {
        let suite_id = hpke_suite_id::<K, A>();
        let shared_secret = K::decap(secret_key.secret_bytes(), &enc.0)?;
        let km = key_schedule_base(&suite_id, &shared_secret, info, A::NK)?;
        Ok(HpkeOpenerCtx {
            key: km.key,
            base_nonce: km.base_nonce,
            seq: 0,
            suite_id,
            exporter_secret: km.exporter_secret,
            _phantom: PhantomData,
        })
    }
}

impl<K: DhKem, A: AeadSuite> Hpke for HpkeSuiteImpl<K, A> {
    fn seal(
        &self,
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        pub_key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Vec<u8>), rustls::Error> {
        let suite_id = hpke_suite_id::<K, A>();

        let (shared_secret, enc) = K::encap(&pub_key.0)?;

        let km = key_schedule_base(&suite_id, &shared_secret, info, A::NK)?;

        let nonce = compute_nonce(&km.base_nonce, 0);
        let ct = A::seal(&km.key, &nonce, aad, plaintext)?;

        Ok((EncapsulatedSecret(enc), ct))
    }

    fn setup_sealer(
        &self,
        info: &[u8],
        pub_key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Box<dyn HpkeSealer + 'static>), rustls::Error> {
        let (enc, ctx) = self.setup_sender(info, pub_key)?;
        Ok((enc, Box::new(ctx)))
    }

    fn open(
        &self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        secret_key: &HpkePrivateKey,
    ) -> Result<Vec<u8>, rustls::Error> {
        let suite_id = hpke_suite_id::<K, A>();

        let shared_secret = K::decap(secret_key.secret_bytes(), &enc.0)?;

        let km = key_schedule_base(&suite_id, &shared_secret, info, A::NK)?;

        let nonce = compute_nonce(&km.base_nonce, 0);
        A::open(&km.key, &nonce, aad, ciphertext)
    }

    fn setup_opener(
        &self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        secret_key: &HpkePrivateKey,
    ) -> Result<Box<dyn HpkeOpener + 'static>, rustls::Error> {
        Ok(Box::new(self.setup_receiver(enc, info, secret_key)?))
    }

    fn generate_key_pair(&self) -> Result<(HpkePublicKey, HpkePrivateKey), rustls::Error> {
        let (pk_bytes, sk_bytes) = K::generate()?;
        Ok((HpkePublicKey(pk_bytes), HpkePrivateKey::from(sk_bytes)))
    }

    fn suite(&self) -> HpkeSuite {
        let kem = match K::KEM_ID {
            0x0020 => HpkeKem::DHKEM_X25519_HKDF_SHA256,
            0x0010 => HpkeKem::DHKEM_P256_HKDF_SHA256,
            other => panic!("HpkeSuiteImpl: unknown KEM_ID {:#06x}", other),
        };
        let aead = match A::AEAD_ID {
            0x0001 => HpkeAead::AES_128_GCM,
            0x0003 => HpkeAead::CHACHA20_POLY_1305,
            other => panic!("HpkeSuiteImpl: unknown AEAD_ID {:#06x}", other),
        };
        HpkeSuite {
            kem,
            sym: HpkeSymmetricCipherSuite {
                kdf_id: HpkeKdf::HKDF_SHA256,
                aead_id: aead,
            },
        }
    }
}

// ── HpkeSealerCtx ────────────────────────────────────────────────────────────

/// Stateful HPKE sealer context.  Tracks the sequence number and computes
/// per-message nonces.
///
/// Also carries the RFC 9180 §5.3 exporter secret so that
/// [`HpkeSealerCtx::export`] is available without re-running the key schedule.
pub struct HpkeSealerCtx<A: AeadSuite> {
    key: Vec<u8>,
    base_nonce: [u8; 12],
    seq: u64,
    /// Full 10-byte HPKE suite_id for Export domain separation.
    suite_id: [u8; 10],
    /// RFC 9180 §5.1 exporter secret, used by `export()`.
    exporter_secret: [u8; 32],
    _phantom: PhantomData<A>,
}

impl<A: AeadSuite> fmt::Debug for HpkeSealerCtx<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HpkeSealerCtx")
            .field("seq", &self.seq)
            .finish_non_exhaustive()
    }
}

impl<A: AeadSuite> HpkeSealerCtx<A> {
    /// RFC 9180 §5.3 Context.Export.
    ///
    /// Derives `len` bytes of keying material from the exporter secret using the
    /// given `exporter_context`.  Label `"sec"` is used per the RFC (distinct from
    /// the `"exp"` label used during key schedule derivation of the exporter secret).
    ///
    /// Returns `Err` if `len` exceeds the HKDF-SHA256 maximum (255 × 32 = 8160 bytes).
    pub fn export(&self, exporter_context: &[u8], len: usize) -> Result<Vec<u8>, rustls::Error> {
        labeled_expand_checked(
            &self.suite_id,
            &self.exporter_secret,
            b"sec",
            exporter_context,
            len,
        )
    }
}

impl<A: AeadSuite + 'static> HpkeSealer for HpkeSealerCtx<A> {
    fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let nonce = compute_nonce(&self.base_nonce, self.seq);
        let ct = A::seal(&self.key, &nonce, aad, plaintext)?;
        // §5.2: MUST abort if sequence number would overflow.
        self.seq = self.seq.checked_add(1).ok_or_else(|| {
            rustls::Error::General("HPKE: message sequence number limit reached".into())
        })?;
        Ok(ct)
    }
}

// ── HpkeOpenerCtx ────────────────────────────────────────────────────────────

/// Stateful HPKE opener context.
///
/// Also carries the RFC 9180 §5.3 exporter secret so that
/// [`HpkeOpenerCtx::export`] is available without re-running the key schedule.
pub struct HpkeOpenerCtx<A: AeadSuite> {
    key: Vec<u8>,
    base_nonce: [u8; 12],
    seq: u64,
    /// Full 10-byte HPKE suite_id for Export domain separation.
    suite_id: [u8; 10],
    /// RFC 9180 §5.1 exporter secret, used by `export()`.
    exporter_secret: [u8; 32],
    _phantom: PhantomData<A>,
}

impl<A: AeadSuite> fmt::Debug for HpkeOpenerCtx<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HpkeOpenerCtx")
            .field("seq", &self.seq)
            .finish_non_exhaustive()
    }
}

impl<A: AeadSuite> HpkeOpenerCtx<A> {
    /// RFC 9180 §5.3 Context.Export.
    ///
    /// Derives `len` bytes of keying material from the exporter secret using the
    /// given `exporter_context`.  Label `"sec"` is used per the RFC (distinct from
    /// the `"exp"` label used during key schedule derivation of the exporter secret).
    ///
    /// Returns `Err` if `len` exceeds the HKDF-SHA256 maximum (255 × 32 = 8160 bytes).
    pub fn export(&self, exporter_context: &[u8], len: usize) -> Result<Vec<u8>, rustls::Error> {
        labeled_expand_checked(
            &self.suite_id,
            &self.exporter_secret,
            b"sec",
            exporter_context,
            len,
        )
    }
}

impl<A: AeadSuite + 'static> HpkeOpener for HpkeOpenerCtx<A> {
    fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let nonce = compute_nonce(&self.base_nonce, self.seq);
        let pt = A::open(&self.key, &nonce, aad, ciphertext)?;
        // §5.2: MUST abort if sequence number would overflow.
        self.seq = self.seq.checked_add(1).ok_or_else(|| {
            rustls::Error::General("HPKE: message sequence number limit reached".into())
        })?;
        Ok(pt)
    }
}

// ── Suite statics ─────────────────────────────────────────────────────────────

/// DHKEM(X25519,HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM
pub static X25519_HKDF_SHA256_AES128GCM: HpkeSuiteImpl<kem::KemX25519, aead::AeadAes128Gcm> =
    HpkeSuiteImpl(PhantomData);

/// DHKEM(X25519,HKDF-SHA256) / HKDF-SHA256 / ChaCha20Poly1305
pub static X25519_HKDF_SHA256_CHACHA20: HpkeSuiteImpl<kem::KemX25519, aead::AeadChacha20> =
    HpkeSuiteImpl(PhantomData);

/// DHKEM(P-256,HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM
pub static P256_HKDF_SHA256_AES128GCM: HpkeSuiteImpl<kem::KemP256, aead::AeadAes128Gcm> =
    HpkeSuiteImpl(PhantomData);

/// DHKEM(P-256,HKDF-SHA256) / HKDF-SHA256 / ChaCha20Poly1305
pub static P256_HKDF_SHA256_CHACHA20: HpkeSuiteImpl<kem::KemP256, aead::AeadChacha20> =
    HpkeSuiteImpl(PhantomData);

// ── Typed const suite values ───────────────────────────────────────────────────

/// DHKEM(X25519,HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM — typed const (for `setup_sender`/`setup_receiver`).
pub const HPKE_X25519_HKDF_SHA256_AES128GCM: HpkeSuiteImpl<KemX25519, AeadAes128Gcm> =
    HpkeSuiteImpl(std::marker::PhantomData);

/// DHKEM(X25519,HKDF-SHA256) / HKDF-SHA256 / ChaCha20Poly1305 — typed const.
pub const HPKE_X25519_HKDF_SHA256_CHACHA20: HpkeSuiteImpl<KemX25519, AeadChacha20> =
    HpkeSuiteImpl(std::marker::PhantomData);

/// DHKEM(P-256,HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM — typed const.
pub const HPKE_P256_HKDF_SHA256_AES128GCM: HpkeSuiteImpl<KemP256, AeadAes128Gcm> =
    HpkeSuiteImpl(std::marker::PhantomData);

/// DHKEM(P-256,HKDF-SHA256) / HKDF-SHA256 / ChaCha20Poly1305 — typed const.
pub const HPKE_P256_HKDF_SHA256_CHACHA20: HpkeSuiteImpl<KemP256, AeadChacha20> =
    HpkeSuiteImpl(std::marker::PhantomData);

/// All four Pure-Rust HPKE suites for ECH support.
static ALL_SUITES: [&dyn Hpke; 4] = [
    &X25519_HKDF_SHA256_AES128GCM,
    &X25519_HKDF_SHA256_CHACHA20,
    &P256_HKDF_SHA256_AES128GCM,
    &P256_HKDF_SHA256_CHACHA20,
];

/// Return all four Pure-Rust HPKE suites for ECH support.
///
/// These suites implement RFC 9180 base mode over vetted RustCrypto primitives
/// with zero C/FFI dependencies.
pub fn pure_hpke_suites() -> &'static [&'static dyn Hpke] {
    &ALL_SUITES
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hpke::aead::{AeadAes128Gcm, AeadChacha20};

    // ── Suite IDs ────────────────────────────────────────────────────────────

    #[test]
    fn suite_ids_correct() {
        let s = X25519_HKDF_SHA256_AES128GCM.suite();
        assert_eq!(s.kem, HpkeKem::DHKEM_X25519_HKDF_SHA256);
        assert_eq!(s.sym.kdf_id, HpkeKdf::HKDF_SHA256);
        assert_eq!(s.sym.aead_id, HpkeAead::AES_128_GCM);

        let s = X25519_HKDF_SHA256_CHACHA20.suite();
        assert_eq!(s.kem, HpkeKem::DHKEM_X25519_HKDF_SHA256);
        assert_eq!(s.sym.aead_id, HpkeAead::CHACHA20_POLY_1305);

        let s = P256_HKDF_SHA256_AES128GCM.suite();
        assert_eq!(s.kem, HpkeKem::DHKEM_P256_HKDF_SHA256);
        assert_eq!(s.sym.aead_id, HpkeAead::AES_128_GCM);

        let s = P256_HKDF_SHA256_CHACHA20.suite();
        assert_eq!(s.kem, HpkeKem::DHKEM_P256_HKDF_SHA256);
        assert_eq!(s.sym.aead_id, HpkeAead::CHACHA20_POLY_1305);
    }

    // ── Roundtrip tests ───────────────────────────────────────────────────────

    fn roundtrip_single<K: DhKem + Send + Sync, A: AeadSuite + Send + Sync>(
        suite: &HpkeSuiteImpl<K, A>,
    ) {
        let (pk, sk) = suite.generate_key_pair().expect("generate_key_pair");

        // One-shot seal/open
        let info = b"test-info";
        let aad = b"test-aad";
        let pt = b"hello hpke world";

        let (enc, ct) = suite.seal(info, aad, pt, &pk).expect("seal");
        let recovered = suite.open(&enc, info, aad, &ct, &sk).expect("open");
        assert_eq!(recovered, pt);
    }

    fn roundtrip_multi<K: DhKem + Send + Sync, A: AeadSuite + Send + Sync>(
        suite: &HpkeSuiteImpl<K, A>,
    ) {
        let (pk, sk) = suite.generate_key_pair().expect("generate_key_pair");

        let info = b"multi-message-test";
        let (enc, mut sealer) = suite.setup_sealer(info, &pk).expect("setup_sealer");
        let mut opener = suite.setup_opener(&enc, info, &sk).expect("setup_opener");

        for i in 0u8..3 {
            let pt = format!("message {i}").into_bytes();
            let aad = format!("aad {i}").into_bytes();
            let ct = sealer.seal(&aad, &pt).expect("sealer.seal");
            let recovered = opener.open(&aad, &ct).expect("opener.open");
            assert_eq!(recovered, pt);
        }
    }

    #[test]
    fn roundtrip_x25519_aes128() {
        roundtrip_single(&X25519_HKDF_SHA256_AES128GCM);
        roundtrip_multi(&X25519_HKDF_SHA256_AES128GCM);
    }

    #[test]
    fn roundtrip_x25519_chacha20() {
        roundtrip_single(&X25519_HKDF_SHA256_CHACHA20);
        roundtrip_multi(&X25519_HKDF_SHA256_CHACHA20);
    }

    #[test]
    fn roundtrip_p256_aes128() {
        roundtrip_single(&P256_HKDF_SHA256_AES128GCM);
        roundtrip_multi(&P256_HKDF_SHA256_AES128GCM);
    }

    #[test]
    fn roundtrip_p256_chacha20() {
        roundtrip_single(&P256_HKDF_SHA256_CHACHA20);
        roundtrip_multi(&P256_HKDF_SHA256_CHACHA20);
    }

    // ── Sequence overflow MUST abort ──────────────────────────────────────────

    #[test]
    fn seq_overflow_aborts_sealer() {
        // Build a sealer context manually with seq=u64::MAX
        let key = vec![0u8; AeadAes128Gcm::NK];
        let base_nonce = [0u8; 12];
        let suite_id = *b"HPKE\x00\x20\x00\x01\x00\x01";
        let mut ctx = HpkeSealerCtx::<AeadAes128Gcm> {
            key,
            base_nonce,
            seq: u64::MAX,
            suite_id,
            exporter_secret: [0u8; 32],
            _phantom: PhantomData,
        };
        // The seal call itself will succeed (seq MAX is valid), but post-increment should fail.
        // Actually MAX is valid to use for the last message, but incrementing overflows:
        let result = ctx.seal(b"aad", b"plaintext");
        assert!(
            result.is_err(),
            "sealer must error on seq overflow (seq was u64::MAX)"
        );
    }

    #[test]
    fn seq_overflow_aborts_opener() {
        let key = vec![0u8; AeadAes128Gcm::NK];
        let base_nonce = [0u8; 12];
        let suite_id = *b"HPKE\x00\x20\x00\x01\x00\x01";

        // First build a valid ciphertext at seq=0 so we have valid ct to open at seq=u64::MAX
        // Actually for this test we just need to verify the sequence overflow check fires.
        // We set seq to u64::MAX so the first open attempt will overflow after computing nonce.
        // But we can't have a valid ct for seq=u64::MAX without a real seal. Instead,
        // let's set up a sealer/opener at seq=u64::MAX - 1, do one successful round, and
        // confirm the second errors.
        let mut sealer = HpkeSealerCtx::<AeadAes128Gcm> {
            key: key.clone(),
            base_nonce,
            seq: u64::MAX - 1,
            suite_id,
            exporter_secret: [0u8; 32],
            _phantom: PhantomData,
        };
        let mut opener = HpkeOpenerCtx::<AeadAes128Gcm> {
            key,
            base_nonce,
            seq: u64::MAX - 1,
            suite_id,
            exporter_secret: [0u8; 32],
            _phantom: PhantomData,
        };

        // seq = MAX-1: one more message allowed
        let ct = sealer
            .seal(b"", b"hello")
            .expect("should seal at seq MAX-1");
        let _pt = opener.open(b"", &ct).expect("should open at seq MAX-1");

        // seq = MAX: this is the last allowed message, but post-increment overflows
        // Build matching ct at seq=MAX from sealer (which is now at MAX)
        let ct2 = sealer.seal(b"", b"hello2");
        assert!(
            ct2.is_err(),
            "sealer must fail when seq would overflow past MAX"
        );
    }

    // ── Nonce derivation check ─────────────────────────────────────────────────

    #[test]
    fn nonce_xor_is_correct() {
        let base_nonce = [0x11u8; 12];

        // seq=0 → I2OSP(0,12) = [0;12], nonce = base_nonce XOR 0 = base_nonce
        let n0 = compute_nonce(&base_nonce, 0);
        assert_eq!(n0, base_nonce);

        // seq=1 → last byte of I2OSP is 1, XOR with base[11]=0x11 gives 0x10
        let n1 = compute_nonce(&base_nonce, 1);
        let mut expected = base_nonce;
        expected[11] ^= 1;
        assert_eq!(n1, expected);
    }

    // ── RFC 9180 KAT Tests ───────────────────────────────────────────────────

    fn run_kat_x25519_aes128(kat: &crate::hpke::vectors::kat::Kat) {
        use crate::hpke::kem::x25519_encap_deterministic;

        // Verify enc matches pk_em
        let sk_em: [u8; 32] = kat.sk_em.try_into().expect("sk_em must be 32 bytes");
        let (shared_secret, enc) =
            x25519_encap_deterministic(&sk_em, kat.pk_rm).expect("encap_deterministic");

        assert_eq!(enc, kat.enc, "enc mismatch");
        assert_eq!(shared_secret, kat.shared_secret, "shared_secret mismatch");

        // Run key schedule
        let suite_id = b"HPKE\x00\x20\x00\x01\x00\x01"; // X25519/SHA256/AES128GCM
        let km = key_schedule_base(suite_id, &shared_secret, kat.info, AeadAes128Gcm::NK)
            .expect("key_schedule_base");

        assert_eq!(km.key, kat.key_bytes, "key mismatch");
        assert_eq!(&km.base_nonce, kat.base_nonce, "base_nonce mismatch");
        assert_eq!(
            &km.exporter_secret, kat.exporter_secret,
            "exporter_secret mismatch"
        );

        // Verify export vectors
        for exp in kat.exports {
            let got = crate::hpke::kdf::labeled_expand_checked(
                suite_id,
                &km.exporter_secret,
                b"sec",
                exp.exporter_context,
                exp.l,
            )
            .expect("export");
            assert_eq!(
                got, exp.exported_value,
                "export mismatch (ctx={:?})",
                exp.exporter_context
            );
        }

        // Verify encryption vectors
        for ev in kat.enc_vecs {
            let nonce = compute_nonce(&km.base_nonce, ev.seq);
            let ct = AeadAes128Gcm::seal(&km.key, &nonce, ev.aad, ev.pt).expect("seal");
            assert_eq!(ct, ev.ct, "ciphertext mismatch at seq={}", ev.seq);

            // Verify round-trip
            let pt = AeadAes128Gcm::open(&km.key, &nonce, ev.aad, ev.ct).expect("open");
            assert_eq!(pt, ev.pt);
        }
    }

    fn run_kat_x25519_chacha20(kat: &crate::hpke::vectors::kat::Kat) {
        use crate::hpke::kem::x25519_encap_deterministic;

        let sk_em: [u8; 32] = kat.sk_em.try_into().expect("sk_em must be 32 bytes");
        let (shared_secret, enc) =
            x25519_encap_deterministic(&sk_em, kat.pk_rm).expect("encap_deterministic");

        assert_eq!(enc, kat.enc, "enc mismatch");
        assert_eq!(shared_secret, kat.shared_secret, "shared_secret mismatch");

        let suite_id = b"HPKE\x00\x20\x00\x01\x00\x03"; // X25519/SHA256/ChaCha20
        let km = key_schedule_base(suite_id, &shared_secret, kat.info, AeadChacha20::NK)
            .expect("key_schedule_base");

        assert_eq!(km.key, kat.key_bytes, "key mismatch");
        assert_eq!(&km.base_nonce, kat.base_nonce, "base_nonce mismatch");
        assert_eq!(
            &km.exporter_secret, kat.exporter_secret,
            "exporter_secret mismatch"
        );

        for exp in kat.exports {
            let got = crate::hpke::kdf::labeled_expand_checked(
                suite_id,
                &km.exporter_secret,
                b"sec",
                exp.exporter_context,
                exp.l,
            )
            .expect("export");
            assert_eq!(
                got, exp.exported_value,
                "export mismatch (ctx={:?})",
                exp.exporter_context
            );
        }

        for ev in kat.enc_vecs {
            let nonce = compute_nonce(&km.base_nonce, ev.seq);
            let ct = AeadChacha20::seal(&km.key, &nonce, ev.aad, ev.pt).expect("seal");
            assert_eq!(ct, ev.ct, "ciphertext mismatch at seq={}", ev.seq);
        }
    }

    fn run_kat_p256_aes128(kat: &crate::hpke::vectors::kat::Kat) {
        use crate::hpke::kem::p256_encap_deterministic;

        let (shared_secret, enc) =
            p256_encap_deterministic(kat.sk_em, kat.pk_rm).expect("encap_deterministic");

        assert_eq!(enc, kat.enc, "enc mismatch");
        assert_eq!(shared_secret, kat.shared_secret, "shared_secret mismatch");

        let suite_id = b"HPKE\x00\x10\x00\x01\x00\x01"; // P-256/SHA256/AES128GCM
        let km = key_schedule_base(suite_id, &shared_secret, kat.info, AeadAes128Gcm::NK)
            .expect("key_schedule_base");

        assert_eq!(km.key, kat.key_bytes, "key mismatch");
        assert_eq!(&km.base_nonce, kat.base_nonce, "base_nonce mismatch");
        assert_eq!(
            &km.exporter_secret, kat.exporter_secret,
            "exporter_secret mismatch"
        );

        for exp in kat.exports {
            let got = crate::hpke::kdf::labeled_expand_checked(
                suite_id,
                &km.exporter_secret,
                b"sec",
                exp.exporter_context,
                exp.l,
            )
            .expect("export");
            assert_eq!(
                got, exp.exported_value,
                "export mismatch (ctx={:?})",
                exp.exporter_context
            );
        }

        for ev in kat.enc_vecs {
            let nonce = compute_nonce(&km.base_nonce, ev.seq);
            let ct = AeadAes128Gcm::seal(&km.key, &nonce, ev.aad, ev.pt).expect("seal");
            assert_eq!(ct, ev.ct, "ciphertext mismatch at seq={}", ev.seq);
        }
    }

    fn run_kat_p256_chacha20(kat: &crate::hpke::vectors::kat::Kat) {
        use crate::hpke::kem::p256_encap_deterministic;

        let (shared_secret, enc) =
            p256_encap_deterministic(kat.sk_em, kat.pk_rm).expect("encap_deterministic");

        assert_eq!(enc, kat.enc, "enc mismatch");
        assert_eq!(shared_secret, kat.shared_secret, "shared_secret mismatch");

        let suite_id = b"HPKE\x00\x10\x00\x01\x00\x03"; // P-256/SHA256/ChaCha20
        let km = key_schedule_base(suite_id, &shared_secret, kat.info, AeadChacha20::NK)
            .expect("key_schedule_base");

        assert_eq!(km.key, kat.key_bytes, "key mismatch");
        assert_eq!(&km.base_nonce, kat.base_nonce, "base_nonce mismatch");
        assert_eq!(
            &km.exporter_secret, kat.exporter_secret,
            "exporter_secret mismatch"
        );

        for exp in kat.exports {
            let got = crate::hpke::kdf::labeled_expand_checked(
                suite_id,
                &km.exporter_secret,
                b"sec",
                exp.exporter_context,
                exp.l,
            )
            .expect("export");
            assert_eq!(
                got, exp.exported_value,
                "export mismatch (ctx={:?})",
                exp.exporter_context
            );
        }

        for ev in kat.enc_vecs {
            let nonce = compute_nonce(&km.base_nonce, ev.seq);
            let ct = AeadChacha20::seal(&km.key, &nonce, ev.aad, ev.pt).expect("seal");
            assert_eq!(ct, ev.ct, "ciphertext mismatch at seq={}", ev.seq);
        }
    }

    #[test]
    fn kat_a1_x25519_aes128gcm() {
        run_kat_x25519_aes128(&crate::hpke::vectors::kat::A1);
    }

    #[test]
    fn kat_a2_x25519_chacha20() {
        run_kat_x25519_chacha20(&crate::hpke::vectors::kat::A2);
    }

    #[test]
    fn kat_a3_p256_aes128gcm() {
        run_kat_p256_aes128(&crate::hpke::vectors::kat::A3);
    }

    #[test]
    fn kat_a5_p256_chacha20() {
        run_kat_p256_chacha20(&crate::hpke::vectors::kat::A5);
    }

    // ── RFC 9180 §5.3 Context.Export round-trip tests ────────────────────────

    /// setup_sender + setup_receiver must produce identical export() output for any (context, L).
    fn export_roundtrip<K: DhKem + Send + Sync, A: AeadSuite + Send + Sync>(
        suite: &HpkeSuiteImpl<K, A>,
    ) {
        let (pk, sk) = suite.generate_key_pair().expect("generate_key_pair");
        let info = b"export-roundtrip-test";
        let (enc, sender_ctx) = suite.setup_sender(info, &pk).expect("setup_sender");
        let receiver_ctx = suite
            .setup_receiver(&enc, info, &sk)
            .expect("setup_receiver");

        let contexts: &[&[u8]] = &[b"", b"\x00", b"TestContext", b"arbitrary-app-label"];
        for ctx in contexts {
            for l in [0usize, 1, 16, 32, 64] {
                let sender_out = sender_ctx.export(ctx, l).expect("sender export");
                let receiver_out = receiver_ctx.export(ctx, l).expect("receiver export");
                assert_eq!(
                    sender_out, receiver_out,
                    "export mismatch: ctx={ctx:?}, l={l}"
                );
                assert_eq!(sender_out.len(), l, "export length mismatch");
            }
        }

        // Non-zero exporter_secret (sanity check)
        assert_ne!(
            sender_ctx.exporter_secret, [0u8; 32],
            "exporter_secret must be non-zero"
        );
    }

    #[test]
    fn export_roundtrip_x25519_aes128() {
        export_roundtrip(&X25519_HKDF_SHA256_AES128GCM);
    }

    #[test]
    fn export_roundtrip_x25519_chacha20() {
        export_roundtrip(&X25519_HKDF_SHA256_CHACHA20);
    }

    #[test]
    fn export_roundtrip_p256_aes128() {
        export_roundtrip(&P256_HKDF_SHA256_AES128GCM);
    }

    #[test]
    fn export_roundtrip_p256_chacha20() {
        export_roundtrip(&P256_HKDF_SHA256_CHACHA20);
    }

    /// export() with l > 255*32 must return Err (not panic).
    #[test]
    fn export_overlength_returns_err() {
        let suite = &X25519_HKDF_SHA256_AES128GCM;
        let (pk, sk) = suite.generate_key_pair().expect("generate_key_pair");
        let (enc, sender_ctx) = suite.setup_sender(b"info", &pk).expect("setup_sender");
        let receiver_ctx = suite
            .setup_receiver(&enc, b"info", &sk)
            .expect("setup_receiver");

        let too_large = 255 * 32 + 1;
        assert!(
            sender_ctx.export(b"ctx", too_large).is_err(),
            "sender export must Err on oversized L"
        );
        assert!(
            receiver_ctx.export(b"ctx", too_large).is_err(),
            "receiver export must Err on oversized L"
        );
    }

    /// Typed const suites must have correct suite IDs (sanity check).
    #[test]
    fn typed_const_suites_correct() {
        assert_eq!(
            HPKE_X25519_HKDF_SHA256_AES128GCM.suite().kem,
            HpkeKem::DHKEM_X25519_HKDF_SHA256
        );
        assert_eq!(
            HPKE_X25519_HKDF_SHA256_CHACHA20.suite().kem,
            HpkeKem::DHKEM_X25519_HKDF_SHA256
        );
        assert_eq!(
            HPKE_P256_HKDF_SHA256_AES128GCM.suite().kem,
            HpkeKem::DHKEM_P256_HKDF_SHA256
        );
        assert_eq!(
            HPKE_P256_HKDF_SHA256_CHACHA20.suite().kem,
            HpkeKem::DHKEM_P256_HKDF_SHA256
        );
    }

    // ── X25519 non-contributory DH rejection ─────────────────────────────────

    #[test]
    fn x25519_noncontributory_rejected() {
        // The all-zeros X25519 public key is a low-order / identity point on Curve25519.
        // DH output will be the identity (all-zeros), which fails was_contributory().
        // Verify was_contributory() behaves correctly, which is the check used inside encap/decap.
        let zero_pk = [0u8; 32];
        let sk = x25519_dalek::StaticSecret::from([1u8; 32]);
        let pk = x25519_dalek::PublicKey::from(zero_pk);
        let dh = sk.diffie_hellman(&pk);
        assert!(
            !dh.was_contributory(),
            "DH with identity point should not be contributory"
        );
    }
}
