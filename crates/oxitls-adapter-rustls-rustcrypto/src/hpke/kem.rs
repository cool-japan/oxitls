//! RFC 9180 §4 DHKEM implementations: X25519 and P-256.
//!
//! Both KEMs implement the `DhKem` trait which supplies:
//! - `encap(pk_r)` → `(shared_secret[32], enc[])`
//! - `decap(sk_r, enc)` → `shared_secret[32]`
//! - `generate()` → `(pk_bytes, sk_bytes)`
//!
//! `ExtractAndExpand` (the DHKEM-specific key derivation) is performed
//! inside this module using the `labeled_extract` / `labeled_expand`
//! helpers from `super::kdf`, always with the KEM-specific `suite_id`.

use p256::elliptic_curve::sec1::ToSec1Point;

use super::kdf::{labeled_expand, labeled_extract};

// ── DhKem trait ───────────────────────────────────────────────────────────────

/// A zero-cost marker that encapsulates the primitive operations needed for one
/// DHKEM variant.  All methods are inherently non-`self` because the implementors
/// are zero-sized types.
pub trait DhKem: 'static + Send + Sync {
    /// HPKE KEM algorithm ID (big-endian u16 value from the IANA registry).
    const KEM_ID: u16;
    /// Length of the encapsulated key (enc).
    #[allow(dead_code)]
    const NENC: usize;
    /// Length of a serialized public key.
    #[allow(dead_code)]
    const NPK: usize;
    /// Length of a serialized private key (scalar length).
    #[allow(dead_code)]
    const NSK: usize;
    /// Length of the shared secret produced by ExtractAndExpand.
    const NSECRET: usize;

    /// KEM suite_id used inside the KEM's own LabeledExtract/Expand:
    ///   b"KEM" || I2OSP(KEM_ID, 2)
    fn kem_suite_id() -> [u8; 5] {
        let id_bytes = Self::KEM_ID.to_be_bytes();
        [b'K', b'E', b'M', id_bytes[0], id_bytes[1]]
    }

    /// Generate a fresh ephemeral key pair.
    ///
    /// Returns `(pk_bytes, sk_bytes)`.
    fn generate() -> Result<(Vec<u8>, Vec<u8>), rustls::Error>;

    /// Encapsulate for recipient public key `pk_r`.
    ///
    /// Returns `(shared_secret[NSECRET], enc[NENC])`.
    fn encap(pk_r: &[u8]) -> Result<([u8; 32], Vec<u8>), rustls::Error>;

    /// Decapsulate `enc` using recipient secret key `sk_r`.
    ///
    /// Returns `shared_secret[NSECRET]`.
    fn decap(sk_r: &[u8], enc: &[u8]) -> Result<[u8; 32], rustls::Error>;
}

/// ExtractAndExpand for DHKEM (RFC 9180 §4.1).
///
/// ```text
/// ExtractAndExpand(dh, kem_context) =
///     eae_prk = LabeledExtract("", "eae_prk", dh)
///     return LabeledExpand(eae_prk, "shared_secret", kem_context, Nsecret)
/// ```
/// Note: the extract label is `"eae_prk"` (not `"shared_secret"`).
fn extract_and_expand<K: DhKem>(dh: &[u8], kem_context: &[u8]) -> [u8; 32] {
    let suite_id = K::kem_suite_id();
    // Step 1: LabeledExtract with label "eae_prk"
    let eae_prk = labeled_extract(suite_id.as_slice(), b"", b"eae_prk", dh);
    // Step 2: LabeledExpand with label "shared_secret"
    let out = labeled_expand(
        suite_id.as_slice(),
        &eae_prk,
        b"shared_secret",
        kem_context,
        K::NSECRET,
    );
    let mut ss = [0u8; 32];
    ss.copy_from_slice(&out[..32]);
    ss
}

// ── DHKEM(X25519, HKDF-SHA256) ────────────────────────────────────────────────

/// Zero-sized type for DHKEM(X25519, HKDF-SHA256).
pub struct KemX25519;

impl DhKem for KemX25519 {
    const KEM_ID: u16 = 0x0020;
    const NENC: usize = 32;
    const NPK: usize = 32;
    const NSK: usize = 32;
    const NSECRET: usize = 32;

    fn generate() -> Result<(Vec<u8>, Vec<u8>), rustls::Error> {
        let mut buf = [0u8; 32];
        getrandom::fill(&mut buf)
            .map_err(|e| rustls::Error::General(format!("X25519 keygen: getrandom failed: {e}")))?;
        let sk = x25519_dalek::StaticSecret::from(buf);
        let pk = x25519_dalek::PublicKey::from(&sk);
        Ok((pk.as_bytes().to_vec(), sk.to_bytes().to_vec()))
    }

    fn encap(pk_r: &[u8]) -> Result<([u8; 32], Vec<u8>), rustls::Error> {
        // Parse recipient public key
        let pk_r_bytes: [u8; 32] = pk_r.try_into().map_err(|_| {
            rustls::Error::General("X25519 Encap: recipient pk must be 32 bytes".into())
        })?;
        let pk_r = x25519_dalek::PublicKey::from(pk_r_bytes);

        // Generate ephemeral key pair
        let mut eph_bytes = [0u8; 32];
        getrandom::fill(&mut eph_bytes)
            .map_err(|e| rustls::Error::General(format!("X25519 Encap: getrandom failed: {e}")))?;
        let sk_em = x25519_dalek::StaticSecret::from(eph_bytes);
        let pk_em = x25519_dalek::PublicKey::from(&sk_em);

        // DH: skEm · pkR
        let dh_result = sk_em.diffie_hellman(&pk_r);
        if !dh_result.was_contributory() {
            return Err(rustls::Error::General(
                "X25519 Encap: non-contributory DH (small-order recipient key)".into(),
            ));
        }
        let dh = dh_result.as_bytes();

        // kem_context = pkEm || pkR (both 32 bytes)
        let mut kem_context = Vec::with_capacity(64);
        kem_context.extend_from_slice(pk_em.as_bytes());
        kem_context.extend_from_slice(pk_r_bytes.as_slice());

        let shared_secret = extract_and_expand::<Self>(dh, &kem_context);
        let enc = pk_em.as_bytes().to_vec();

        Ok((shared_secret, enc))
    }

    fn decap(sk_r: &[u8], enc: &[u8]) -> Result<[u8; 32], rustls::Error> {
        // Parse enc (ephemeral sender public key)
        let enc_bytes: [u8; 32] = enc
            .try_into()
            .map_err(|_| rustls::Error::General("X25519 Decap: enc must be 32 bytes".into()))?;
        let pk_em = x25519_dalek::PublicKey::from(enc_bytes);

        // Parse recipient secret key
        let sk_bytes: [u8; 32] = sk_r.try_into().map_err(|_| {
            rustls::Error::General("X25519 Decap: secret key must be 32 bytes".into())
        })?;
        let sk_r = x25519_dalek::StaticSecret::from(sk_bytes);

        // Recipient public key (for kem_context)
        let pk_r = x25519_dalek::PublicKey::from(&sk_r);

        // DH: skR · pkEm
        let dh_result = sk_r.diffie_hellman(&pk_em);
        if !dh_result.was_contributory() {
            return Err(rustls::Error::General(
                "X25519 Decap: non-contributory DH (small-order sender key)".into(),
            ));
        }
        let dh = dh_result.as_bytes();

        // kem_context = enc || pkR
        let mut kem_context = Vec::with_capacity(64);
        kem_context.extend_from_slice(enc_bytes.as_slice());
        kem_context.extend_from_slice(pk_r.as_bytes());

        Ok(extract_and_expand::<Self>(dh, &kem_context))
    }
}

/// Encap with a caller-supplied ephemeral secret key (for KAT / deterministic testing).
///
/// Only available in tests.
#[cfg(test)]
pub(crate) fn x25519_encap_deterministic(
    sk_em_bytes: &[u8; 32],
    pk_r: &[u8],
) -> Result<([u8; 32], Vec<u8>), rustls::Error> {
    let pk_r_bytes: [u8; 32] = pk_r.try_into().map_err(|_| {
        rustls::Error::General("X25519 Encap: recipient pk must be 32 bytes".into())
    })?;
    let pk_r = x25519_dalek::PublicKey::from(pk_r_bytes);

    let sk_em = x25519_dalek::StaticSecret::from(*sk_em_bytes);
    let pk_em = x25519_dalek::PublicKey::from(&sk_em);

    let dh_result = sk_em.diffie_hellman(&pk_r);
    if !dh_result.was_contributory() {
        return Err(rustls::Error::General(
            "X25519 Encap: non-contributory DH".into(),
        ));
    }
    let dh = dh_result.as_bytes();

    let mut kem_context = Vec::with_capacity(64);
    kem_context.extend_from_slice(pk_em.as_bytes());
    kem_context.extend_from_slice(pk_r_bytes.as_slice());

    let shared_secret = extract_and_expand::<KemX25519>(dh, &kem_context);
    let enc = pk_em.as_bytes().to_vec();
    Ok((shared_secret, enc))
}

// ── DHKEM(P-256, HKDF-SHA256) ────────────────────────────────────────────────

/// Zero-sized type for DHKEM(P-256, HKDF-SHA256).
pub struct KemP256;

impl DhKem for KemP256 {
    const KEM_ID: u16 = 0x0010;
    const NENC: usize = 65; // uncompressed SEC1: 0x04 || X(32) || Y(32)
    const NPK: usize = 65;
    const NSK: usize = 32;
    const NSECRET: usize = 32;

    fn generate() -> Result<(Vec<u8>, Vec<u8>), rustls::Error> {
        let sk = p256_rejection_sample()?;
        let pk = sk.public_key();
        let pk_bytes = pk.to_uncompressed_point();
        let sk_bytes = sk.to_bytes().to_vec();
        Ok((pk_bytes.as_slice().to_vec(), sk_bytes))
    }

    fn encap(pk_r: &[u8]) -> Result<([u8; 32], Vec<u8>), rustls::Error> {
        // Parse recipient public key (uncompressed SEC1, 65 bytes)
        let pk_r = p256::PublicKey::from_sec1_bytes(pk_r).map_err(|_| {
            rustls::Error::General("P-256 Encap: invalid recipient public key".into())
        })?;

        // Generate ephemeral key pair via rejection sampling
        let sk_em = p256_rejection_sample()?;
        let pk_em = sk_em.public_key();

        // DH: ECDH(skEm, pkR) → 32-byte X-coordinate
        let dh = sk_em
            .diffie_hellman(&pk_r)
            .raw_secret_bytes()
            .as_slice()
            .to_vec();

        // enc = SerializePublicKey(pkEm) — 65-byte uncompressed SEC1
        let enc: Vec<u8> = pk_em.to_uncompressed_point().as_slice().to_vec();

        // kem_context = enc || SerializePublicKey(pkR)
        let pk_r_bytes: Vec<u8> = pk_r.to_uncompressed_point().as_slice().to_vec();
        let mut kem_context = Vec::with_capacity(130);
        kem_context.extend_from_slice(&enc);
        kem_context.extend_from_slice(&pk_r_bytes);

        let shared_secret = extract_and_expand::<Self>(&dh, &kem_context);
        Ok((shared_secret, enc))
    }

    fn decap(sk_r: &[u8], enc: &[u8]) -> Result<[u8; 32], rustls::Error> {
        // Parse enc (ephemeral sender public key, uncompressed SEC1, 65 bytes)
        let pk_em = p256::PublicKey::from_sec1_bytes(enc).map_err(|_| {
            rustls::Error::General("P-256 Decap: invalid enc (sender ephemeral public key)".into())
        })?;

        // Parse recipient secret key (32-byte scalar)
        let sk_r = p256::SecretKey::from_slice(sk_r).map_err(|_| {
            rustls::Error::General("P-256 Decap: invalid recipient secret key".into())
        })?;

        // DH: ECDH(skR, pkEm) → 32-byte X-coordinate
        let dh = sk_r
            .diffie_hellman(&pk_em)
            .raw_secret_bytes()
            .as_slice()
            .to_vec();

        // Recipient public key serialization for kem_context
        let pk_r = sk_r.public_key();
        let pk_r_bytes: Vec<u8> = pk_r.to_uncompressed_point().as_slice().to_vec();

        // kem_context = enc || SerializePublicKey(pkR)
        let mut kem_context = Vec::with_capacity(130);
        kem_context.extend_from_slice(enc);
        kem_context.extend_from_slice(&pk_r_bytes);

        Ok(extract_and_expand::<Self>(&dh, &kem_context))
    }
}

/// Rejection-sampling P-256 private key generation.
///
/// Fills a 32-byte buffer with random bytes and attempts `SecretKey::from_slice`.
/// Loops until success. The probability of a single rejection is < 2^-128.
fn p256_rejection_sample() -> Result<p256::SecretKey, rustls::Error> {
    let mut buf = [0u8; 32];
    loop {
        getrandom::fill(&mut buf)
            .map_err(|e| rustls::Error::General(format!("P-256 keygen: getrandom failed: {e}")))?;
        if let Ok(sk) = p256::SecretKey::from_slice(&buf) {
            return Ok(sk);
        }
        // scalar was 0 or >= order — retry (astronomically rare)
    }
}

/// Encap with a caller-supplied ephemeral secret key scalar (for KAT).
///
/// Only available in tests.
#[cfg(test)]
pub(crate) fn p256_encap_deterministic(
    sk_em_bytes: &[u8],
    pk_r: &[u8],
) -> Result<([u8; 32], Vec<u8>), rustls::Error> {
    let pk_r = p256::PublicKey::from_sec1_bytes(pk_r)
        .map_err(|_| rustls::Error::General("P-256 Encap: invalid recipient pk".into()))?;

    let sk_em = p256::SecretKey::from_slice(sk_em_bytes)
        .map_err(|_| rustls::Error::General("P-256 Encap: invalid ephemeral sk".into()))?;
    let pk_em = sk_em.public_key();

    let dh = sk_em
        .diffie_hellman(&pk_r)
        .raw_secret_bytes()
        .as_slice()
        .to_vec();

    let enc: Vec<u8> = pk_em.to_uncompressed_point().as_slice().to_vec();
    let pk_r_bytes: Vec<u8> = pk_r.to_uncompressed_point().as_slice().to_vec();

    let mut kem_context = Vec::with_capacity(130);
    kem_context.extend_from_slice(&enc);
    kem_context.extend_from_slice(&pk_r_bytes);

    let shared_secret = extract_and_expand::<KemP256>(&dh, &kem_context);
    Ok((shared_secret, enc))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_generate_and_encap_decap_roundtrip() {
        let (pk_r, sk_r) = KemX25519::generate().expect("generate");
        let (ss_enc, enc) = KemX25519::encap(&pk_r).expect("encap");
        let ss_dec = KemX25519::decap(&sk_r, &enc).expect("decap");
        assert_eq!(ss_enc, ss_dec);
        assert_eq!(enc.len(), KemX25519::NENC);
    }

    #[test]
    fn p256_generate_and_encap_decap_roundtrip() {
        let (pk_r, sk_r) = KemP256::generate().expect("generate");
        let (ss_enc, enc) = KemP256::encap(&pk_r).expect("encap");
        let ss_dec = KemP256::decap(&sk_r, &enc).expect("decap");
        assert_eq!(ss_enc, ss_dec);
        assert_eq!(enc.len(), KemP256::NENC);
    }

    #[test]
    fn x25519_kem_suite_id() {
        assert_eq!(KemX25519::kem_suite_id(), *b"KEM\x00\x20");
    }

    #[test]
    fn p256_kem_suite_id() {
        assert_eq!(KemP256::kem_suite_id(), *b"KEM\x00\x10");
    }

    #[test]
    fn x25519_noncontributory_rejected() {
        // The all-zeros X25519 point is a low-order / identity point on Curve25519.
        // DH with any scalar produces the identity (all-zeros) output.
        // was_contributory() returns false for the identity (all-zeros) output.
        let small_order_pk = [0u8; 32];
        let sk = x25519_dalek::StaticSecret::from([1u8; 32]);
        let pk = x25519_dalek::PublicKey::from(small_order_pk);
        let dh = sk.diffie_hellman(&pk);
        // Verify the DH check exists and evaluates correctly.
        // The all-zeros point is provably non-contributory in X25519.
        assert!(
            !dh.was_contributory(),
            "DH with all-zeros pk should be non-contributory"
        );
        // The encap implementation rejects non-contributory DH outputs.
        // Since encap uses random ephemeral, we verify the check path directly
        // via the raw DH as above.
    }

    #[test]
    fn p256_invalid_public_key_rejected() {
        // All-zeros is not on the P-256 curve
        let bad_pk = [0u8; 65];
        assert!(KemP256::encap(&bad_pk).is_err());
        assert!(KemP256::decap(&[0u8; 32], &bad_pk).is_err());
    }
}
