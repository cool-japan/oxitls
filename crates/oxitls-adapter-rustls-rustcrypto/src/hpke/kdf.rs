//! RFC 9180 key derivation: LabeledExtract, LabeledExpand, and key schedule (base mode).
//!
//! All HKDF operations use SHA-256 throughout (the only KDF used by this module).
//! The `suite_id` passed to each function controls whether we are in the KEM
//! domain (b"KEM\x00\x20" / b"KEM\x00\x10") or the full HPKE domain
//! (b"HPKE\x00\x20\x00\x01\x00\x01" etc.).

use hkdf::Hkdf;
use sha2::Sha256;

/// HPKE-v1 prefix bytes shared by every LabeledExtract/Expand operation.
const HPKE_V1: &[u8] = b"HPKE-v1";

/// I2OSP(n, 2): encode `n` as 2 big-endian bytes.
#[inline]
fn i2osp2(n: u16) -> [u8; 2] {
    n.to_be_bytes()
}

/// RFC 9180 §4 LabeledExtract.
///
/// ```text
/// LabeledExtract(salt, label, ikm) =
///     Extract(salt, "HPKE-v1" || suite_id || label || ikm)
/// ```
///
/// Returns a 32-byte PRK (SHA-256 hash length).
pub fn labeled_extract(suite_id: &[u8], salt: &[u8], label: &[u8], ikm: &[u8]) -> [u8; 32] {
    // Build the labeled IKM by concatenating without allocation:
    //   "HPKE-v1" || suite_id || label || ikm
    // We feed them sequentially using GenericHkdfExtract.
    let mut extract_ctx = hkdf::HkdfExtract::<Sha256>::new(Some(salt));
    extract_ctx.input_ikm(HPKE_V1);
    extract_ctx.input_ikm(suite_id);
    extract_ctx.input_ikm(label);
    extract_ctx.input_ikm(ikm);
    let (prk, _) = extract_ctx.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(prk.as_slice());
    out
}

/// RFC 9180 §4 LabeledExpand.
///
/// ```text
/// LabeledExpand(prk, label, info, L) =
///     Expand(prk, I2OSP(L,2) || "HPKE-v1" || suite_id || label || info, L)
/// ```
///
/// Returns `l` bytes of output keying material.
///
/// # Errors
/// Returns `Err` if `prk` is shorter than 32 bytes, if `l` does not fit in a
/// `u16`, or if `l` exceeds the HKDF-SHA256 maximum (255 * 32 = 8160 bytes).
/// This is a thin, non-panicking wrapper around [`labeled_expand_checked`]
/// (defined below `key_schedule_base`) — kept as a free function so internal
/// callers with compile-time-constant `l` (12, 16, 32) don't need to move
/// their call sites relative to `key_schedule_base`.
pub fn labeled_expand(
    suite_id: &[u8],
    prk: &[u8],
    label: &[u8],
    info: &[u8],
    l: usize,
) -> Result<Vec<u8>, rustls::Error> {
    labeled_expand_checked(suite_id, prk, label, info, l)
}

/// Intermediate material produced by the HPKE base-mode key schedule.
pub struct HpkeKeyMaterial {
    /// AEAD key (length determined by `nk` parameter).
    pub key: Vec<u8>,
    /// 12-byte base nonce.
    pub base_nonce: [u8; 12],
    /// Exporter secret (32 bytes) — RFC 9180 §5.1 `exporter_secret`.
    pub exporter_secret: [u8; 32],
}

/// RFC 9180 §5.1 key schedule for base mode (mode = 0).
///
/// `suite_id`    — full HPKE suite_id (b"HPKE" || kem_id || kdf_id || aead_id)
/// `shared_secret` — 32-byte shared secret from KEM Encap/Decap
/// `info`        — application-supplied context
/// `nk`          — AEAD key length (16 for AES-128-GCM, 32 for ChaCha20Poly1305)
pub fn key_schedule_base(
    suite_id: &[u8],
    shared_secret: &[u8],
    info: &[u8],
    nk: usize,
) -> Result<HpkeKeyMaterial, rustls::Error> {
    const MODE_BASE: u8 = 0;
    let default_psk = b"";
    let default_psk_id = b"";

    // psk_id_hash = LabeledExtract("", "psk_id_hash", default_psk_id)
    let psk_id_hash = labeled_extract(suite_id, b"", b"psk_id_hash", default_psk_id);

    // info_hash = LabeledExtract("", "info_hash", info)
    let info_hash = labeled_extract(suite_id, b"", b"info_hash", info);

    // ks_context = mode || psk_id_hash || info_hash  (65 bytes for SHA-256)
    let mut ks_context = vec![MODE_BASE];
    ks_context.extend_from_slice(&psk_id_hash);
    ks_context.extend_from_slice(&info_hash);

    // secret = LabeledExtract(shared_secret, "secret", default_psk)
    let secret = labeled_extract(suite_id, shared_secret, b"secret", default_psk);

    // key = LabeledExpand(secret, "key", ks_context, Nk)
    let key = labeled_expand(suite_id, &secret, b"key", &ks_context, nk)?;

    // base_nonce = LabeledExpand(secret, "base_nonce", ks_context, Nn=12)
    let base_nonce_vec = labeled_expand(suite_id, &secret, b"base_nonce", &ks_context, 12)?;

    let mut base_nonce = [0u8; 12];
    base_nonce.copy_from_slice(&base_nonce_vec);

    // exporter_secret = LabeledExpand(secret, "exp", ks_context, Nh=32)
    // RFC 9180 §5.1: exporter_secret is surfaced for use by Context.Export (§5.3).
    let exp_vec = labeled_expand(suite_id, &secret, b"exp", &ks_context, 32)?;
    let mut exporter_secret = [0u8; 32];
    exporter_secret.copy_from_slice(&exp_vec);

    Ok(HpkeKeyMaterial {
        key,
        base_nonce,
        exporter_secret,
    })
}

/// RFC 9180 §5.3 Context.Export: length-checked LabeledExpand.
///
/// This is the underlying implementation shared by [`labeled_expand`]. It is
/// kept as a separate, explicitly-named entry point because the public
/// Export path (where `l` may be attacker-influenced) documents its
/// error-returning contract independently of the internal key-schedule
/// caller in [`key_schedule_base`].
///
/// The maximum output length for HKDF-SHA256 is `255 * HashLen = 255 * 32 = 8160` bytes.
pub fn labeled_expand_checked(
    suite_id: &[u8],
    prk: &[u8],
    label: &[u8],
    info: &[u8],
    l: usize,
) -> Result<Vec<u8>, rustls::Error> {
    const MAX_L: usize = 255 * 32; // HKDF-SHA256 maximum output
    if l > MAX_L {
        return Err(rustls::Error::General(format!(
            "HPKE Export: requested length {l} exceeds maximum {MAX_L} bytes"
        )));
    }
    let l_u16 = u16::try_from(l)
        .map_err(|_| rustls::Error::General("HPKE Export: length does not fit in u16".into()))?;
    let hkdf = Hkdf::<Sha256>::from_prk(prk).map_err(|_| {
        rustls::Error::General("HPKE Export: invalid PRK (must be at least 32 bytes)".into())
    })?;
    let l_bytes = i2osp2(l_u16);
    let mut okm = vec![0u8; l];
    hkdf.expand_multi_info(
        &[l_bytes.as_slice(), HPKE_V1, suite_id, label, info],
        &mut okm,
    )
    .map_err(|_| rustls::Error::General("HPKE Export: HKDF expand failed".into()))?;
    Ok(okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity-check that LabeledExtract with a known empty-salt,
    /// empty-ikm, arbitrary label and suite_id produces 32 bytes.
    #[test]
    fn labeled_extract_returns_32_bytes() {
        let suite_id = b"HPKE\x00\x20\x00\x01\x00\x01";
        let prk = labeled_extract(suite_id, b"", b"secret", b"");
        assert_eq!(prk.len(), 32);
    }

    /// LabeledExpand with varying L.
    #[test]
    fn labeled_expand_varying_l() {
        let suite_id = b"HPKE\x00\x20\x00\x01\x00\x01";
        let prk = labeled_extract(suite_id, b"", b"key", b"");
        for l in [12usize, 16, 32] {
            let out = labeled_expand(suite_id, &prk, b"key", b"ctx", l).expect("l within bounds");
            assert_eq!(out.len(), l);
        }
    }

    /// Regression guard: `labeled_expand` must return `Err`, not panic, on a
    /// too-short PRK. Before this fix it was `.expect()`-based and would abort
    /// the process (a DoS if `l`/`prk` were ever attacker-influenced).
    #[test]
    fn labeled_expand_short_prk_returns_err_not_panic() {
        let suite_id = b"HPKE\x00\x20\x00\x01\x00\x01";
        let short_prk = [0u8; 4]; // shorter than SHA-256's 32-byte output
        let result = labeled_expand(suite_id, &short_prk, b"key", b"ctx", 16);
        assert!(result.is_err(), "short PRK must be rejected, not panic");
    }

    /// Regression guard: `labeled_expand` must return `Err`, not panic, when
    /// `l` exceeds the HKDF-SHA256 maximum output length.
    #[test]
    fn labeled_expand_oversized_l_returns_err_not_panic() {
        let suite_id = b"HPKE\x00\x20\x00\x01\x00\x01";
        let prk = labeled_extract(suite_id, b"", b"key", b"");
        let result = labeled_expand(suite_id, &prk, b"key", b"ctx", 255 * 32 + 1);
        assert!(result.is_err(), "oversized l must be rejected, not panic");
    }
}
