// SPDX-License-Identifier: Apache-2.0
// Copyright COOLJAPAN OU (Team Kitasan)
//! PKCS#11-backed [`rustls::sign::SigningKey`] and [`rustls::sign::Signer`] implementations.
//!
//! This module is only compiled when the `pkcs11` feature is active.

use std::path::Path;
use std::sync::Arc;

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::rsa::PkcsPssParams;
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::KeyType;
use cryptoki::slot::Slot;

use rustls::{Error as RustlsError, SignatureAlgorithm, SignatureScheme};

use crate::error::{Pkcs11Error, PkcsSignError};
use crate::pool::Pkcs11SessionPool;
use crate::session::{find_private_key_by_label, open_user_session, probe_key_type};

// ─── DER encoding helper ─────────────────────────────────────────────────────

/// Convert a raw r||s ECDSA signature (64 bytes for P-256) into DER/ASN.1.
///
/// rustls requires DER-encoded ECDSA signatures, but many HSMs produce raw
/// concatenated r||s bytes.  If the token already returns DER the caller
/// detects this (tag byte 0x30) and skips this function.
fn raw_ecdsa_to_der(raw: &[u8]) -> Result<Vec<u8>, PkcsSignError> {
    if !raw.len().is_multiple_of(2) {
        return Err(PkcsSignError::InvalidSignatureLength {
            expected: raw.len() / 2 * 2,
            got: raw.len(),
        });
    }
    let half = raw.len() / 2;
    let r = &raw[..half];
    let s = &raw[half..];

    let encode_int = |bytes: &[u8]| -> Vec<u8> {
        // Strip leading zero bytes, then re-add one if the high bit is set.
        let stripped: Vec<u8> = {
            let trimmed: &[u8] = bytes
                .iter()
                .position(|&b| b != 0)
                .map(|i| &bytes[i..])
                .unwrap_or(&[0u8][..]);
            trimmed.to_vec()
        };
        let needs_pad = stripped.first().copied().unwrap_or(0) >= 0x80;
        let content_len = stripped.len() + usize::from(needs_pad);
        let mut enc = Vec::with_capacity(2 + content_len);
        enc.push(0x02); // INTEGER tag
        enc.push(content_len as u8);
        if needs_pad {
            enc.push(0x00);
        }
        enc.extend_from_slice(&stripped);
        enc
    };

    let r_enc = encode_int(r);
    let s_enc = encode_int(s);
    let seq_len = r_enc.len() + s_enc.len();
    let mut der = Vec::with_capacity(2 + seq_len);
    der.push(0x30); // SEQUENCE tag
    der.push(seq_len as u8);
    der.extend_from_slice(&r_enc);
    der.extend_from_slice(&s_enc);
    Ok(der)
}

// ─── SigningBackend trait seam ────────────────────────────────────────────────

/// Trait seam for the raw PKCS#11 signing operation.
///
/// The key handle is held by the backend so that callers of [`sign_internal`]
/// do not need to construct an [`cryptoki::object::ObjectHandle`].  This keeps
/// the trait testable with a pure-Rust mock in safe code, because the handle
/// can be obtained once (from a real session) and stored in the production
/// backend, while the mock simply ignores it.
pub(crate) trait SigningBackend {
    fn sign_raw(&self, mechanism: &Mechanism, message: &[u8]) -> Result<Vec<u8>, PkcsSignError>;
}

/// Production backend: delegates to a real `cryptoki::Session`.
///
/// Holds the session reference *and* the resolved key handle, so the handle
/// does not need to be threaded through the public `sign_internal` API.
pub(crate) struct CryptokiSigningBackend<'sess> {
    session: &'sess cryptoki::session::Session,
    key_handle: cryptoki::object::ObjectHandle,
}

impl<'sess> CryptokiSigningBackend<'sess> {
    pub(crate) fn new(
        session: &'sess cryptoki::session::Session,
        key_handle: cryptoki::object::ObjectHandle,
    ) -> Self {
        Self {
            session,
            key_handle,
        }
    }
}

impl<'sess> SigningBackend for CryptokiSigningBackend<'sess> {
    fn sign_raw(&self, mechanism: &Mechanism, message: &[u8]) -> Result<Vec<u8>, PkcsSignError> {
        self.session
            .sign(mechanism, self.key_handle, message)
            .map_err(|e| PkcsSignError::SignError(e.to_string()))
    }
}

/// Core signing routine via an injectable backend.
///
/// Separates the raw HSM call from post-processing so tests can inject a
/// pure-Rust mock backend without any PKCS#11 module present.
pub(crate) fn sign_internal(
    backend: &dyn SigningBackend,
    mechanism: &Mechanism,
    message: &[u8],
    scheme: SignatureScheme,
) -> Result<Vec<u8>, PkcsSignError> {
    let raw_sig = backend.sign_raw(mechanism, message)?;
    finalize_signature(scheme, raw_sig)
}

// ─── Pool-backed Signer (single-use, per-signature) ──────────────────────────

/// A single-use pool-backed signer that acquires a session from the shared pool.
#[derive(Debug)]
pub(crate) struct Pkcs11PooledSigner {
    pool: Arc<Pkcs11SessionPool>,
    key_label: String,
    scheme: SignatureScheme,
}

impl Pkcs11PooledSigner {
    pub(crate) fn new(
        pool: Arc<Pkcs11SessionPool>,
        key_label: String,
        scheme: SignatureScheme,
    ) -> Self {
        Self {
            pool,
            key_label,
            scheme,
        }
    }
}

impl rustls::sign::Signer for Pkcs11PooledSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, RustlsError> {
        sign_via_pool(&self.pool, &self.key_label, self.scheme, message)
            .map_err(|e| RustlsError::General(e.to_string()))
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

// ─── Legacy Signer (single-use, per-signature) ───────────────────────────────

/// A single-use signer that holds enough state to call `C_Sign` on demand.
#[derive(Debug)]
pub(crate) struct Pkcs11Signer {
    pkcs11: Arc<Pkcs11>,
    slot: Slot,
    pin: String,
    key_label: String,
    scheme: SignatureScheme,
}

impl Pkcs11Signer {
    pub(crate) fn new(
        pkcs11: Arc<Pkcs11>,
        slot: Slot,
        pin: String,
        key_label: String,
        scheme: SignatureScheme,
    ) -> Self {
        Self {
            pkcs11,
            slot,
            pin,
            key_label,
            scheme,
        }
    }
}

impl rustls::sign::Signer for Pkcs11Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, RustlsError> {
        sign_with_pkcs11(
            &self.pkcs11,
            self.slot,
            &self.pin,
            &self.key_label,
            self.scheme,
            message,
        )
        .map_err(|e| RustlsError::General(e.to_string()))
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

// ─── Signing key ─────────────────────────────────────────────────────────────

/// Backing storage for a [`Pkcs11SigningKey`].
///
/// Two modes are supported:
/// - **Pool-backed** (`from_pool`): uses a shared session pool for concurrent
///   TLS handshakes.  This is the recommended mode for production use via
///   [`crate::provider::Pkcs11TlsProvider`].
/// - **Direct** (`new`): creates its own `Pkcs11` context.  Kept for
///   backward compatibility.
#[derive(Debug)]
enum SigningKeyBackend {
    Pool {
        pool: Arc<Pkcs11SessionPool>,
    },
    Direct {
        pkcs11: Arc<Pkcs11>,
        slot: Slot,
        pin: String,
    },
}

/// A PKCS#11-backed [`rustls::sign::SigningKey`].
///
/// Supports two construction modes: pool-backed (preferred) via [`Self::new`],
/// and direct module-loading via [`Self::new_direct`].
#[derive(Debug)]
pub struct Pkcs11SigningKey {
    backend: SigningKeyBackend,
    key_label: String,
    /// Cached algorithm family detected at construction time.
    algorithm: SignatureAlgorithm,
}

impl Pkcs11SigningKey {
    /// Construct a new pool-backed signing key.
    ///
    /// Acquires a session from `pool` to probe the key type once, then
    /// releases it.  The algorithm is cached so that `algorithm()` can return
    /// without I/O.
    ///
    /// # Errors
    ///
    /// Returns [`Pkcs11Error`] if the pool is exhausted, the key is not found,
    /// or the key type is unsupported.
    pub fn new(pool: Arc<Pkcs11SessionPool>, key_label: &str) -> Result<Self, Pkcs11Error> {
        let algorithm = {
            let pooled = pool.acquire()?;
            let session = pooled.session();
            let handle =
                find_private_key_by_label(session, key_label).map_err(Pkcs11Error::from)?;
            let kt = probe_key_type(session, handle).map_err(Pkcs11Error::from)?;
            key_type_to_algorithm(kt)
                .map_err(|e| Pkcs11Error::Other(format!("unsupported key type: {e}")))?
        };

        Ok(Self {
            backend: SigningKeyBackend::Pool { pool },
            key_label: key_label.to_string(),
            algorithm,
        })
    }

    /// Construct a direct (module-loading) signing key.
    ///
    /// Loads the PKCS#11 module at `module_path`, initializes it, and opens
    /// a temporary session to probe the key type.  Each signing operation
    /// opens a new session.
    ///
    /// This constructor is provided for backward compatibility.  New code
    /// should prefer [`Self::new`] with a [`Pkcs11SessionPool`].
    ///
    /// # Errors
    ///
    /// Returns [`PkcsSignError`] if the module cannot be loaded, the slot is
    /// invalid, or the key label is not found.
    pub fn new_direct(
        module_path: &Path,
        slot: Slot,
        pin: &str,
        key_label: &str,
    ) -> Result<Self, PkcsSignError> {
        let pkcs11 =
            Pkcs11::new(module_path).map_err(|e| PkcsSignError::InitError(e.to_string()))?;

        pkcs11
            .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .map_err(|e| PkcsSignError::InitError(format!("C_Initialize failed: {e}")))?;

        let pkcs11 = Arc::new(pkcs11);

        // Probe key type once to cache the algorithm family.
        let algorithm = {
            let session = open_user_session(&pkcs11, slot, pin)?;
            let handle = find_private_key_by_label(&session, key_label)?;
            let kt = probe_key_type(&session, handle)?;
            key_type_to_algorithm(kt)?
        };

        Ok(Self {
            backend: SigningKeyBackend::Direct {
                pkcs11,
                slot,
                pin: pin.to_string(),
            },
            key_label: key_label.to_string(),
            algorithm,
        })
    }
}

impl rustls::sign::SigningKey for Pkcs11SigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn rustls::sign::Signer>> {
        // Pick the best matching scheme from what the TLS peer offered.
        let preferred = preferred_schemes(self.algorithm);
        for &scheme in preferred {
            if offered.contains(&scheme) {
                return match &self.backend {
                    SigningKeyBackend::Pool { pool } => Some(Box::new(Pkcs11PooledSigner::new(
                        Arc::clone(pool),
                        self.key_label.clone(),
                        scheme,
                    ))),
                    SigningKeyBackend::Direct { pkcs11, slot, pin } => {
                        Some(Box::new(Pkcs11Signer::new(
                            Arc::clone(pkcs11),
                            *slot,
                            pin.clone(),
                            self.key_label.clone(),
                            scheme,
                        )))
                    }
                };
            }
        }
        None
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Map a cryptoki [`KeyType`] to the corresponding rustls [`SignatureAlgorithm`].
fn key_type_to_algorithm(kt: KeyType) -> Result<SignatureAlgorithm, PkcsSignError> {
    if kt == KeyType::EC {
        Ok(SignatureAlgorithm::ECDSA)
    } else if kt == KeyType::RSA {
        Ok(SignatureAlgorithm::RSA)
    } else {
        Err(PkcsSignError::KeyNotFound(format!(
            "unsupported PKCS#11 key type: {kt:?}"
        )))
    }
}

/// Return the ordered list of [`SignatureScheme`]s to try for a given
/// algorithm family (most preferred first).
fn preferred_schemes(algorithm: SignatureAlgorithm) -> &'static [SignatureScheme] {
    match algorithm {
        SignatureAlgorithm::ECDSA => &[
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP256_SHA256,
        ],
        SignatureAlgorithm::RSA => &[
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA256,
        ],
        // Treat everything else as empty — choose_scheme will return None.
        _ => &[],
    }
}

/// Map a rustls [`SignatureScheme`] to the appropriate cryptoki [`Mechanism`].
///
/// RSA-PSS schemes use `Mechanism::RsaPkcsPss` with the correct
/// `PkcsPssParams` (hash algorithm, MGF, salt length = hash output length).
fn scheme_to_mechanism(scheme: SignatureScheme) -> Result<Mechanism<'static>, PkcsSignError> {
    match scheme {
        SignatureScheme::ECDSA_NISTP256_SHA256 => Ok(Mechanism::EcdsaSha256),
        SignatureScheme::ECDSA_NISTP384_SHA384 => Ok(Mechanism::EcdsaSha384),
        SignatureScheme::RSA_PKCS1_SHA256 => Ok(Mechanism::Sha256RsaPkcs),
        SignatureScheme::RSA_PKCS1_SHA384 => Ok(Mechanism::Sha384RsaPkcs),
        SignatureScheme::RSA_PKCS1_SHA512 => Ok(Mechanism::Sha512RsaPkcs),
        // RSA-PSS: use the correct mechanism with explicit hash + MGF + salt params.
        // Salt length equals the hash output length per RFC 8446 §4.2.3.
        SignatureScheme::RSA_PSS_SHA256 => Ok(Mechanism::RsaPkcsPss(PkcsPssParams {
            hash_alg: MechanismType::SHA256,
            mgf: cryptoki::mechanism::rsa::PkcsMgfType::MGF1_SHA256,
            s_len: 32_u64.into(), // SHA-256 output = 32 bytes
        })),
        SignatureScheme::RSA_PSS_SHA384 => Ok(Mechanism::RsaPkcsPss(PkcsPssParams {
            hash_alg: MechanismType::SHA384,
            mgf: cryptoki::mechanism::rsa::PkcsMgfType::MGF1_SHA384,
            s_len: 48_u64.into(), // SHA-384 output = 48 bytes
        })),
        SignatureScheme::RSA_PSS_SHA512 => Ok(Mechanism::RsaPkcsPss(PkcsPssParams {
            hash_alg: MechanismType::SHA512,
            mgf: cryptoki::mechanism::rsa::PkcsMgfType::MGF1_SHA512,
            s_len: 64_u64.into(), // SHA-512 output = 64 bytes
        })),
        _ => Err(PkcsSignError::SignError(format!(
            "unsupported signature scheme: {scheme:?}"
        ))),
    }
}

/// Sign `message` via a pool-acquired session.
fn sign_via_pool(
    pool: &Pkcs11SessionPool,
    key_label: &str,
    scheme: SignatureScheme,
    message: &[u8],
) -> Result<Vec<u8>, PkcsSignError> {
    let pooled = pool
        .acquire()
        .map_err(|e| PkcsSignError::SessionError(format!("pool acquire failed: {e}")))?;
    let session = pooled.session();
    let handle = find_private_key_by_label(session, key_label)?;
    let mechanism = scheme_to_mechanism(scheme)?;
    let backend = CryptokiSigningBackend::new(session, handle);
    sign_internal(&backend, &mechanism, message, scheme)
}

/// Core signing routine: open a fresh session, find the key, call C_Sign.
fn sign_with_pkcs11(
    pkcs11: &Pkcs11,
    slot: Slot,
    pin: &str,
    key_label: &str,
    scheme: SignatureScheme,
    message: &[u8],
) -> Result<Vec<u8>, PkcsSignError> {
    let session = open_user_session(pkcs11, slot, pin)?;
    let handle = find_private_key_by_label(&session, key_label)?;
    let mechanism = scheme_to_mechanism(scheme)?;
    let backend = CryptokiSigningBackend::new(&session, handle);
    sign_internal(&backend, &mechanism, message, scheme)
}

/// Apply post-processing to a raw token signature.
///
/// - ECDSA: convert raw r||s to DER if needed.
/// - RSA: pass through unchanged.
fn finalize_signature(scheme: SignatureScheme, raw_sig: Vec<u8>) -> Result<Vec<u8>, PkcsSignError> {
    match scheme {
        SignatureScheme::ECDSA_NISTP256_SHA256 | SignatureScheme::ECDSA_NISTP384_SHA384 => {
            if raw_sig.first().copied() == Some(0x30) {
                // Already DER encoded — pass through.
                Ok(raw_sig)
            } else {
                raw_ecdsa_to_der(&raw_sig)
            }
        }
        // RSA PKCS#1 v1.5 and RSA-PSS: no conversion needed.
        _ => Ok(raw_sig),
    }
}

// ─── Test-only mock backend ───────────────────────────────────────────────────

/// Pure-Rust ECDSA P-256 mock for testing without a PKCS#11 module.
///
/// Uses a fixed deterministic signing key so tests are reproducible.
/// The mock ignores the mechanism and key handle — it always signs with
/// its internal P-256 key using the ECDSA algorithm.
#[cfg(test)]
pub(crate) struct MockEcdsaBackend {
    signing_key: p256::ecdsa::SigningKey,
}

#[cfg(test)]
impl MockEcdsaBackend {
    /// Construct a mock backend with a fixed deterministic P-256 signing key.
    pub(crate) fn new() -> Self {
        // 0x01 repeated 32 times is a valid non-zero scalar for P-256.
        let sk_bytes = [0x01u8; 32];
        let signing_key = p256::ecdsa::SigningKey::from_slice(&sk_bytes)
            .expect("fixed test scalar is valid for P-256");
        Self { signing_key }
    }

    /// Return the verifying key corresponding to the mock signing key.
    pub(crate) fn verifying_key(&self) -> p256::ecdsa::VerifyingKey {
        *self.signing_key.verifying_key()
    }
}

#[cfg(test)]
impl SigningBackend for MockEcdsaBackend {
    fn sign_raw(&self, _mechanism: &Mechanism, message: &[u8]) -> Result<Vec<u8>, PkcsSignError> {
        use p256::ecdsa::signature::Signer as _;
        let sig: p256::ecdsa::Signature = self.signing_key.sign(message);
        // Return raw r||s (64 bytes for P-256).
        Ok(sig.to_bytes().to_vec())
    }
}

// ─── Unit tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that `raw_ecdsa_to_der` produces valid DER SEQUENCE output for a
    /// known 64-byte r||s input.
    #[test]
    fn raw_ecdsa_to_der_is_valid_asn1() {
        let mut raw = vec![0u8; 64];
        raw[..32].fill(0x01); // r
        raw[32..].fill(0x02); // s

        let der = raw_ecdsa_to_der(&raw).expect("raw_ecdsa_to_der should succeed");

        // DER SEQUENCE: tag 0x30, then length, then content.
        assert_eq!(der[0], 0x30, "should start with DER SEQUENCE tag");
        assert!(der.len() > 10, "DER output should be non-trivial");
    }

    /// Verify that `raw_ecdsa_to_der` rejects odd-length input.
    #[test]
    fn raw_ecdsa_to_der_rejects_odd_length() {
        let raw = vec![0x01u8; 63]; // odd — not a valid r||s
        let err = raw_ecdsa_to_der(&raw).unwrap_err();
        match err {
            PkcsSignError::InvalidSignatureLength { .. } => {}
            other => panic!("unexpected error variant: {other}"),
        }
    }

    /// End-to-end test: `sign_internal` with `MockEcdsaBackend` produces a
    /// DER-encoded ECDSA-P256 signature that is cryptographically valid.
    ///
    /// This exercises the full pipeline through the trait seam:
    /// `sign_internal` → `MockEcdsaBackend::sign_raw` → raw r||s bytes →
    /// `finalize_signature` → `raw_ecdsa_to_der` → verified DER signature.
    /// No PKCS#11 module or HSM is required.
    #[test]
    fn mock_ecdsa_sign_internal_round_trip() {
        use p256::ecdsa::signature::Verifier as _;

        let mock = MockEcdsaBackend::new();
        let vk = mock.verifying_key();
        let message = b"oxitls PKCS11-signer mock test message";
        let mechanism = Mechanism::EcdsaSha256;

        let der = sign_internal(
            &mock,
            &mechanism,
            message,
            SignatureScheme::ECDSA_NISTP256_SHA256,
        )
        .expect("sign_internal should succeed with mock backend");

        // The finalized output must start with the DER SEQUENCE tag.
        assert_eq!(der[0], 0x30, "finalized signature must be DER-encoded");

        // Parse the DER bytes and verify cryptographically.
        let sig = p256::ecdsa::Signature::from_der(&der)
            .expect("DER output must be a valid ECDSA signature");
        vk.verify(message, &sig)
            .expect("signature must verify with the corresponding verifying key");
    }

    /// Verify that `sign_internal` with the mock backend returns valid DER
    /// for a short message, confirming `raw_ecdsa_to_der` is applied.
    #[test]
    fn mock_ecdsa_sign_internal_produces_der() {
        let mock = MockEcdsaBackend::new();
        let mechanism = Mechanism::EcdsaSha256;

        let der = sign_internal(
            &mock,
            &mechanism,
            b"test",
            SignatureScheme::ECDSA_NISTP256_SHA256,
        )
        .expect("sign_internal should succeed");

        assert_eq!(der[0], 0x30, "output must be DER SEQUENCE");
        assert!(der.len() > 8, "DER output should be non-trivial");
    }
}
