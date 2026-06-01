//! OxiCrypto-backed signing key types that implement rcgen's `SigningKey` /
//! `PublicKeyData` trait pair without ever touching ring or aws-lc-rs.
//!
//! # Algorithms
//!
//! | Type | rcgen algorithm |
//! |------|-----------------|
//! | [`OxiEd25519Key`] | `PKCS_ED25519` |
//! | [`OxiEcdsaP256Key`] | `PKCS_ECDSA_P256_SHA256` |
//! | [`OxiEcdsaP384Key`] | `PKCS_ECDSA_P384_SHA384` |
//! | [`OxiRsa2048Key`] | `PKCS_RSA_SHA256` (2048-bit modulus) |
//! | [`OxiRsa4096Key`] | `PKCS_RSA_SHA256` (4096-bit modulus) |
//!
//! # PKCS#8 DER export
//!
//! Each key type exposes `pkcs8_der()` returning the raw PKCS#8 DER bytes so
//! that tests can hand them to rustls via
//! `PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(bytes))`.

use ed25519_dalek::{pkcs8::EncodePrivateKey as DalekPkcs8, SigningKey as DalekSigningKey};
use getrandom::fill as random_fill;
use p256::{
    ecdsa::{
        signature::Signer as EcdsaSigner, Signature as P256Signature, SigningKey as P256SigningKey,
    },
    pkcs8::EncodePrivateKey as P256Pkcs8,
};
use p384::ecdsa::{Signature as P384Signature, SigningKey as P384SigningKey};
use rcgen::{
    PublicKeyData, SignatureAlgorithm, SigningKey, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384,
    PKCS_ED25519, PKCS_RSA_SHA256,
};
use rsa::{
    pkcs1::EncodeRsaPublicKey as RsaEncodePublicKeyPkcs1,
    pkcs1v15::SigningKey as RsaPkcs1v15SigningKey,
    pkcs8::DecodePrivateKey as RsaDecodePrivateKey,
    sha2::Sha256 as RsaSha256,
    signature::{RandomizedSigner, SignatureEncoding as RsaSignatureEncoding},
    RsaPrivateKey,
};

use oxitls_core::TlsError;

// ── Ed25519 ───────────────────────────────────────────────────────────────────

/// An Ed25519 signing key backed by `ed25519-dalek`, implementing rcgen's
/// [`SigningKey`] + [`PublicKeyData`] pair.
///
/// The public key is the raw 32-byte Edwards-y point, which is what rcgen
/// places in the SubjectPublicKeyInfo BIT STRING for `PKCS_ED25519`.
pub struct OxiEd25519Key {
    inner: DalekSigningKey,
    /// Cached public key bytes (32 bytes) — avoids temporary lifetime in `der_bytes()`.
    pub_key_bytes: [u8; 32],
    /// Cached PKCS#8 DER for hand-off to rustls.
    pkcs8_der_bytes: Vec<u8>,
}

impl OxiEd25519Key {
    /// Generate a new random Ed25519 key pair using OS entropy.
    ///
    /// # Errors
    /// Returns [`TlsError::Other`] if the OS RNG fails.
    pub fn generate() -> Result<Self, TlsError> {
        let mut seed = [0u8; 32];
        random_fill(&mut seed).map_err(|e| TlsError::Other(e.to_string()))?;
        Self::from_seed(seed)
    }

    /// Construct from a 32-byte raw seed.
    ///
    /// # Errors
    /// Returns [`TlsError::Other`] if PKCS#8 serialization fails.
    pub fn from_seed(seed: [u8; 32]) -> Result<Self, TlsError> {
        let inner = DalekSigningKey::from_bytes(&seed);
        let pub_key_bytes = *inner.verifying_key().as_bytes();
        let doc = inner
            .to_pkcs8_der()
            .map_err(|e| TlsError::Other(e.to_string()))?;
        let pkcs8_der_bytes = doc.as_bytes().to_vec();
        Ok(Self {
            inner,
            pub_key_bytes,
            pkcs8_der_bytes,
        })
    }

    /// Return the PKCS#8 DER bytes for the private key.
    ///
    /// Pass these to rustls via:
    /// ```ignore
    /// PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.pkcs8_der()))
    /// ```
    pub fn pkcs8_der(&self) -> &[u8] {
        &self.pkcs8_der_bytes
    }
}

impl PublicKeyData for OxiEd25519Key {
    /// Raw 32-byte public key (Edwards-y point), as expected by rcgen for
    /// `PKCS_ED25519`.
    fn der_bytes(&self) -> &[u8] {
        &self.pub_key_bytes
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &PKCS_ED25519
    }
}

impl SigningKey for OxiEd25519Key {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        use ed25519_dalek::Signer as DalekSign;
        let sig: ed25519_dalek::Signature = self.inner.sign(msg);
        Ok(sig.to_bytes().to_vec())
    }
}

// ── ECDSA P-256 ───────────────────────────────────────────────────────────────

/// An ECDSA P-256 signing key backed by the `p256` crate, implementing rcgen's
/// [`SigningKey`] + [`PublicKeyData`] pair.
///
/// `der_bytes()` returns the **uncompressed** (65-byte, `0x04 ‖ X ‖ Y`) SEC1
/// public key, which is what rcgen places in the SubjectPublicKeyInfo BIT
/// STRING for `PKCS_ECDSA_P256_SHA256`.
pub struct OxiEcdsaP256Key {
    inner: P256SigningKey,
    /// Uncompressed SEC1 public key (65 bytes) — cached to satisfy lifetime.
    uncompressed_pub: Vec<u8>,
    /// Cached PKCS#8 DER for hand-off to rustls.
    pkcs8_der_bytes: Vec<u8>,
}

impl OxiEcdsaP256Key {
    /// Generate a new random P-256 key pair using OS entropy.
    ///
    /// # Errors
    /// Returns [`TlsError::Other`] if the OS RNG or PKCS#8 serialization fails.
    pub fn generate() -> Result<Self, TlsError> {
        // Retry loop handles the astronomically unlikely case of getrandom
        // returning the zero scalar.
        loop {
            let mut scalar = [0u8; 32];
            random_fill(&mut scalar).map_err(|e| TlsError::Other(e.to_string()))?;
            if let Some(key) = Self::try_from_scalar(scalar)? {
                return Ok(key);
            }
        }
    }

    /// Construct from a 32-byte raw scalar (big-endian).
    ///
    /// Returns `None` when the scalar is the zero element.
    ///
    /// # Errors
    /// Returns [`TlsError::Other`] if PKCS#8 serialization fails.
    fn try_from_scalar(scalar: [u8; 32]) -> Result<Option<Self>, TlsError> {
        let inner = match P256SigningKey::from_bytes((&scalar).into()) {
            Ok(k) => k,
            Err(_) => return Ok(None),
        };
        let doc = inner
            .to_pkcs8_der()
            .map_err(|e| TlsError::Other(e.to_string()))?;
        let pkcs8_der_bytes = doc.as_bytes().to_vec();
        // Uncompressed SEC1: 0x04 ‖ X ‖ Y (65 bytes)
        // p256 0.14+ uses `to_sec1_point(false)` instead of `to_encoded_point(false)`.
        let uncompressed_pub = inner
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec();
        Ok(Some(Self {
            inner,
            uncompressed_pub,
            pkcs8_der_bytes,
        }))
    }

    /// Return the PKCS#8 DER bytes for the private key.
    pub fn pkcs8_der(&self) -> &[u8] {
        &self.pkcs8_der_bytes
    }
}

impl PublicKeyData for OxiEcdsaP256Key {
    /// Uncompressed SEC1 public key (65 bytes: `0x04 ‖ X ‖ Y`), as required by
    /// WebPKI and rcgen's SubjectPublicKeyInfo encoding for P-256.
    fn der_bytes(&self) -> &[u8] {
        &self.uncompressed_pub
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &PKCS_ECDSA_P256_SHA256
    }
}

impl SigningKey for OxiEcdsaP256Key {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        let sig: P256Signature = self.inner.sign(msg);
        // rcgen expects the DER-encoded ASN.1 SEQUENCE signature for ECDSA.
        Ok(sig.to_der().as_bytes().to_vec())
    }
}

// ── ECDSA P-384 ───────────────────────────────────────────────────────────────

/// An ECDSA P-384 signing key backed by the `p384` crate, implementing rcgen's
/// [`SigningKey`] + [`PublicKeyData`] pair.
///
/// `der_bytes()` returns the **uncompressed** (97-byte, `0x04 ‖ X ‖ Y`) SEC1
/// public key, which is what rcgen places in the SubjectPublicKeyInfo BIT
/// STRING for `PKCS_ECDSA_P384_SHA384`.
pub struct OxiEcdsaP384Key {
    inner: P384SigningKey,
    /// Uncompressed SEC1 public key (97 bytes) — cached to satisfy lifetime.
    uncompressed_pub: Vec<u8>,
    /// Cached PKCS#8 DER for hand-off to rustls.
    pkcs8_der_bytes: Vec<u8>,
}

impl OxiEcdsaP384Key {
    /// Generate a new random P-384 key pair using OS entropy.
    ///
    /// # Errors
    /// Returns [`TlsError::Other`] if the OS RNG or PKCS#8 serialization fails.
    pub fn generate() -> Result<Self, TlsError> {
        loop {
            let mut scalar = [0u8; 48];
            random_fill(&mut scalar).map_err(|e| TlsError::Other(e.to_string()))?;
            if let Some(key) = Self::try_from_scalar(scalar)? {
                return Ok(key);
            }
        }
    }

    fn try_from_scalar(scalar: [u8; 48]) -> Result<Option<Self>, TlsError> {
        let inner = match P384SigningKey::from_bytes((&scalar).into()) {
            Ok(k) => k,
            Err(_) => return Ok(None),
        };
        let doc = inner
            .to_pkcs8_der()
            .map_err(|e| TlsError::Other(e.to_string()))?;
        let pkcs8_der_bytes = doc.as_bytes().to_vec();
        // Uncompressed SEC1: 0x04 ‖ X ‖ Y (97 bytes for P-384)
        let uncompressed_pub = inner
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec();
        Ok(Some(Self {
            inner,
            uncompressed_pub,
            pkcs8_der_bytes,
        }))
    }

    /// Return the PKCS#8 DER bytes for the private key.
    pub fn pkcs8_der(&self) -> &[u8] {
        &self.pkcs8_der_bytes
    }
}

impl PublicKeyData for OxiEcdsaP384Key {
    /// Uncompressed SEC1 public key (97 bytes: `0x04 ‖ X ‖ Y`), as required by
    /// WebPKI and rcgen's SubjectPublicKeyInfo encoding for P-384.
    fn der_bytes(&self) -> &[u8] {
        &self.uncompressed_pub
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &PKCS_ECDSA_P384_SHA384
    }
}

impl SigningKey for OxiEcdsaP384Key {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        let sig: P384Signature = self.inner.sign(msg);
        // rcgen expects the DER-encoded ASN.1 SEQUENCE signature for ECDSA.
        Ok(sig.to_der().as_bytes().to_vec())
    }
}

// ── RSA 2048 ─────────────────────────────────────────────────────────────────

/// An RSA-2048 signing key backed by the pure-Rust `rsa` crate, implementing
/// rcgen's [`SigningKey`] + [`PublicKeyData`] pair.
///
/// Uses PKCS#1 v1.5 with SHA-256 (matching `PKCS_RSA_SHA256`). The public key
/// bytes returned by `der_bytes()` are the DER-encoded `RSAPublicKey` SEQUENCE
/// (not the SubjectPublicKeyInfo wrapper — rcgen builds the SPKI wrapper itself).
pub struct OxiRsa2048Key {
    inner: RsaPrivateKey,
    /// DER-encoded `RSAPublicKey` (for the SPKI BIT STRING contents).
    pub_key_der: Vec<u8>,
    /// PKCS#8 DER of the private key.
    pkcs8_der_bytes: Vec<u8>,
}

impl OxiRsa2048Key {
    /// Generate a new 2048-bit RSA key pair using OS entropy.
    ///
    /// # Errors
    /// Returns [`TlsError::Other`] on key generation or serialization failure.
    pub fn generate() -> Result<Self, TlsError> {
        let mut rng = oxitls_core::OsRng;
        let inner = RsaPrivateKey::new(&mut rng, 2048)
            .map_err(|e| TlsError::Other(format!("RSA-2048 keygen: {e}")))?;
        Self::from_inner(inner)
    }

    /// Load a 2048-bit RSA key pair from PKCS#8 DER bytes.
    ///
    /// This is useful in tests where a pre-generated key is used to avoid the
    /// cost of RSA-2048 key generation in pure Rust (which can take over a
    /// minute without hardware acceleration).
    ///
    /// # Errors
    /// Returns [`TlsError::Other`] on parse or serialization failure.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, TlsError> {
        let inner = RsaPrivateKey::from_pkcs8_der(der)
            .map_err(|e| TlsError::Other(format!("RSA-2048 PKCS#8 parse: {e}")))?;
        Self::from_inner(inner)
    }

    fn from_inner(inner: RsaPrivateKey) -> Result<Self, TlsError> {
        // PKCS#1 RSAPublicKey DER (the BIT STRING contents expected by rcgen for RSA)
        let pub_key_der = inner
            .to_public_key()
            .to_pkcs1_der()
            .map_err(|e| TlsError::Other(format!("RSA-2048 pubkey PKCS#1 DER: {e}")))?
            .to_vec();

        let pkcs8_der_bytes = inner
            .to_pkcs8_der()
            .map_err(|e| TlsError::Other(format!("RSA-2048 PKCS#8 DER: {e}")))?
            .as_bytes()
            .to_vec();

        Ok(Self {
            inner,
            pub_key_der,
            pkcs8_der_bytes,
        })
    }

    /// Return the PKCS#8 DER bytes for the private key.
    pub fn pkcs8_der(&self) -> &[u8] {
        &self.pkcs8_der_bytes
    }
}

impl PublicKeyData for OxiRsa2048Key {
    /// PKCS#1 DER-encoded `RSAPublicKey` (SEQUENCE { INTEGER n, INTEGER e }).
    ///
    /// rcgen wraps this in the BIT STRING of the SubjectPublicKeyInfo. For RSA
    /// the BIT STRING content is the raw PKCS#1 `RSAPublicKey`, not the SPKI
    /// wrapper — the same format returned by ring/aws-lc's `kp.public_key()`.
    fn der_bytes(&self) -> &[u8] {
        &self.pub_key_der
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &PKCS_RSA_SHA256
    }
}

impl SigningKey for OxiRsa2048Key {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        use oxitls_core::OsRng;
        let signing_key = RsaPkcs1v15SigningKey::<RsaSha256>::new(self.inner.clone());
        let sig = signing_key
            .try_sign_with_rng(&mut OsRng, msg)
            .map_err(|_| rcgen::Error::RingUnspecified)?;
        Ok(sig.to_bytes().to_vec())
    }
}

// ── RSA 4096 ─────────────────────────────────────────────────────────────────

/// An RSA-4096 signing key backed by the pure-Rust `rsa` crate, implementing
/// rcgen's [`SigningKey`] + [`PublicKeyData`] pair.
///
/// Key generation takes 2–5 seconds on modern hardware. Uses PKCS#1 v1.5 with
/// SHA-256 (matching `PKCS_RSA_SHA256`).
pub struct OxiRsa4096Key {
    inner: RsaPrivateKey,
    /// DER-encoded SubjectPublicKeyInfo for the RSA public key.
    pub_key_der: Vec<u8>,
    /// PKCS#8 DER of the private key.
    pkcs8_der_bytes: Vec<u8>,
}

impl OxiRsa4096Key {
    /// Generate a new 4096-bit RSA key pair using OS entropy.
    ///
    /// # Errors
    /// Returns [`TlsError::Other`] on key generation or serialization failure.
    pub fn generate() -> Result<Self, TlsError> {
        let mut rng = oxitls_core::OsRng;
        let inner = RsaPrivateKey::new(&mut rng, 4096)
            .map_err(|e| TlsError::Other(format!("RSA-4096 keygen: {e}")))?;
        Self::from_inner(inner)
    }

    /// Load a 4096-bit RSA key pair from PKCS#8 DER bytes.
    ///
    /// This is useful in tests where a pre-generated key is used to avoid the
    /// cost of RSA-4096 key generation in pure Rust (which can take several
    /// minutes without hardware acceleration).
    ///
    /// # Errors
    /// Returns [`TlsError::Other`] on parse or serialization failure.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, TlsError> {
        let inner = RsaPrivateKey::from_pkcs8_der(der)
            .map_err(|e| TlsError::Other(format!("RSA-4096 PKCS#8 parse: {e}")))?;
        Self::from_inner(inner)
    }

    fn from_inner(inner: RsaPrivateKey) -> Result<Self, TlsError> {
        // PKCS#1 RSAPublicKey DER (the BIT STRING contents expected by rcgen for RSA)
        let pub_key_der = inner
            .to_public_key()
            .to_pkcs1_der()
            .map_err(|e| TlsError::Other(format!("RSA-4096 pubkey PKCS#1 DER: {e}")))?
            .to_vec();

        let pkcs8_der_bytes = inner
            .to_pkcs8_der()
            .map_err(|e| TlsError::Other(format!("RSA-4096 PKCS#8 DER: {e}")))?
            .as_bytes()
            .to_vec();

        Ok(Self {
            inner,
            pub_key_der,
            pkcs8_der_bytes,
        })
    }

    /// Return the PKCS#8 DER bytes for the private key.
    pub fn pkcs8_der(&self) -> &[u8] {
        &self.pkcs8_der_bytes
    }
}

impl PublicKeyData for OxiRsa4096Key {
    /// PKCS#1 DER-encoded `RSAPublicKey` (SEQUENCE { INTEGER n, INTEGER e }).
    ///
    /// rcgen wraps this in the BIT STRING of the SubjectPublicKeyInfo.
    fn der_bytes(&self) -> &[u8] {
        &self.pub_key_der
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &PKCS_RSA_SHA256
    }
}

impl SigningKey for OxiRsa4096Key {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        use oxitls_core::OsRng;
        let signing_key = RsaPkcs1v15SigningKey::<RsaSha256>::new(self.inner.clone());
        let sig = signing_key
            .try_sign_with_rng(&mut OsRng, msg)
            .map_err(|_| rcgen::Error::RingUnspecified)?;
        Ok(sig.to_bytes().to_vec())
    }
}
