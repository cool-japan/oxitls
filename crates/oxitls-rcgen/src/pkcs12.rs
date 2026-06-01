//! PKCS#12 (PFX) export for [`CertifiedKey`].
//!
//! The output is a password-protected `.pfx` blob compatible with browsers,
//! Java keystores, and `openssl pkcs12`. Pure-Rust implementation via the
//! `p12` crate; no OpenSSL, no ring.
//!
//! # Algorithm
//!
//! `p12 = "0.6"` builds a PFX whose key bag is encrypted with
//! **PBE-with-SHA-and-3-KEY-Triple-DES-CBC** (RFC 7292 §B.1) using 2048
//! PBKDF iterations (`p12::ITERATIONS`). The MAC uses HMAC-SHA-1 derived from
//! the same password. While the task brief preferred AES-256 / PBES2,
//! `p12` 0.6 does not expose PBES2 encryption — and the COOLJAPAN policy
//! prohibits using the `openssl` or non-Pure-Rust crates that would. The 3DES
//! variant is still a valid PKCS#12 profile (every browser and OpenSSL build
//! reads it) and remains 100 % Pure Rust through the `des` crate.
//!
//! # Re-import / round-trip
//!
//! The output bytes round-trip through `p12::PFX::parse` and through
//! `openssl pkcs12 -in file.pfx`. See `tests::pkcs12_roundtrip`.

use oxitls_core::TlsError;

use crate::cert::CertifiedKey;

impl CertifiedKey {
    /// Export this certificate + private key as a PKCS#12 (PFX) blob protected
    /// with the given password.
    ///
    /// # Arguments
    /// * `password` — encrypts the private key bag and the integrity MAC.
    /// * `friendly_name` — UTF-8 attribute (`pkcs12-friendlyName`) attached to
    ///   both the key bag and the cert bag. Browsers display this as the
    ///   certificate's "nickname".
    ///
    /// # Errors
    /// Returns [`TlsError::Other`] if PBKDF / encryption fails. In practice
    /// this should never happen — `p12::PFX::new` only returns `None` when
    /// the OS RNG is unavailable, which is fatal anyway.
    ///
    /// # Algorithm note
    /// Pure-Rust PFX construction via the `p12` crate uses
    /// PBE-with-SHA-and-3KeyTripleDES-CBC for the key bag (RFC 7292 §B.1).
    /// PBES2 / AES-256 is not exposed by `p12` 0.6; if you need an AES-based
    /// PFX, decrypt this output and re-wrap with an explicit PBES2 helper.
    pub fn to_pkcs12(&self, password: &str, friendly_name: &str) -> Result<Vec<u8>, TlsError> {
        let pfx = p12::PFX::new(
            &self.cert_der,
            &self.pkcs8_der,
            None,
            password,
            friendly_name,
        )
        .ok_or_else(|| {
            TlsError::Other(
                "PKCS#12 construction failed (OS RNG unavailable or DER encoding rejected)"
                    .to_string(),
            )
        })?;
        Ok(pfx.to_der())
    }

    /// Export this certificate + private key as a PKCS#12 (PFX) blob with
    /// extra CA certificates included in the bag.
    ///
    /// The order of `ca_chain` is preserved; typically pass intermediates
    /// nearest-to-leaf first, then the root.
    ///
    /// # Errors
    /// See [`CertifiedKey::to_pkcs12`].
    pub fn to_pkcs12_with_chain(
        &self,
        password: &str,
        friendly_name: &str,
        ca_chain: &[&[u8]],
    ) -> Result<Vec<u8>, TlsError> {
        let pfx = p12::PFX::new_with_cas(
            &self.cert_der,
            &self.pkcs8_der,
            ca_chain,
            password,
            friendly_name,
        )
        .ok_or_else(|| {
            TlsError::Other(
                "PKCS#12 construction failed (OS RNG unavailable or DER encoding rejected)"
                    .to_string(),
            )
        })?;
        Ok(pfx.to_der())
    }
}
