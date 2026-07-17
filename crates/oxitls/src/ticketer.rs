//! `OxiTicketer` — a Pure-Rust TLS session-ticket encryptor/decryptor backed
//! by OxiCrypto AES-256-GCM, implementing [`rustls::server::ProducesTickets`].
//!
//! # Wire format
//!
//! ```text
//! version_byte (1) || nonce (12) || ciphertext_with_tag (n + 16)
//! ```
//!
//! `version_byte = 0x01`.
//! AAD = `b"oxitls-ticket-v1"`.
//!
//! # Key rotation
//!
//! A ticketer holds a **current** key and an optional **previous** key:
//!
//! - **Encrypt**: always uses the current key.
//! - **Decrypt**: tries the current key first, then falls back to the previous
//!   key.  This lets a previous key remain valid for decryption across a single
//!   rotation cycle.
//!
//! Keys are 32 random bytes each, generated via OS entropy at construction time.

use std::sync::RwLock;

use aes_gcm::{
    aead::{AeadInOut, KeyInit},
    Aes256Gcm, Nonce, Tag,
};
use getrandom::fill as random_fill;

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const KEY_LEN: usize = 32;
const VERSION_BYTE: u8 = 0x01;
const AAD: &[u8] = b"oxitls-ticket-v1";

// ── Internal key slot ─────────────────────────────────────────────────────────

#[derive(Clone)]
struct TicketKey {
    bytes: [u8; KEY_LEN],
}

impl TicketKey {
    fn generate() -> Result<Self, crate::TlsError> {
        let mut bytes = [0u8; KEY_LEN];
        random_fill(&mut bytes).map_err(|e| crate::TlsError::Other(e.to_string()))?;
        Ok(Self { bytes })
    }
}

// ── OxiTicketer ───────────────────────────────────────────────────────────────

/// State shared under the `RwLock`.
struct TicketerState {
    current: TicketKey,
    previous: Option<TicketKey>,
}

/// A Pure-Rust TLS session-ticket encryptor backed by AES-256-GCM.
///
/// Create via [`OxiTicketer::new`] (or [`OxiTicketer::new_with_lifetime`]) and
/// then install on the server config:
///
/// ```no_run
/// # use std::sync::Arc;
/// # use oxitls::ticketer::OxiTicketer;
/// # use oxitls::tls13::ServerBuilder;
/// # fn main() -> Result<(), oxitls_core::TlsError> {
/// let ticketer = Arc::new(OxiTicketer::new()?);
/// let config = ServerBuilder::new()
///     // ... cert/key ...
///     .with_ticketer(ticketer)
///     .build()?;
/// # Ok(())
/// # }
/// ```
pub struct OxiTicketer {
    state: RwLock<TicketerState>,
    lifetime_secs: u32,
}

impl std::fmt::Debug for OxiTicketer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OxiTicketer")
            .field("lifetime_secs", &self.lifetime_secs)
            .finish_non_exhaustive()
    }
}

impl OxiTicketer {
    /// Construct with the default lifetime of 6 hours (21 600 seconds).
    ///
    /// Generates two random AES-256-GCM keys from OS entropy.
    ///
    /// # Errors
    /// Returns [`crate::TlsError::Other`] if the OS RNG fails.
    pub fn new() -> Result<Self, crate::TlsError> {
        Self::new_with_lifetime(6 * 60 * 60)
    }

    /// Construct with a custom ticket lifetime in seconds.
    ///
    /// # Errors
    /// Returns [`crate::TlsError::Other`] if the OS RNG fails.
    pub fn new_with_lifetime(lifetime_secs: u32) -> Result<Self, crate::TlsError> {
        let current = TicketKey::generate()?;
        // Start with no previous key; one is set on the first `rotate()` call.
        let state = TicketerState {
            current,
            previous: None,
        };
        Ok(Self {
            state: RwLock::new(state),
            lifetime_secs,
        })
    }

    /// Rotate keys: promote current to previous, generate a fresh current key.
    ///
    /// After rotation the old current key is kept as `previous` for one cycle
    /// so in-flight tickets can still be decrypted.
    ///
    /// # Errors
    /// Returns [`crate::TlsError::Other`] if the OS RNG fails.
    pub fn rotate(&self) -> Result<(), crate::TlsError> {
        let new_current = TicketKey::generate()?;
        let mut guard = self
            .state
            .write()
            .map_err(|_| crate::TlsError::Other("RwLock poisoned".into()))?;
        // Move current → previous, discard old previous.
        let old_current = guard.current.clone();
        guard.current = new_current;
        guard.previous = Some(old_current);
        Ok(())
    }
}

// ── Encryption helpers ────────────────────────────────────────────────────────

fn encrypt_with_key(key_bytes: &[u8; KEY_LEN], plain: &[u8]) -> Option<Vec<u8>> {
    // wire format: VERSION (1) || NONCE (12) || CIPHERTEXT ‖ TAG (n+16)
    let mut nonce_bytes = [0u8; NONCE_LEN];
    random_fill(&mut nonce_bytes).ok()?;

    let mut out = Vec::with_capacity(1 + NONCE_LEN + plain.len() + TAG_LEN);
    out.push(VERSION_BYTE);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(plain);
    // We'll encrypt the plaintext portion in-place.
    let cipher_start = 1 + NONCE_LEN;
    let cipher_end = cipher_start + plain.len();

    let cipher = Aes256Gcm::new_from_slice(key_bytes).ok()?;
    let nonce = Nonce::try_from(nonce_bytes.as_slice()).ok()?;

    let tag = cipher
        .encrypt_inout_detached(&nonce, AAD, (&mut out[cipher_start..cipher_end]).into())
        .ok()?;
    out.extend_from_slice(&tag);
    Some(out)
}

fn decrypt_with_key(key_bytes: &[u8; KEY_LEN], ticket: &[u8]) -> Option<Vec<u8>> {
    // Minimum: 1 (version) + 12 (nonce) + 0 (pt) + 16 (tag) = 29 bytes
    let min_len = 1 + NONCE_LEN + TAG_LEN;
    if ticket.len() < min_len {
        return None;
    }
    if ticket[0] != VERSION_BYTE {
        return None;
    }
    let nonce_bytes = &ticket[1..1 + NONCE_LEN];
    let ct_and_tag = &ticket[1 + NONCE_LEN..];

    if ct_and_tag.len() < TAG_LEN {
        return None;
    }
    let pt_len = ct_and_tag.len() - TAG_LEN;

    let cipher = Aes256Gcm::new_from_slice(key_bytes).ok()?;
    let nonce = Nonce::try_from(nonce_bytes).ok()?;

    let tag_slice = &ct_and_tag[pt_len..];
    let tag = Tag::try_from(tag_slice).ok()?;

    let mut buf: Vec<u8> = ct_and_tag[..pt_len].to_vec();
    cipher
        .decrypt_inout_detached(&nonce, AAD, (&mut buf[..]).into(), &tag)
        .ok()?;
    Some(buf)
}

// ── ProducesTickets ───────────────────────────────────────────────────────────

impl rustls::server::ProducesTickets for OxiTicketer {
    fn enabled(&self) -> bool {
        true
    }

    fn lifetime(&self) -> u32 {
        self.lifetime_secs
    }

    fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>> {
        let guard = self.state.read().ok()?;
        encrypt_with_key(&guard.current.bytes, plain)
    }

    fn decrypt(&self, ticket: &[u8]) -> Option<Vec<u8>> {
        let guard = self.state.read().ok()?;
        // Try current key first.
        if let Some(pt) = decrypt_with_key(&guard.current.bytes, ticket) {
            return Some(pt);
        }
        // Fall back to previous key.
        if let Some(prev) = &guard.previous {
            return decrypt_with_key(&prev.bytes, ticket);
        }
        None
    }
}
