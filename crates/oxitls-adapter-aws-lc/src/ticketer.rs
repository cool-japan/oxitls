//! `AwsLcTicketRotator` — TLS session-ticket encryptor/decryptor backed by
//! aws-lc-rs AES-256-GCM with automatic key rotation.
//!
//! # Wire format
//!
//! ```text
//! nonce (12) || ciphertext_with_tag (n + 16)
//! ```
//!
//! # Key rotation
//!
//! - **Encrypt**: always uses the current key.
//! - **Decrypt**: tries the current key first, then falls back to the previous
//!   key, allowing tickets encrypted before a rotation to remain valid.
//!
//! # Runtime requirement
//!
//! [`AwsLcTicketRotator::new`] spawns a Tokio background task.  It must be
//! called from within a Tokio runtime context (e.g., inside `#[tokio::main]`
//! or `#[tokio::test]`).

#[cfg(feature = "aws-lc")]
use std::{
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};

// ── Wire-format constants ─────────────────────────────────────────────────────

#[cfg(feature = "aws-lc")]
const NONCE_LEN: usize = 12;
#[cfg(feature = "aws-lc")]
const TAG_LEN: usize = 16;
#[cfg(feature = "aws-lc")]
const KEY_LEN: usize = 32;

// ── Internal state ────────────────────────────────────────────────────────────

/// State held under the `RwLock`.
#[cfg(feature = "aws-lc")]
struct RotatorState {
    current_key: [u8; KEY_LEN],
    previous_key: Option<[u8; KEY_LEN]>,
    /// Monotonically increasing rotation counter.
    generation: u64,
}

/// Generate 32 random bytes via `aws_lc_rs::rand::fill`.
#[cfg(feature = "aws-lc")]
fn random_key() -> Result<[u8; KEY_LEN], oxitls_core::TlsError> {
    let mut key = [0u8; KEY_LEN];
    aws_lc_rs::rand::fill(&mut key)
        .map_err(|e| oxitls_core::TlsError::Other(format!("rng error: {e:?}")))?;
    Ok(key)
}

#[cfg(feature = "aws-lc")]
impl RotatorState {
    fn generate() -> Result<Self, oxitls_core::TlsError> {
        let current_key = random_key()?;
        Ok(Self {
            current_key,
            previous_key: None,
            generation: 0,
        })
    }

    /// Promote current → previous, generate a fresh current key.
    fn rotate(&mut self) -> Result<(), oxitls_core::TlsError> {
        let new_key = random_key()?;
        self.previous_key = Some(self.current_key);
        self.current_key = new_key;
        self.generation = self.generation.saturating_add(1);
        Ok(())
    }
}

// ── AwsLcTicketRotator ────────────────────────────────────────────────────────

/// A TLS session-ticket encryptor/decryptor backed by aws-lc-rs AES-256-GCM.
///
/// Keys rotate automatically on a configurable interval. Create with
/// [`AwsLcTicketRotator::new`] and wrap in `Arc` before passing to rustls:
///
/// ```no_run
/// # #[cfg(feature = "aws-lc")]
/// # {
/// use std::sync::Arc;
/// use std::time::Duration;
/// use oxitls_adapter_aws_lc::AwsLcTicketRotator;
///
/// let ticketer = AwsLcTicketRotator::new(Duration::from_secs(3600)).unwrap();
/// let _arc: Arc<AwsLcTicketRotator> = ticketer;
/// # }
/// ```
#[cfg(feature = "aws-lc")]
pub struct AwsLcTicketRotator {
    state: Arc<RwLock<RotatorState>>,
    rotation_interval: Duration,
    /// `lifetime()` = 2 × rotation interval (clamped to ≥ 1 second).
    lifetime_secs: u32,
    /// Handle for the background rotation task; held so we can abort on drop.
    _task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

#[cfg(feature = "aws-lc")]
impl AwsLcTicketRotator {
    /// Create a new rotator with the given rotation interval and spawn the
    /// background rotation task.
    ///
    /// Requires an active Tokio runtime context.
    ///
    /// # Errors
    /// Returns `TlsError::Other` if the OS RNG fails during initial key
    /// generation.
    pub fn new(rotation_interval: Duration) -> Result<Arc<Self>, oxitls_core::TlsError> {
        let state = Arc::new(RwLock::new(RotatorState::generate()?));

        // lifetime = 2 × rotation interval, clamped to [1, u32::MAX] seconds.
        let interval_secs = rotation_interval.as_secs().max(1);
        let lifetime_secs = (2u64)
            .saturating_mul(interval_secs)
            .min(u64::from(u32::MAX)) as u32;
        let lifetime_secs = lifetime_secs.max(1);

        let rotator = Arc::new(Self {
            state: Arc::clone(&state),
            rotation_interval,
            lifetime_secs,
            _task: Mutex::new(None),
        });

        // Spawn background rotation task.
        let state_for_task = Arc::clone(&state);
        let handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(rotation_interval);
            // First tick fires immediately; skip it so the first rotation
            // happens after one full interval.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let mut guard = match state_for_task.write() {
                    Ok(g) => g,
                    Err(_) => break, // RwLock poisoned — stop gracefully
                };
                // Ignore RNG errors in the background task; old key continues.
                let _ = guard.rotate();
            }
        });

        // Store the JoinHandle.
        if let Ok(mut guard) = rotator._task.lock() {
            *guard = Some(handle);
        }

        Ok(rotator)
    }

    /// Return the current rotation generation count.
    pub fn generation(&self) -> u64 {
        self.state.read().map(|g| g.generation).unwrap_or(0)
    }
}

#[cfg(feature = "aws-lc")]
impl Drop for AwsLcTicketRotator {
    fn drop(&mut self) {
        if let Ok(mut guard) = self._task.lock() {
            if let Some(handle) = guard.take() {
                handle.abort();
            }
        }
    }
}

#[cfg(feature = "aws-lc")]
impl std::fmt::Debug for AwsLcTicketRotator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let generation = self.state.read().map(|g| g.generation).unwrap_or(0);
        f.debug_struct("AwsLcTicketRotator")
            .field("generation", &generation)
            .field("rotation_interval", &self.rotation_interval)
            .field("lifetime_secs", &self.lifetime_secs)
            .finish_non_exhaustive()
    }
}

// ── AEAD helpers ──────────────────────────────────────────────────────────────

/// Encrypt `plain` with `key_bytes` using AES-256-GCM.
///
/// Wire format: `nonce (12) || ciphertext_with_tag (plain.len() + 16)`.
#[cfg(feature = "aws-lc")]
fn encrypt_ticket(key_bytes: &[u8; KEY_LEN], plain: &[u8]) -> Option<Vec<u8>> {
    use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};

    let mut nonce_bytes = [0u8; NONCE_LEN];
    aws_lc_rs::rand::fill(&mut nonce_bytes).ok()?;

    let unbound = UnboundKey::new(&AES_256_GCM, key_bytes).ok()?;
    let key = LessSafeKey::new(unbound);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    // `seal_in_place_append_tag` operates on the Vec and appends the tag.
    let mut ct: Vec<u8> = plain.to_vec();
    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut ct)
        .ok()?;

    // Wire format: nonce || ciphertext_with_tag
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Some(out)
}

/// Decrypt `ticket` with `key_bytes`.
///
/// Returns `Some(plaintext)` on success, `None` on authentication failure or
/// malformed input.
#[cfg(feature = "aws-lc")]
fn decrypt_ticket(key_bytes: &[u8; KEY_LEN], ticket: &[u8]) -> Option<Vec<u8>> {
    use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};

    let min_len = NONCE_LEN + TAG_LEN; // 0-byte plaintext minimum
    if ticket.len() < min_len {
        return None;
    }
    let nonce_bytes: [u8; NONCE_LEN] = ticket[..NONCE_LEN].try_into().ok()?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let unbound = UnboundKey::new(&AES_256_GCM, key_bytes).ok()?;
    let key = LessSafeKey::new(unbound);

    let mut ct: Vec<u8> = ticket[NONCE_LEN..].to_vec();
    let pt = key.open_in_place(nonce, Aad::empty(), &mut ct).ok()?;
    Some(pt.to_vec())
}

// ── ProducesTickets impl ──────────────────────────────────────────────────────

#[cfg(feature = "aws-lc")]
impl rustls::server::ProducesTickets for AwsLcTicketRotator {
    fn enabled(&self) -> bool {
        true
    }

    fn lifetime(&self) -> u32 {
        self.lifetime_secs
    }

    fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>> {
        let guard = self.state.read().ok()?;
        encrypt_ticket(&guard.current_key, plain)
    }

    fn decrypt(&self, ticket: &[u8]) -> Option<Vec<u8>> {
        let guard = self.state.read().ok()?;
        // Try current key first.
        if let Some(pt) = decrypt_ticket(&guard.current_key, ticket) {
            return Some(pt);
        }
        // Fall back to previous key.
        if let Some(prev) = &guard.previous_key {
            return decrypt_ticket(prev, ticket);
        }
        None
    }
}
