//! RFC 8446 §8 single-use-ticket anti-replay for 0-RTT early data.
//!
//! In TLS 1.3, a server that accepts 0-RTT data must protect against replay
//! attacks (RFC 8446 §8.1–§8.2). This module wraps any [`rustls::server::ProducesTickets`]
//! implementation with a time-windowed single-use recording mechanism:
//!
//! - On first use: the ticket's SHA-256 fingerprint is recorded with a
//!   timestamp; the plaintext session state is returned normally.
//! - On replay within the window: returns `None`, which causes rustls to
//!   reject the PSK resumption → no 0-RTT data is accepted.
//! - After the window expires: the fingerprint is pruned; the ticket may be
//!   used once more (harmless: tickets are also expired by their lifetime).
//!
//! Keyed on `SHA-256(ticket_bytes)` so key rotation does not affect replay
//! tracking — the fingerprint depends on the ciphertext, not the key.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sha2::{Digest, Sha256};

/// Verdict returned by [`ReplayGuard::check_and_record`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayVerdict {
    /// First use within the current window. The ticket's fingerprint has been
    /// recorded; the caller should proceed normally.
    Fresh,
    /// The ticket fingerprint was already recorded within the window.
    /// The caller should return `None` to reject the PSK/0-RTT attempt.
    Replayed,
}

/// Monotonic clock abstraction, enabling deterministic tests without sleeps.
pub trait Clock: Send + Sync {
    /// Current time as seconds since an arbitrary epoch (must be monotonically
    /// non-decreasing across a single process lifetime).
    fn unix_seconds(&self) -> u64;
}

/// Production clock backed by `std::time::SystemTime`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn unix_seconds(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs()
    }
}

/// Advanceable mock clock for tests. Starts at 0 seconds.
///
/// Clone shares the same underlying counter.
#[derive(Debug, Clone, Default)]
pub struct MockClock(Arc<Mutex<u64>>);

impl MockClock {
    /// Create a new mock clock starting at second 0.
    pub fn new() -> Self {
        Self::default()
    }

    /// Advance the clock by `secs` seconds.
    pub fn advance_secs(&self, secs: u64) {
        let mut guard = self.0.lock().unwrap_or_else(|e| e.into_inner());
        *guard += secs;
    }
}

impl Clock for MockClock {
    fn unix_seconds(&self) -> u64 {
        *self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

// ── ReplayGuard ───────────────────────────────────────────────────────────────

/// Time-windowed single-use ticket fingerprint store.
///
/// Stores the SHA-256 hash of each recently-seen ticket alongside the second
/// it was first observed. Entries older than `window` are pruned lazily on
/// each [`check_and_record`][Self::check_and_record] call.
pub struct ReplayGuard<C: Clock = SystemClock> {
    seen: Mutex<HashMap<[u8; 32], u64>>,
    window_secs: u64,
    clock: C,
}

impl ReplayGuard<SystemClock> {
    /// Create a guard with the given window (in seconds) and the system clock.
    pub fn new(window_secs: u64) -> Self {
        Self::with_clock(window_secs, SystemClock)
    }
}

impl<C: Clock> ReplayGuard<C> {
    /// Create a guard with a custom clock (for testing).
    pub fn with_clock(window_secs: u64, clock: C) -> Self {
        Self {
            seen: Mutex::new(HashMap::new()),
            window_secs,
            clock,
        }
    }

    /// Check whether `ticket` has been seen within the current window.
    ///
    /// - If not seen (or if the previous record has expired): record it and
    ///   return [`ReplayVerdict::Fresh`].
    /// - If seen within the window: return [`ReplayVerdict::Replayed`] without
    ///   updating the record (the first timestamp is preserved).
    pub fn check_and_record(&self, ticket: &[u8]) -> ReplayVerdict {
        let key: [u8; 32] = Sha256::digest(ticket).into();
        let now = self.clock.unix_seconds();

        let mut guard = self.seen.lock().unwrap_or_else(|e| e.into_inner());

        // Prune entries older than the window.
        guard.retain(|_, recorded_at| now.saturating_sub(*recorded_at) <= self.window_secs);

        use std::collections::hash_map::Entry;
        match guard.entry(key) {
            Entry::Occupied(_) => ReplayVerdict::Replayed,
            Entry::Vacant(e) => {
                e.insert(now);
                ReplayVerdict::Fresh
            }
        }
    }
}

// ── ArcTicketer ───────────────────────────────────────────────────────────────

/// Newtype wrapping `Arc<dyn ProducesTickets>` to satisfy the `T: ProducesTickets`
/// bound on [`AntiReplayTicketer`].
pub(crate) struct ArcTicketer(pub Arc<dyn rustls::server::ProducesTickets + Send + Sync>);

impl std::fmt::Debug for ArcTicketer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArcTicketer").finish_non_exhaustive()
    }
}

impl rustls::server::ProducesTickets for ArcTicketer {
    fn enabled(&self) -> bool {
        self.0.enabled()
    }

    fn lifetime(&self) -> u32 {
        self.0.lifetime()
    }

    fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>> {
        self.0.encrypt(plain)
    }

    fn decrypt(&self, ticket: &[u8]) -> Option<Vec<u8>> {
        self.0.decrypt(ticket)
    }
}

// ── AntiReplayTicketer ────────────────────────────────────────────────────────

/// Wraps a [`rustls::server::ProducesTickets`] implementation with RFC 8446 §8 single-use
/// replay protection.
///
/// Install on a [`ServerBuilder`][crate::tls13::ServerBuilder] via
/// [`with_anti_replay`][crate::tls13::ServerBuilder::with_anti_replay].
///
/// # Security
///
/// After `decrypt` returns `Some(plaintext)` for a given ticket, every
/// subsequent `decrypt` call with the **same** ticket bytes returns `None`
/// until the replay window expires. rustls treats `None` from `ProducesTickets`
/// as "no valid session" → the client must complete a full handshake, and any
/// 0-RTT early data is rejected.
///
/// This protects against a replay attacker who captures a ClientHello (with
/// early data) and re-sends it to the same server within the ticket lifetime.
pub struct AntiReplayTicketer<T: rustls::server::ProducesTickets, C: Clock = SystemClock> {
    inner: T,
    guard: ReplayGuard<C>,
}

impl<T: rustls::server::ProducesTickets, C: Clock> std::fmt::Debug for AntiReplayTicketer<T, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AntiReplayTicketer").finish_non_exhaustive()
    }
}

impl<T: rustls::server::ProducesTickets> AntiReplayTicketer<T, SystemClock> {
    /// Wrap `inner` with a replay window equal to the ticket lifetime.
    pub fn new(inner: T) -> Self {
        let window_secs = u64::from(inner.lifetime());
        Self {
            guard: ReplayGuard::new(window_secs),
            inner,
        }
    }
}

impl<T: rustls::server::ProducesTickets, C: Clock> AntiReplayTicketer<T, C> {
    /// Wrap `inner` with a custom clock (for testing).
    pub fn with_clock(inner: T, clock: C) -> Self {
        let window_secs = u64::from(inner.lifetime());
        Self {
            inner,
            guard: ReplayGuard::with_clock(window_secs, clock),
        }
    }
}

impl<T: rustls::server::ProducesTickets + Send + Sync, C: Clock> rustls::server::ProducesTickets
    for AntiReplayTicketer<T, C>
{
    fn enabled(&self) -> bool {
        self.inner.enabled()
    }

    fn lifetime(&self) -> u32 {
        self.inner.lifetime()
    }

    fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>> {
        self.inner.encrypt(plain)
    }

    /// Decrypt a session ticket with single-use replay protection.
    ///
    /// The ticket is first validated by the inner ticketer (callers that supply
    /// garbage tickets are rejected before the fingerprint is recorded, so the
    /// replay table cannot be poisoned). Only if the inner `decrypt` succeeds is
    /// the fingerprint checked and recorded.
    fn decrypt(&self, ticket: &[u8]) -> Option<Vec<u8>> {
        // Validate before recording — prevents garbage from poisoning the set.
        let plaintext = self.inner.decrypt(ticket)?;

        match self.guard.check_and_record(ticket) {
            ReplayVerdict::Fresh => Some(plaintext),
            ReplayVerdict::Replayed => None,
        }
    }
}
