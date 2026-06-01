//! Intermediate certificate cache — LRU keyed by SHA-256 fingerprint.
//!
//! Backed by [`lru::LruCache`] wrapped in an [`std::sync::RwLock`]. The cache
//! is **synchronous** by design — rustls verifier callbacks (where this is
//! used) are themselves synchronous, and any async wrapper would force a
//! `block_on` that risks deadlocking the current runtime worker.
//!
//! Pure-Rust: depends only on `lru` (pure Rust) and `sha2` (pure Rust).
//!
//! # Concurrency
//!
//! Reads use [`lru::LruCache::peek`] under a read guard, so reads do not move
//! entries in the LRU ordering. If LRU-promotion-on-read semantics are needed
//! (typical for hot path caches), call [`IntermediateCertCache::touch`]
//! explicitly under a write guard.
//!
//! # Error handling
//!
//! Lock poisoning maps to [`oxitls_core::TlsError::Other`] rather than
//! `unwrap()`. Production paths must never panic on lock poison.

use std::num::NonZeroUsize;
use std::sync::RwLock;

use lru::LruCache;
use oxitls_core::TlsError;
use rustls_pki_types::CertificateDer;
use sha2::{Digest, Sha256};

/// Compute the SHA-256 fingerprint of an arbitrary DER blob.
///
/// Used to fingerprint intermediate certificates for cache lookup.
pub fn fingerprint_sha256(der: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(der);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Bounded LRU cache of intermediate certificates keyed by SHA-256 fingerprint.
///
/// # Example
///
/// ```
/// use std::num::NonZeroUsize;
/// use oxitls_webpki_roots::IntermediateCertCache;
/// use rustls_pki_types::CertificateDer;
///
/// # fn main() -> Result<(), oxitls_core::TlsError> {
/// let cache = IntermediateCertCache::new(
///     NonZeroUsize::new(128).ok_or_else(|| {
///         oxitls_core::TlsError::Other("invalid capacity".into())
///     })?,
/// );
/// let cert = CertificateDer::from(vec![0x30, 0x82, 0x01, 0x02]);
/// let fp = cache.insert(cert.clone())?;
/// let got = cache.get(&fp)?;
/// assert_eq!(got, Some(cert));
/// # Ok(())
/// # }
/// ```
pub struct IntermediateCertCache {
    inner: RwLock<LruCache<[u8; 32], CertificateDer<'static>>>,
}

impl std::fmt::Debug for IntermediateCertCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.inner.read() {
            Ok(guard) => f
                .debug_struct("IntermediateCertCache")
                .field("len", &guard.len())
                .field("cap", &guard.cap())
                .finish(),
            Err(_) => f.write_str("IntermediateCertCache { <poisoned> }"),
        }
    }
}

impl IntermediateCertCache {
    /// Create a new cache with the given fixed capacity (in entries).
    ///
    /// Capacity is bounded — once full, the least-recently-touched entry is
    /// evicted on the next `insert`.
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self {
            inner: RwLock::new(LruCache::new(capacity)),
        }
    }

    /// Insert a certificate and return its SHA-256 fingerprint.
    ///
    /// The fingerprint is computed over the DER bytes and used as the cache
    /// key — callers can later look the cert up via [`Self::get`].
    ///
    /// # Errors
    ///
    /// Returns [`TlsError::Other`] if the internal lock is poisoned.
    pub fn insert(&self, cert: CertificateDer<'static>) -> Result<[u8; 32], TlsError> {
        let fingerprint = fingerprint_sha256(cert.as_ref());
        let mut guard = self
            .inner
            .write()
            .map_err(|e| TlsError::Other(format!("intermediate cache lock poisoned: {e}")))?;
        guard.put(fingerprint, cert);
        Ok(fingerprint)
    }

    /// Look up a certificate by its SHA-256 fingerprint.
    ///
    /// Uses [`LruCache::peek`] — does **not** move the entry to the
    /// most-recently-used position. Use [`Self::touch`] explicitly when
    /// LRU-promote-on-read semantics are needed.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError::Other`] if the internal lock is poisoned.
    pub fn get(&self, fingerprint: &[u8; 32]) -> Result<Option<CertificateDer<'static>>, TlsError> {
        let guard = self
            .inner
            .read()
            .map_err(|e| TlsError::Other(format!("intermediate cache lock poisoned: {e}")))?;
        Ok(guard.peek(fingerprint).cloned())
    }

    /// Look up and LRU-promote an entry in one call (write-lock).
    ///
    /// Use this in hot paths where you want recently-used certificates to
    /// survive eviction longer.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError::Other`] if the internal lock is poisoned.
    pub fn touch(
        &self,
        fingerprint: &[u8; 32],
    ) -> Result<Option<CertificateDer<'static>>, TlsError> {
        let mut guard = self
            .inner
            .write()
            .map_err(|e| TlsError::Other(format!("intermediate cache lock poisoned: {e}")))?;
        Ok(guard.get(fingerprint).cloned())
    }

    /// Return the current number of cached entries.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError::Other`] if the internal lock is poisoned.
    pub fn len(&self) -> Result<usize, TlsError> {
        let guard = self
            .inner
            .read()
            .map_err(|e| TlsError::Other(format!("intermediate cache lock poisoned: {e}")))?;
        Ok(guard.len())
    }

    /// Return `true` if the cache is empty.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError::Other`] if the internal lock is poisoned.
    pub fn is_empty(&self) -> Result<bool, TlsError> {
        Ok(self.len()? == 0)
    }

    /// Return the configured maximum capacity.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError::Other`] if the internal lock is poisoned.
    pub fn capacity(&self) -> Result<NonZeroUsize, TlsError> {
        let guard = self
            .inner
            .read()
            .map_err(|e| TlsError::Other(format!("intermediate cache lock poisoned: {e}")))?;
        Ok(guard.cap())
    }

    /// Check whether a fingerprint is currently cached (does not promote).
    ///
    /// # Errors
    ///
    /// Returns [`TlsError::Other`] if the internal lock is poisoned.
    pub fn contains(&self, fingerprint: &[u8; 32]) -> Result<bool, TlsError> {
        let guard = self
            .inner
            .read()
            .map_err(|e| TlsError::Other(format!("intermediate cache lock poisoned: {e}")))?;
        Ok(guard.peek(fingerprint).is_some())
    }

    /// Remove all entries from the cache.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError::Other`] if the internal lock is poisoned.
    pub fn clear(&self) -> Result<(), TlsError> {
        let mut guard = self
            .inner
            .write()
            .map_err(|e| TlsError::Other(format!("intermediate cache lock poisoned: {e}")))?;
        guard.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cap(n: usize) -> NonZeroUsize {
        NonZeroUsize::new(n).expect("test capacity must be non-zero")
    }

    fn make_cert(seed: u8) -> CertificateDer<'static> {
        // Minimal blob: not a real cert, but the cache only sees opaque bytes.
        // Vary the seed so each blob gets a unique fingerprint.
        let bytes: Vec<u8> = (0..64).map(|i| (i as u8).wrapping_add(seed)).collect();
        CertificateDer::from(bytes)
    }

    #[test]
    fn new_cache_is_empty() {
        let cache = IntermediateCertCache::new(cap(8));
        assert_eq!(cache.len().expect("len"), 0);
        assert!(cache.is_empty().expect("is_empty"));
    }

    #[test]
    fn insert_then_get_roundtrip() {
        let cache = IntermediateCertCache::new(cap(4));
        let cert = make_cert(1);
        let fp = cache.insert(cert.clone()).expect("insert");
        let got = cache.get(&fp).expect("get");
        assert_eq!(got, Some(cert));
        assert_eq!(cache.len().expect("len"), 1);
        assert!(!cache.is_empty().expect("is_empty"));
        assert!(cache.contains(&fp).expect("contains"));
    }

    #[test]
    fn miss_returns_none() {
        let cache = IntermediateCertCache::new(cap(4));
        let missing = [0u8; 32];
        assert_eq!(cache.get(&missing).expect("get"), None);
        assert!(!cache.contains(&missing).expect("contains"));
    }

    #[test]
    fn capacity_eviction() {
        // Capacity 2 — third insert should evict the LRU entry.
        let cache = IntermediateCertCache::new(cap(2));
        let a = make_cert(0);
        let b = make_cert(1);
        let c = make_cert(2);
        let fp_a = cache.insert(a.clone()).expect("insert a");
        let fp_b = cache.insert(b.clone()).expect("insert b");
        let fp_c = cache.insert(c.clone()).expect("insert c");
        assert_eq!(cache.len().expect("len"), 2);
        // `a` was the oldest — should have been evicted.
        assert_eq!(cache.get(&fp_a).expect("get a"), None);
        assert_eq!(cache.get(&fp_b).expect("get b"), Some(b));
        assert_eq!(cache.get(&fp_c).expect("get c"), Some(c));
    }

    #[test]
    fn touch_promotes_entry() {
        let cache = IntermediateCertCache::new(cap(2));
        let a = make_cert(0);
        let b = make_cert(1);
        let c = make_cert(2);
        let fp_a = cache.insert(a.clone()).expect("insert a");
        let _fp_b = cache.insert(b.clone()).expect("insert b");
        // Touch `a` — promotes it to MRU; next insert should evict `b` instead.
        let touched = cache.touch(&fp_a).expect("touch a");
        assert_eq!(touched, Some(a.clone()));
        let _fp_c = cache.insert(c).expect("insert c");
        // `a` survived because we touched it.
        assert_eq!(cache.get(&fp_a).expect("get a"), Some(a));
    }

    #[test]
    fn clear_drops_all_entries() {
        let cache = IntermediateCertCache::new(cap(4));
        let _ = cache.insert(make_cert(0)).expect("insert 0");
        let _ = cache.insert(make_cert(1)).expect("insert 1");
        assert_eq!(cache.len().expect("len"), 2);
        cache.clear().expect("clear");
        assert_eq!(cache.len().expect("len"), 0);
        assert!(cache.is_empty().expect("is_empty"));
    }

    #[test]
    fn capacity_reports_configured_value() {
        let cache = IntermediateCertCache::new(cap(7));
        assert_eq!(cache.capacity().expect("capacity").get(), 7);
    }

    #[test]
    fn fingerprint_is_deterministic_sha256() {
        // Known SHA-256 of "hello" — we don't depend on this exact value
        // matching the sha2 crate; we just confirm same input → same output.
        let a = fingerprint_sha256(b"hello");
        let b = fingerprint_sha256(b"hello");
        let c = fingerprint_sha256(b"world");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
