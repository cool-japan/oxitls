#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! OxiTLS webpki trust anchors — Mozilla CA bundle, pure Rust.
//!
//! Provides `webpki_root_certs()` for a pre-populated `RootCertStore` from the
//! Mozilla CA bundle, plus a `RootStoreBuilder` for custom root store
//! construction and `TrustAnchorInfo` for root store introspection.

use std::sync::{Arc, OnceLock};

use rustls::RootCertStore;
use rustls_pki_types::TrustAnchor;
use sha2::{Digest, Sha256};

// ── Sub-modules ───────────────────────────────────────────────────────────────

mod expiring;
mod intermediate_cache;
mod native_roots;

pub use expiring::{expiring_roots, expiring_roots_from_ders, parse_not_after};
pub use intermediate_cache::IntermediateCertCache;
pub use native_roots::load_native_roots;

// ── Cached root store ────────────────────────────────────────────────────────

/// Global cached root cert store. The Mozilla CA bundle never changes at
/// runtime, so we construct it once and share via `Arc`.
static CACHED_ROOT_STORE: OnceLock<Arc<RootCertStore>> = OnceLock::new();

/// Build a `RootCertStore` pre-populated with the Mozilla CA bundle.
///
/// The store is constructed on first call and cached via `OnceLock`. Subsequent
/// calls return a clone of the cached store (cheap: `RootCertStore` is backed
/// by a `Vec<TrustAnchor>`).
pub fn webpki_root_certs() -> RootCertStore {
    let cached = CACHED_ROOT_STORE.get_or_init(|| {
        let mut store = RootCertStore::empty();
        store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Arc::new(store)
    });
    // Clone is needed because downstream code may mutate the store (add custom
    // roots). The clone is cheap — just copying the Vec of trust anchors.
    RootCertStore::clone(cached)
}

/// Return a shared reference to the cached root cert store.
///
/// Unlike [`webpki_root_certs()`], this returns an `Arc` reference without
/// cloning the inner store. Useful when you only need read access.
pub fn webpki_root_certs_arc() -> Arc<RootCertStore> {
    let cached = CACHED_ROOT_STORE.get_or_init(|| {
        let mut store = RootCertStore::empty();
        store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Arc::new(store)
    });
    Arc::clone(cached)
}

/// Return the number of trust anchors in the Mozilla CA bundle.
///
/// This is a constant determined at compile time by the `webpki-roots` crate
/// version.
pub fn root_cert_count() -> usize {
    webpki_roots::TLS_SERVER_ROOTS.len()
}

/// Build a filtered `RootCertStore` including only trust anchors accepted by
/// the given predicate.
///
/// # Example
/// ```
/// use oxitls_webpki_roots::webpki_root_certs_filtered;
///
/// // Include only roots — always-true filter equals the full store.
/// let store = webpki_root_certs_filtered(|_| true);
/// assert!(!store.is_empty());
/// ```
pub fn webpki_root_certs_filtered(filter: impl Fn(&TrustAnchor) -> bool) -> RootCertStore {
    let mut store = RootCertStore::empty();
    store.extend(
        webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .filter(|ta| filter(ta))
            .cloned(),
    );
    store
}

// ── Trust Anchor Info ────────────────────────────────────────────────────────

/// Summary information about a trust anchor (root CA) in the store.
///
/// Provides the subject distinguished name bytes, SHA-256 fingerprint of the
/// SPKI, and the raw `TrustAnchor` for further inspection.
#[derive(Debug, Clone)]
pub struct TrustAnchorInfo {
    /// The subject distinguished name (DER-encoded).
    pub subject_der: Vec<u8>,
    /// SHA-256 fingerprint of the Subject Public Key Info (SPKI) DER.
    pub spki_sha256: [u8; 32],
    /// Optional expiration timestamp (not_after) from the certificate.
    pub not_after: Option<time::OffsetDateTime>,
}

impl TrustAnchorInfo {
    /// Construct from a `TrustAnchor`.
    pub fn from_trust_anchor(ta: &TrustAnchor) -> Self {
        let subject_der = ta.subject.as_ref().to_vec();
        let spki_hash = Sha256::digest(ta.subject_public_key_info.as_ref());
        let mut spki_sha256 = [0u8; 32];
        spki_sha256.copy_from_slice(&spki_hash);
        Self {
            subject_der,
            spki_sha256,
            not_after: None,
        }
    }

    /// Return the subject distinguished name bytes (DER-encoded).
    pub fn subject_dn(&self) -> &[u8] {
        &self.subject_der
    }

    /// Return the SHA-256 fingerprint of the Subject Public Key Info (SPKI).
    pub fn fingerprint_sha256(&self) -> &[u8; 32] {
        &self.spki_sha256
    }

    /// Construct from a DER-encoded X.509 certificate.
    ///
    /// Extracts subject DN and SPKI SHA-256 fingerprint from the parsed cert.
    /// Returns `None` if the DER cannot be parsed.
    pub fn from_cert_der(der: &[u8]) -> Option<Self> {
        use x509_parser::prelude::FromDer as _;
        let (_rest, cert) = x509_parser::certificate::X509Certificate::from_der(der).ok()?;
        let subject_der = cert.subject().as_raw().to_vec();
        let spki_bytes = cert.public_key().raw;
        let spki_hash = Sha256::digest(spki_bytes);
        let mut spki_sha256 = [0u8; 32];
        spki_sha256.copy_from_slice(&spki_hash);
        Some(Self {
            subject_der,
            spki_sha256,
            not_after: None,
        })
    }

    /// Builder method: set the `not_after` expiration timestamp.
    pub fn with_not_after(mut self, not_after: time::OffsetDateTime) -> Self {
        self.not_after = Some(not_after);
        self
    }
}

impl std::fmt::Display for TrustAnchorInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Display the SPKI fingerprint in hex.
        write!(f, "SPKI-SHA256:")?;
        for b in &self.spki_sha256 {
            write!(f, "{b:02X}")?;
        }
        write!(f, " (subject {} bytes)", self.subject_der.len())
    }
}

/// List all trust anchors in the Mozilla CA bundle with summary information.
pub fn list_trust_anchors() -> Vec<TrustAnchorInfo> {
    webpki_roots::TLS_SERVER_ROOTS
        .iter()
        .map(TrustAnchorInfo::from_trust_anchor)
        .collect()
}

// ── Root Store Builder ───────────────────────────────────────────────────────

/// Builder for custom `RootCertStore` instances.
///
/// Allows combining webpki roots with custom PEM/DER certificates, and
/// excluding specific roots by their SPKI SHA-256 fingerprint.
///
/// # Example
/// ```
/// use oxitls_webpki_roots::RootStoreBuilder;
///
/// let store = RootStoreBuilder::new()
///     .with_webpki_roots()
///     .build();
///
/// assert!(!store.is_empty());
/// ```
pub struct RootStoreBuilder {
    include_webpki: bool,
    additional_der: Vec<Vec<u8>>,
    additional_pem: Vec<Vec<u8>>,
    excluded_spki_sha256: Vec<[u8; 32]>,
}

impl RootStoreBuilder {
    /// Create a new builder with no roots included.
    pub fn new() -> Self {
        Self {
            include_webpki: false,
            additional_der: Vec::new(),
            additional_pem: Vec::new(),
            excluded_spki_sha256: Vec::new(),
        }
    }

    /// Include the Mozilla CA bundle (webpki-roots).
    pub fn with_webpki_roots(mut self) -> Self {
        self.include_webpki = true;
        self
    }

    /// Add a single DER-encoded root certificate.
    pub fn add_der(mut self, cert_der: Vec<u8>) -> Self {
        self.additional_der.push(cert_der);
        self
    }

    /// Add root certificates from PEM-encoded data.
    ///
    /// The PEM data may contain multiple certificates.
    pub fn add_pem(mut self, pem_data: Vec<u8>) -> Self {
        self.additional_pem.push(pem_data);
        self
    }

    /// Exclude a trust anchor by its SPKI SHA-256 fingerprint.
    ///
    /// The fingerprint is the SHA-256 hash of the Subject Public Key Info (SPKI)
    /// DER encoding of the root certificate.
    pub fn exclude_fingerprint(mut self, spki_sha256: [u8; 32]) -> Self {
        self.excluded_spki_sha256.push(spki_sha256);
        self
    }

    /// Build the `RootCertStore`.
    ///
    /// Applies the exclusion list after adding all roots.
    pub fn build(self) -> RootCertStore {
        let mut store = RootCertStore::empty();

        // Add webpki roots (with exclusion filter).
        if self.include_webpki {
            store.extend(
                webpki_roots::TLS_SERVER_ROOTS
                    .iter()
                    .filter(|ta| {
                        let hash = Sha256::digest(ta.subject_public_key_info.as_ref());
                        let mut fingerprint = [0u8; 32];
                        fingerprint.copy_from_slice(&hash);
                        !self.excluded_spki_sha256.contains(&fingerprint)
                    })
                    .cloned(),
            );
        }

        // Add DER certs.
        for der in self.additional_der {
            let cert = rustls_pki_types::CertificateDer::from(der);
            // Silently skip invalid certs — builder pattern is forgiving.
            let _ = store.add(cert);
        }

        // Add PEM certs.
        for pem_data in &self.additional_pem {
            let mut reader = std::io::BufReader::new(pem_data.as_slice());
            if let Ok(certs) = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>() {
                for cert in certs {
                    let _ = store.add(cert);
                }
            }
        }

        store
    }
}

impl Default for RootStoreBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Build a `RootCertStore` from a slice of `TrustAnchor` values.
///
/// Useful for constructing a store from a custom set of trust anchors, e.g.
/// from the webpki-roots bundle or from a native root loader.
///
/// # Example
/// ```
/// use oxitls_webpki_roots::root_store_from_anchors;
///
/// let store = root_store_from_anchors(webpki_roots::TLS_SERVER_ROOTS);
/// assert!(!store.is_empty());
/// ```
pub fn root_store_from_anchors(anchors: &[TrustAnchor<'static>]) -> RootCertStore {
    let mut store = RootCertStore::empty();
    store.extend(anchors.iter().cloned());
    store
}

/// Merge multiple root cert stores into one.
///
/// Duplicate trust anchors (by subject) may appear in the merged store.
/// This is harmless — rustls will match the first applicable anchor.
pub fn merge_root_stores(stores: &[RootCertStore]) -> RootCertStore {
    let mut merged = RootCertStore::empty();
    for store in stores {
        merged.extend(store.roots.iter().cloned());
    }
    merged
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_store_non_empty() {
        let store = webpki_root_certs();
        assert!(
            !store.is_empty(),
            "webpki root cert store must not be empty"
        );
    }

    #[test]
    fn root_cert_count_positive() {
        let count = root_cert_count();
        assert!(count > 100, "expected > 100 trust anchors, got {count}");
    }

    #[test]
    fn cached_store_returns_same_content() {
        let a = webpki_root_certs();
        let b = webpki_root_certs();
        assert_eq!(a.len(), b.len());
    }

    #[test]
    fn arc_store_is_shared() {
        let a = webpki_root_certs_arc();
        let b = webpki_root_certs_arc();
        assert!(Arc::ptr_eq(&a, &b));
    }

    #[test]
    fn filtered_always_true_equals_full() {
        let full = webpki_root_certs();
        let filtered = webpki_root_certs_filtered(|_| true);
        assert_eq!(full.len(), filtered.len());
    }

    #[test]
    fn filtered_always_false_is_empty() {
        let filtered = webpki_root_certs_filtered(|_| false);
        assert!(filtered.is_empty());
    }

    #[test]
    fn list_trust_anchors_non_empty() {
        let anchors = list_trust_anchors();
        assert!(!anchors.is_empty());
        // Each should have non-empty subject and fingerprint.
        for info in &anchors {
            assert!(!info.subject_der.is_empty());
            assert_ne!(info.spki_sha256, [0u8; 32]);
        }
    }

    #[test]
    fn trust_anchor_info_display() {
        let anchors = list_trust_anchors();
        let first = &anchors[0];
        let display = format!("{first}");
        assert!(display.contains("SPKI-SHA256:"));
    }

    #[test]
    fn root_store_builder_empty() {
        let store = RootStoreBuilder::new().build();
        assert!(store.is_empty());
    }

    #[test]
    fn root_store_builder_with_webpki() {
        let store = RootStoreBuilder::new().with_webpki_roots().build();
        assert!(!store.is_empty());
        assert_eq!(store.len(), webpki_root_certs().len());
    }

    #[test]
    fn root_store_builder_exclude() {
        // Get the first anchor's fingerprint and exclude it.
        let anchors = list_trust_anchors();
        let first_fp = anchors[0].spki_sha256;
        let store = RootStoreBuilder::new()
            .with_webpki_roots()
            .exclude_fingerprint(first_fp)
            .build();
        // Should be one less than the full store.
        assert_eq!(store.len(), webpki_root_certs().len() - 1);
    }

    #[test]
    fn merge_stores() {
        let a = webpki_root_certs();
        let b = RootCertStore::empty();
        let merged = merge_root_stores(&[a.clone(), b]);
        assert_eq!(merged.len(), a.len());
    }
}
