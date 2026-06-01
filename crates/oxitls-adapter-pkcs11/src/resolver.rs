// SPDX-License-Identifier: Apache-2.0
// Copyright COOLJAPAN OU (Team Kitasan)
//! PKCS#11-backed TLS server certificate resolver.
//!
//! This module is only compiled when the `pkcs11` feature is active.

use std::collections::BTreeMap;
use std::sync::Arc;

use rustls::pki_types::CertificateDer;
use rustls::server::ClientHello;
use rustls::sign::CertifiedKey;

use crate::signer::Pkcs11SigningKey;

/// Match a requested SNI hostname against a keyed map.
///
/// Resolution order:
/// 1. Exact match: `requested == key`
/// 2. Wildcard match: key starts with `*.` and matches exactly one left-most
///    label (RFC 6125 §6.4.3 — `*.example.com` matches `foo.example.com` but
///    not `example.com` or `a.b.example.com`)
/// 3. Default: if `strict` is false, return `default`; if true, return `None`
pub(crate) fn match_sni<'a, V>(
    map: &'a BTreeMap<String, V>,
    requested: &str,
    strict: bool,
    default: Option<&'a V>,
) -> Option<&'a V> {
    // Exact match
    if let Some(v) = map.get(requested) {
        return Some(v);
    }
    // Wildcard match: find any key "*.suffix" where requested = "label.suffix"
    for (key, v) in map.iter() {
        if let Some(suffix) = key.strip_prefix("*.") {
            // requested must be exactly "one-label.suffix" (no more dots before suffix)
            if let Some(label_dot) = requested.strip_suffix(suffix) {
                if label_dot.len() > 1
                    && label_dot.ends_with('.')
                    && !label_dot[..label_dot.len() - 1].contains('.')
                {
                    return Some(v);
                }
            }
        }
    }
    // No match
    if strict {
        None
    } else {
        default
    }
}

/// A [`rustls::server::ResolvesServerCert`] backed by one or more PKCS#11 keys.
///
/// Supports both single-certificate (backward-compatible) and multi-tenant
/// SNI-based certificate selection.
///
/// # SNI dispatch
///
/// When built via [`Pkcs11ServerCertResolver::with_sni_map`] the resolver looks
/// up the `server_name` from the TLS `ClientHello` in an internal ordered map.
/// Supports both exact hostname and wildcard matching (RFC 6125 §6.4.3).
/// If no matching SNI entry exists and `strict_sni` is `false`, the `default`
/// entry (if any) is returned.  When `strict_sni` is `true` and there is no
/// match, `None` is returned and the TLS handshake fails.
/// When the resolver holds only a single certificate (`new`) the map is empty
/// and every `ClientHello` returns that certificate.
#[derive(Debug)]
pub struct Pkcs11ServerCertResolver {
    /// SNI hostname → pre-built `CertifiedKey`.
    sni_map: BTreeMap<String, Arc<CertifiedKey>>,
    /// Fallback certificate used when no SNI matches (also the sole cert for
    /// single-certificate configurations).
    default: Option<Arc<CertifiedKey>>,
    /// When `true`, reject connections that do not match any SNI map entry.
    strict_sni: bool,
}

impl Pkcs11ServerCertResolver {
    /// Construct a single-certificate resolver (backward-compatible with Wave 4).
    ///
    /// Every `ClientHello` receives the same certificate chain, regardless of
    /// SNI.  This is equivalent to a `with_sni_map` resolver with an empty map
    /// and a single default entry.
    ///
    /// # Arguments
    ///
    /// * `cert_chain` - DER-encoded certificate chain (leaf first).
    /// * `signing_key` - The PKCS#11-backed signing key for the leaf certificate.
    pub fn new(
        cert_chain: Vec<CertificateDer<'static>>,
        signing_key: Arc<Pkcs11SigningKey>,
    ) -> Self {
        let certified_key = Arc::new(CertifiedKey::new(
            cert_chain,
            signing_key as Arc<dyn rustls::sign::SigningKey>,
        ));
        Self {
            sni_map: BTreeMap::new(),
            default: Some(certified_key),
            strict_sni: false,
        }
    }

    /// Construct a multi-tenant SNI-based resolver.
    ///
    /// Each entry in `map` associates a hostname (e.g. `"example.com"` or
    /// `"*.example.com"` for wildcard) with a certificate chain and its
    /// corresponding signing key.  If the client's `server_name` extension is
    /// absent or does not match any entry in `map`, no certificate is returned
    /// (the TLS handshake fails with a "no suitable certificate" alert).
    ///
    /// Wildcard entries (keys starting with `*.`) follow RFC 6125 §6.4.3:
    /// `*.example.com` matches `foo.example.com` but not `example.com` or
    /// `a.b.example.com`.
    ///
    /// To add a default fallback certificate, insert an entry under the empty
    /// string `""`.
    ///
    /// # Arguments
    ///
    /// * `map` - SNI hostname → `(cert_chain, signing_key)` pairs.
    pub fn with_sni_map(
        map: BTreeMap<
            String,
            (
                Vec<CertificateDer<'static>>,
                Arc<dyn rustls::sign::SigningKey>,
            ),
        >,
    ) -> Self {
        let sni_map: BTreeMap<String, Arc<CertifiedKey>> = map
            .into_iter()
            .map(|(hostname, (chain, key))| (hostname, Arc::new(CertifiedKey::new(chain, key))))
            .collect();

        Self {
            sni_map,
            default: None,
            strict_sni: false,
        }
    }

    /// Enable or disable strict SNI mode.
    ///
    /// When `strict` is `true`, connections whose SNI does not match any entry
    /// in the SNI map are rejected (no fallback to the `default` certificate).
    /// This is useful in multi-tenant deployments where serving an unexpected
    /// certificate would be a security issue.
    ///
    /// Default: `false` (permissive — falls back to the default certificate).
    pub fn with_strict_sni(mut self, strict: bool) -> Self {
        self.strict_sni = strict;
        self
    }
}

impl Pkcs11ServerCertResolver {
    /// Look up the `CertifiedKey` for a given SNI hostname without requiring a
    /// live `ClientHello`.
    ///
    /// This method contains the dispatch logic extracted from the
    /// `ResolvesServerCert` trait impl.  It is public to allow unit testing of
    /// SNI routing without constructing an opaque `ClientHello`.
    ///
    /// Dispatch order:
    /// 1. Exact hostname match in the SNI map.
    /// 2. Wildcard match (`*.example.com` → `foo.example.com`, RFC 6125 §6.4.3).
    /// 3. If `strict_sni` is `false`, fall back to the `default` certificate.
    ///    If `strict_sni` is `true`, return `None`.
    ///
    /// `sni` should be the lowercase hostname string (e.g. `"example.com"`).
    /// Pass `None` to simulate a client that did not send an SNI extension.
    pub fn lookup(&self, sni: Option<&str>) -> Option<Arc<CertifiedKey>> {
        match sni {
            Some(name) => {
                // `self.default` is `Option<Arc<CertifiedKey>>`.
                // `match_sni` maps `&BTreeMap<String, Arc<CertifiedKey>>` and
                // expects `default: Option<&Arc<CertifiedKey>>`.
                let default = self.default.as_ref();
                match_sni(&self.sni_map, name, self.strict_sni, default).map(Arc::clone)
            }
            None => {
                // No SNI sent — respect strict mode the same way.
                if self.strict_sni {
                    None
                } else {
                    self.default.as_ref().map(Arc::clone)
                }
            }
        }
    }
}

impl rustls::server::ResolvesServerCert for Pkcs11ServerCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.lookup(client_hello.server_name())
    }
}

// ---------------------------------------------------------------------------
// Hermetic unit tests for `match_sni` — no HSM, no async, no I/O.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sni_exact_match() {
        let mut map = BTreeMap::new();
        map.insert("foo.example.com".to_string(), 1u32);
        assert_eq!(match_sni(&map, "foo.example.com", false, None), Some(&1));
    }

    #[test]
    fn sni_exact_takes_priority_over_wildcard() {
        let mut map = BTreeMap::new();
        map.insert("foo.example.com".to_string(), 1u32);
        map.insert("*.example.com".to_string(), 2u32);
        assert_eq!(match_sni(&map, "foo.example.com", false, None), Some(&1));
    }

    #[test]
    fn sni_wildcard_single_label() {
        let mut map = BTreeMap::new();
        map.insert("*.example.com".to_string(), 42u32);
        assert_eq!(match_sni(&map, "bar.example.com", false, None), Some(&42));
    }

    #[test]
    fn sni_wildcard_does_not_match_multilabel() {
        let mut map = BTreeMap::new();
        map.insert("*.example.com".to_string(), 42u32);
        assert_eq!(match_sni(&map, "a.b.example.com", false, None), None);
    }

    #[test]
    fn sni_wildcard_does_not_match_apex() {
        let mut map = BTreeMap::new();
        map.insert("*.example.com".to_string(), 42u32);
        assert_eq!(match_sni(&map, "example.com", false, None), None);
    }

    #[test]
    fn sni_strict_returns_none_on_no_match() {
        let map: BTreeMap<String, u32> = BTreeMap::new();
        assert_eq!(match_sni(&map, "other.example.com", true, None), None);
    }

    #[test]
    fn sni_non_strict_returns_default() {
        let map: BTreeMap<String, u32> = BTreeMap::new();
        let default = 99u32;
        assert_eq!(
            match_sni(&map, "other.example.com", false, Some(&default)),
            Some(&99)
        );
    }
}
