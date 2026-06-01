//! Helper for extracting [`ConnectionInfo`] from a rustls connection state.
//!
//! Adapter crates can use [`connection_info_from`] to avoid orphan-rule problems
//! when implementing connection-info accessors for foreign stream types.

use std::ops::Deref;

use rustls::SupportedCipherSuite;

use crate::{CipherSuite, ConnectionInfo, TlsVersion};

/// Extract [`ConnectionInfo`] from a rustls common-state reference.
///
/// The adapter supplies any type `C` that `Deref`s to [`rustls::CommonState`].
/// Returns `None` if `protocol_version()` is not yet known (i.e. the handshake
/// has not completed).
///
/// **SNI is not populated here** — `server_name()` is only available on
/// `ServerConnection`, not on `CommonState`.  Adapters that need SNI should
/// call `with_sni()` on the returned `ConnectionInfo` after this function.
///
/// # Example
/// ```rust,ignore
/// let conn_info = oxitls_core::connection_info_from(&tls_conn)
///     .unwrap_or_default();
/// ```
pub fn connection_info_from<C>(conn: &C) -> Option<ConnectionInfo>
where
    C: Deref<Target = rustls::CommonState>,
{
    let version = conn.protocol_version().map(tls_version_from_rustls)?;
    let cipher = conn.negotiated_cipher_suite().map(cipher_suite_from_rustls);
    let alpn = conn.alpn_protocol().map(|a| a.to_vec());

    let mut info = ConnectionInfo::new().with_version(version);
    if let Some(c) = cipher {
        info = info.with_cipher_suite(c);
    }
    if let Some(a) = alpn {
        info = info.with_alpn_protocol(a);
    }
    Some(info)
}

/// Convert a rustls [`ProtocolVersion`][rustls::ProtocolVersion] to our [`TlsVersion`].
fn tls_version_from_rustls(v: rustls::ProtocolVersion) -> TlsVersion {
    match v {
        rustls::ProtocolVersion::TLSv1_3 => TlsVersion::Tls13,
        rustls::ProtocolVersion::TLSv1_2 => TlsVersion::Tls12,
        // TLS 1.0/1.1 or any future version: fall back to Tls12 as the safer default.
        _ => TlsVersion::Tls12,
    }
}

/// Convert a rustls [`SupportedCipherSuite`] to our [`CipherSuite`].
fn cipher_suite_from_rustls(s: SupportedCipherSuite) -> CipherSuite {
    use rustls::CipherSuite as RS;
    match s.suite() {
        RS::TLS13_AES_256_GCM_SHA384 => CipherSuite::Tls13Aes256GcmSha384,
        RS::TLS13_AES_128_GCM_SHA256 => CipherSuite::Tls13Aes128GcmSha256,
        RS::TLS13_CHACHA20_POLY1305_SHA256 => CipherSuite::Tls13Chacha20Poly1305Sha256,
        RS::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => CipherSuite::Tls12EcdheEcdsaAes128GcmSha256,
        RS::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => CipherSuite::Tls12EcdheEcdsaAes256GcmSha384,
        RS::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => CipherSuite::Tls12EcdheRsaAes128GcmSha256,
        RS::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => CipherSuite::Tls12EcdheRsaAes256GcmSha384,
        RS::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => {
            CipherSuite::Tls12EcdheEcdsaChacha20Poly1305Sha256
        }
        RS::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => {
            CipherSuite::Tls12EcdheRsaChacha20Poly1305Sha256
        }
        _ => CipherSuite::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_version_from_rustls_tls13() {
        let v = tls_version_from_rustls(rustls::ProtocolVersion::TLSv1_3);
        assert_eq!(v, TlsVersion::Tls13);
    }

    #[test]
    fn tls_version_from_rustls_tls12() {
        let v = tls_version_from_rustls(rustls::ProtocolVersion::TLSv1_2);
        assert_eq!(v, TlsVersion::Tls12);
    }

    #[test]
    fn tls_version_from_rustls_unknown_falls_back_to_tls12() {
        // ProtocolVersion::Unknown(0x0300) = SSL 3.0 — should fall back
        let v = tls_version_from_rustls(rustls::ProtocolVersion::Unknown(0x0300));
        assert_eq!(v, TlsVersion::Tls12);
    }
}
