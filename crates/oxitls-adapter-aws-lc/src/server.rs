//! Server-side TLS config builders backed by aws-lc-rs.
//!
//! All items are gated on `#[cfg(feature = "aws-lc")]`.

/// Build a `rustls::ServerConfig` using the aws-lc-rs provider.
///
/// `certs` is the certificate chain (leaf first); `key` is the corresponding
/// private key. `alpn` specifies the list of ALPN protocol IDs to support
/// (pass an empty `Vec` to disable ALPN).
///
/// Does **not** call `CryptoProvider::install_default()`.
///
/// # Errors
/// Returns [`oxitls_core::TlsError`] if the provider, protocol version, or
/// certificate/key configuration is rejected by rustls.
#[cfg(feature = "aws-lc")]
pub fn aws_lc_server_config(
    certs: Vec<rustls_pki_types::CertificateDer<'static>>,
    key: rustls_pki_types::PrivateKeyDer<'static>,
    alpn: Vec<Vec<u8>>,
) -> Result<rustls::ServerConfig, oxitls_core::TlsError> {
    let provider = crate::provider::aws_lc_provider();
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| oxitls_core::TlsError::InvalidConfig(e.to_string()))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| oxitls_core::TlsError::BadCert(e.to_string()))?;
    if !alpn.is_empty() {
        cfg.alpn_protocols = alpn;
    }
    Ok(cfg)
}
