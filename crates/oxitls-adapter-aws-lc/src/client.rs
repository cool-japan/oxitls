//! Client-side TLS config builders backed by aws-lc-rs.
//!
//! All items are gated on `#[cfg(feature = "aws-lc")]`.

/// Build a `rustls::ClientConfig` using the aws-lc-rs provider.
///
/// Server certificates will be validated against `roots`. `alpn` specifies the
/// list of ALPN protocol IDs to advertise (pass an empty `Vec` to disable ALPN).
///
/// Does **not** call `CryptoProvider::install_default()`.
///
/// # Errors
/// Returns [`oxitls_core::TlsError`] if the provider or protocol version
/// configuration is rejected by rustls.
#[cfg(feature = "aws-lc")]
pub fn aws_lc_client_config(
    roots: rustls::RootCertStore,
    alpn: Vec<Vec<u8>>,
) -> Result<rustls::ClientConfig, oxitls_core::TlsError> {
    let provider = crate::provider::aws_lc_provider();
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| oxitls_core::TlsError::InvalidConfig(e.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    if !alpn.is_empty() {
        cfg.alpn_protocols = alpn;
    }
    Ok(cfg)
}

/// Build a mutual-TLS (mTLS) `rustls::ClientConfig` using the aws-lc-rs provider.
///
/// The client presents `client_cert_chain` (leaf first) signed by `client_key`
/// during the handshake. Server certificates are validated against `roots`.
///
/// Does **not** call `CryptoProvider::install_default()`.
///
/// # Errors
/// Returns [`oxitls_core::TlsError`] if the provider, protocol version, or
/// client certificate/key configuration is rejected.
#[cfg(feature = "aws-lc")]
pub fn aws_lc_mtls_client_config(
    roots: rustls::RootCertStore,
    client_cert_chain: Vec<rustls_pki_types::CertificateDer<'static>>,
    client_key: rustls_pki_types::PrivateKeyDer<'static>,
) -> Result<rustls::ClientConfig, oxitls_core::TlsError> {
    let provider = crate::provider::aws_lc_provider();
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| oxitls_core::TlsError::InvalidConfig(e.to_string()))?
        .with_root_certificates(roots)
        .with_client_auth_cert(client_cert_chain, client_key)
        .map_err(|e| oxitls_core::TlsError::BadCert(e.to_string()))?;
    Ok(cfg)
}
