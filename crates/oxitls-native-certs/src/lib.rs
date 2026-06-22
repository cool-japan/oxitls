#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! OxiTLS OS-native certificate-store adapter — a standalone, opt-in quarantine crate.
//!
//! Loads the operating system's native root certificate store via platform FFI:
//! `Security.framework` on macOS and SChannel on Windows. On Linux it reads the
//! system PEM bundle, so the Linux path stays pure Rust.
//!
//! Because the macOS / Windows paths pull in platform FFI shims
//! (`security-framework` / `schannel`), this functionality lives in its own
//! impure-by-design quarantine crate **instead of** behind a feature flag. Apps
//! that need OS-native trust roots depend on `oxitls-native-certs` directly; it
//! is **not** feature-gated from `oxitls-webpki-roots`.
//!
//! All loaders are best-effort: malformed certificates in the host store are
//! skipped rather than aborting the entire load.

use rustls::RootCertStore;
use rustls_pki_types::CertificateDer;

use oxitls_core::TlsError;

/// Load the OS-native root cert store into a [`rustls::RootCertStore`].
///
/// Platform behavior:
/// * **macOS**: queries `Security.framework` trust settings across the
///   User / Admin / System domains and keeps only certs whose effective
///   trust setting permits SSL/TLS validation.
/// * **Linux**: reads the first PEM bundle found among the common system
///   locations (`/etc/ssl/certs/ca-certificates.crt`,
///   `/etc/pki/tls/cert.pem`, `/etc/ssl/cert.pem`).
/// * **Windows**: opens the current-user `ROOT` store via `schannel` and
///   collects all certs.
/// * **Other**: returns [`TlsError::Other`] — not supported.
///
/// The function is `async` because the Linux path uses `tokio::fs`. The
/// platform-FFI paths are wrapped in `tokio::task::spawn_blocking` to avoid
/// blocking the async runtime — Keychain / Schannel calls can take 10s of
/// milliseconds and would otherwise stall executor workers.
///
/// # Errors
///
/// Returns [`TlsError::Other`] (or [`TlsError::Io`]) if the underlying OS
/// call fails. Returns an empty store rather than failing if the store can
/// be opened but contains zero acceptable certificates — callers should
/// check `is_empty()` if a populated store is required.
pub async fn load_native_roots() -> Result<RootCertStore, TlsError> {
    #[cfg(target_os = "macos")]
    {
        load_macos_roots().await
    }

    #[cfg(target_os = "linux")]
    {
        load_linux_roots().await
    }

    #[cfg(target_os = "windows")]
    {
        load_windows_roots().await
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Err(TlsError::Other(
            "native-roots: unsupported target OS".to_string(),
        ))
    }
}

// ── macOS ────────────────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
async fn load_macos_roots() -> Result<RootCertStore, TlsError> {
    // Security.framework calls block — push to a blocking thread.
    let ders = tokio::task::spawn_blocking(macos_collect_trusted_ders)
        .await
        .map_err(|e| TlsError::Other(format!("native-roots macOS join error: {e}")))??;

    let mut store = RootCertStore::empty();
    let certs: Vec<CertificateDer<'static>> = ders.into_iter().map(CertificateDer::from).collect();
    let (_added, _skipped) = store.add_parsable_certificates(certs);
    Ok(store)
}

#[cfg(target_os = "macos")]
fn macos_collect_trusted_ders() -> Result<Vec<Vec<u8>>, TlsError> {
    use security_framework::trust_settings::{Domain, TrustSettings, TrustSettingsForCertificate};

    let mut ders: Vec<Vec<u8>> = Vec::new();
    // Iterate User → Admin → System; later domains overlay earlier ones, but
    // dup certs are harmless (rustls accepts the first matching anchor).
    for domain in [Domain::User, Domain::Admin, Domain::System] {
        let settings = TrustSettings::new(domain);
        let iter = match settings.iter() {
            Ok(it) => it,
            // No trust settings in this domain — skip silently.
            Err(_) => continue,
        };
        for cert in iter {
            let trust_for_ssl = match settings.tls_trust_settings_for_certificate(&cert) {
                Ok(Some(TrustSettingsForCertificate::TrustRoot))
                | Ok(Some(TrustSettingsForCertificate::TrustAsRoot)) => true,
                // No specific SSL setting: Apple docs say empty trust settings
                // mean "always trust"; we follow rustls-platform-verifier's
                // convention and accept these too.
                Ok(None) => true,
                Ok(Some(TrustSettingsForCertificate::Deny)) => false,
                Ok(Some(TrustSettingsForCertificate::Unspecified)) => false,
                Ok(Some(TrustSettingsForCertificate::Invalid)) => false,
                // Skip on error rather than aborting the whole load.
                Err(_) => continue,
            };
            if !trust_for_ssl {
                continue;
            }
            ders.push(cert.to_der());
        }
    }
    Ok(ders)
}

// ── Linux ────────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
async fn load_linux_roots() -> Result<RootCertStore, TlsError> {
    // Standard CA bundle locations across major distros.
    const PATHS: &[&str] = &[
        "/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu/Alpine
        "/etc/pki/tls/cert.pem",              // RHEL/CentOS/Fedora
        "/etc/ssl/cert.pem",                  // OpenBSD-style / some musl distros
    ];

    let mut last_err: Option<std::io::Error> = None;
    for path in PATHS {
        match tokio::fs::read(path).await {
            Ok(bytes) => {
                let mut store = RootCertStore::empty();
                let mut cursor = std::io::Cursor::new(&bytes);
                let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cursor)
                    .filter_map(|res| res.ok())
                    .collect();
                let (_added, _skipped) = store.add_parsable_certificates(certs);
                return Ok(store);
            }
            Err(e) => last_err = Some(e),
        }
    }

    Err(TlsError::Other(format!(
        "native-roots Linux: no CA bundle found at any of {:?} (last error: {:?})",
        PATHS, last_err
    )))
}

// ── Windows ──────────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
async fn load_windows_roots() -> Result<RootCertStore, TlsError> {
    let ders = tokio::task::spawn_blocking(windows_collect_trusted_ders)
        .await
        .map_err(|e| TlsError::Other(format!("native-roots Windows join error: {e}")))??;

    let mut store = RootCertStore::empty();
    let certs: Vec<CertificateDer<'static>> = ders.into_iter().map(CertificateDer::from).collect();
    let (_added, _skipped) = store.add_parsable_certificates(certs);
    Ok(store)
}

#[cfg(target_os = "windows")]
fn windows_collect_trusted_ders() -> Result<Vec<Vec<u8>>, TlsError> {
    use schannel::cert_store::CertStore;

    let store = CertStore::open_current_user("ROOT").map_err(|e| {
        TlsError::Other(format!("native-roots Windows: cannot open ROOT store: {e}"))
    })?;
    let ders: Vec<Vec<u8>> = store.certs().map(|cert| cert.to_der().to_vec()).collect();
    Ok(ders)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Linux test — runs on CI Linux runners. The function should either
    // succeed (most Linux distros ship a CA bundle) or return an error;
    // we just check that it does not panic.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_load_does_not_panic() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        let res = rt.block_on(load_native_roots());
        // Either Ok(store) or Err(...). Both are acceptable.
        let _ = res;
    }

    // Smoke check on macOS — same shape as the Linux test.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_load_does_not_panic() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        let _ = rt.block_on(load_native_roots());
    }
}
