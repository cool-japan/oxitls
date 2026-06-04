//! RFC 8879 TLS certificate compression backed by OxiARC (pure-Rust zlib).
//!
//! Provides pluggable `CertCompressor` and `CertDecompressor` implementations
//! using `oxiarc_deflate` (RFC 1950 zlib / RFC 1951 DEFLATE). Wired into rustls via
//! the public `cert_compressors`/`cert_decompressors` config fields.
//!
//! Compression applies to TLS 1.3 only; rustls ignores it for TLS 1.2.
//!
//! # Feature gate
//! This module is only compiled when the `cert-compression` feature is enabled.
//!
//! # Usage
//!
//! ```no_run
//! # fn example() {
//! use oxitls_adapter_rustls_rustcrypto::cert_compression::install_cert_compression_client;
//! // ... build a rustls::ClientConfig config ...
//! # }
//! ```

use rustls::compress::{
    CertCompressor, CertDecompressor, CompressionFailed, CompressionLevel, DecompressionFailed,
};
use rustls::CertificateCompressionAlgorithm;

/// Zero-sized compressor using `oxiarc_deflate` RFC 1950 zlib.
///
/// Maps `Interactive` to compression level 1 (fast) and `Amortized` to level 9 (best).
#[derive(Debug)]
pub struct OxiArcZlibCompressor;

/// Zero-sized decompressor using `oxiarc_deflate` RFC 1950 zlib.
///
/// Enforces rustls's strict contract: decoded length MUST equal the pre-sized output buffer.
#[derive(Debug)]
pub struct OxiArcZlibDecompressor;

impl CertCompressor for OxiArcZlibCompressor {
    fn compress(
        &self,
        input: Vec<u8>,
        level: CompressionLevel,
    ) -> Result<Vec<u8>, CompressionFailed> {
        let lvl: u8 = match level {
            CompressionLevel::Interactive => 1,
            CompressionLevel::Amortized => 9,
        };
        oxiarc_deflate::zlib_compress(&input, lvl).map_err(|_| CompressionFailed)
    }

    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm::Zlib
    }
}

impl CertDecompressor for OxiArcZlibDecompressor {
    fn decompress(&self, input: &[u8], output: &mut [u8]) -> Result<(), DecompressionFailed> {
        let decoded = oxiarc_deflate::zlib_decompress(input).map_err(|_| DecompressionFailed)?;
        // rustls contract: the decoded length MUST equal the pre-sized output buffer length.
        if decoded.len() != output.len() {
            return Err(DecompressionFailed);
        }
        output.copy_from_slice(&decoded);
        Ok(())
    }

    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm::Zlib
    }
}

/// A `&'static dyn CertCompressor` backed by `oxiarc_deflate` zlib.
pub const OXIARC_ZLIB_COMPRESSOR: &dyn CertCompressor = &OxiArcZlibCompressor;

/// A `&'static dyn CertDecompressor` backed by `oxiarc_deflate` zlib.
pub const OXIARC_ZLIB_DECOMPRESSOR: &dyn CertDecompressor = &OxiArcZlibDecompressor;

/// Install OxiARC zlib cert compression into a [`rustls::ClientConfig`].
///
/// Sets the config's `cert_compressors` and `cert_decompressors` to the OxiARC zlib
/// implementations, overwriting any previously installed compressors.
///
/// This function is the correct one to call for the **client** side per the rustls
/// compress module documentation:
/// - `cert_compressors` → client *sends* a compressed certificate
/// - `cert_decompressors` → client *receives* a compressed certificate from the server
pub fn install_cert_compression_client(config: &mut rustls::ClientConfig) {
    config.cert_compressors = vec![OXIARC_ZLIB_COMPRESSOR];
    config.cert_decompressors = vec![OXIARC_ZLIB_DECOMPRESSOR];
}

/// Install OxiARC zlib cert compression into a [`rustls::ServerConfig`].
///
/// Sets the config's `cert_compressors` and `cert_decompressors` to the OxiARC zlib
/// implementations, overwriting any previously installed compressors.
///
/// This function is the correct one to call for the **server** side:
/// - `cert_compressors` → server *sends* a compressed certificate to the client
/// - `cert_decompressors` → server *receives* a compressed client certificate
pub fn install_cert_compression_server(config: &mut rustls::ServerConfig) {
    config.cert_compressors = vec![OXIARC_ZLIB_COMPRESSOR];
    config.cert_decompressors = vec![OXIARC_ZLIB_DECOMPRESSOR];
}
