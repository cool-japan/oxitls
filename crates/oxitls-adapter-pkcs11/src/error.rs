// SPDX-License-Identifier: Apache-2.0
// Copyright COOLJAPAN OU (Team Kitasan)
//! Error types for the PKCS#11 adapter.

use std::fmt;

/// Errors that can occur when using the PKCS#11 signing adapter.
///
/// This is the legacy error type preserved for backward compatibility.
/// New code should use [`Pkcs11Error`].
#[derive(Debug)]
pub enum PkcsSignError {
    /// Failed to load or initialize the PKCS#11 module.
    InitError(String),
    /// Failed to open or manage a session.
    SessionError(String),
    /// Failed to find a key object matching the given label.
    KeyNotFound(String),
    /// The signing operation itself failed.
    SignError(String),
    /// The raw ECDSA signature from the token had an unexpected length.
    InvalidSignatureLength {
        /// The expected signature byte count.
        expected: usize,
        /// The actual signature byte count returned by the token.
        got: usize,
    },
}

impl fmt::Display for PkcsSignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PkcsSignError::InitError(msg) => write!(f, "PKCS#11 init error: {msg}"),
            PkcsSignError::SessionError(msg) => write!(f, "PKCS#11 session error: {msg}"),
            PkcsSignError::KeyNotFound(label) => {
                write!(f, "PKCS#11 key not found for label: {label}")
            }
            PkcsSignError::SignError(msg) => write!(f, "PKCS#11 sign error: {msg}"),
            PkcsSignError::InvalidSignatureLength { expected, got } => write!(
                f,
                "PKCS#11 invalid signature length: expected {expected}, got {got}"
            ),
        }
    }
}

impl std::error::Error for PkcsSignError {}

// ---------------------------------------------------------------------------
// Production error type (Wave 5)
// ---------------------------------------------------------------------------

/// Comprehensive error type for the PKCS#11 adapter.
///
/// Used throughout the pool, provider, resolver, and signer subsystems.
#[derive(Debug)]
pub enum Pkcs11Error {
    /// Failed to load or initialize the PKCS#11 module or library.
    InitError(String),
    /// Failed to open, manage, or operate on a PKCS#11 session.
    SessionError(String),
    /// No key or certificate object with the requested label was found.
    KeyNotFound(String),
    /// The signing operation returned an error from the token.
    SignError(String),
    /// The session pool has no available sessions.
    SessionPoolExhausted,
    /// An HSM-level error with the raw CKR_ return value code.
    HsmError {
        /// The PKCS#11 return value mapped to a numeric code.
        code: u32,
        /// Human-readable description.
        msg: String,
    },
    /// The requested operation is not supported by this token or implementation.
    Unsupported(String),
    /// The PKCS#11 shared library could not be loaded.
    LoadFailed(String),
    /// A rustls-level error occurred while building or using a TLS configuration.
    Tls(String),
    /// Catch-all for errors that do not fit any specific category.
    Other(String),
}

impl fmt::Display for Pkcs11Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Pkcs11Error::InitError(msg) => write!(f, "PKCS#11 init error: {msg}"),
            Pkcs11Error::SessionError(msg) => write!(f, "PKCS#11 session error: {msg}"),
            Pkcs11Error::KeyNotFound(label) => {
                write!(f, "PKCS#11 key not found for label: {label}")
            }
            Pkcs11Error::SignError(msg) => write!(f, "PKCS#11 sign error: {msg}"),
            Pkcs11Error::SessionPoolExhausted => {
                write!(f, "PKCS#11 session pool exhausted: no available sessions")
            }
            Pkcs11Error::HsmError { code, msg } => {
                write!(f, "PKCS#11 HSM error ({:#x}): {msg}", code)
            }
            Pkcs11Error::Unsupported(msg) => write!(f, "PKCS#11 unsupported: {msg}"),
            Pkcs11Error::LoadFailed(msg) => write!(f, "PKCS#11 library load failed: {msg}"),
            Pkcs11Error::Tls(msg) => write!(f, "TLS error: {msg}"),
            Pkcs11Error::Other(msg) => write!(f, "PKCS#11 error: {msg}"),
        }
    }
}

impl std::error::Error for Pkcs11Error {}

// Map PkcsSignError into Pkcs11Error for bridge compatibility.
impl From<PkcsSignError> for Pkcs11Error {
    fn from(e: PkcsSignError) -> Self {
        match e {
            PkcsSignError::InitError(msg) => Pkcs11Error::InitError(msg),
            PkcsSignError::SessionError(msg) => Pkcs11Error::SessionError(msg),
            PkcsSignError::KeyNotFound(msg) => Pkcs11Error::KeyNotFound(msg),
            PkcsSignError::SignError(msg) => Pkcs11Error::SignError(msg),
            PkcsSignError::InvalidSignatureLength { expected, got } => Pkcs11Error::SignError(
                format!("invalid ECDSA signature length: expected {expected}, got {got}"),
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// From<cryptoki::error::Error> (only compiled when pkcs11 feature is active)
// ---------------------------------------------------------------------------

#[cfg(feature = "pkcs11")]
impl From<cryptoki::error::Error> for Pkcs11Error {
    fn from(e: cryptoki::error::Error) -> Self {
        match e {
            cryptoki::error::Error::Pkcs11(rv, _func) => {
                let code = rv_error_to_code(&rv);
                Pkcs11Error::HsmError {
                    code,
                    msg: format!("PKCS#11 rv={rv}"),
                }
            }
            cryptoki::error::Error::LibraryLoading(inner) => {
                Pkcs11Error::LoadFailed(inner.to_string())
            }
            cryptoki::error::Error::NotSupported => {
                Pkcs11Error::Unsupported("operation not supported by this token".to_string())
            }
            other => Pkcs11Error::Other(other.to_string()),
        }
    }
}

/// Map a `cryptoki::error::RvError` to a numeric CKR_ code.
///
/// `RvError` is a Rust enum, not a numeric primitive, so we match on its
/// `Display` string (e.g. `"CKR_FUNCTION_FAILED"`) and return the
/// corresponding PKCS#11 v2.40 constant value.  Unknown variants fall
/// through to `0xFFFF_FFFF`.
#[cfg(feature = "pkcs11")]
fn rv_error_to_code(rv: &cryptoki::error::RvError) -> u32 {
    let name = format!("{rv}");
    match name.as_str() {
        "CKR_CANCEL" => 0x0000_0001,
        "CKR_HOST_MEMORY" => 0x0000_0002,
        "CKR_SLOT_ID_INVALID" => 0x0000_0003,
        "CKR_GENERAL_ERROR" => 0x0000_0005,
        "CKR_FUNCTION_FAILED" => 0x0000_0006,
        "CKR_ARGUMENTS_BAD" => 0x0000_0007,
        "CKR_NO_EVENT" => 0x0000_0008,
        "CKR_NEED_TO_CREATE_THREADS" => 0x0000_0009,
        "CKR_CANT_LOCK" => 0x0000_000A,
        "CKR_ATTRIBUTE_READ_ONLY" => 0x0000_0010,
        "CKR_ATTRIBUTE_SENSITIVE" => 0x0000_0011,
        "CKR_ATTRIBUTE_TYPE_INVALID" => 0x0000_0012,
        "CKR_ATTRIBUTE_VALUE_INVALID" => 0x0000_0013,
        "CKR_DATA_INVALID" => 0x0000_0020,
        "CKR_DATA_LEN_RANGE" => 0x0000_0021,
        "CKR_DEVICE_ERROR" => 0x0000_0030,
        "CKR_DEVICE_MEMORY" => 0x0000_0031,
        "CKR_DEVICE_REMOVED" => 0x0000_0032,
        "CKR_ENCRYPTED_DATA_INVALID" => 0x0000_0040,
        "CKR_ENCRYPTED_DATA_LEN_RANGE" => 0x0000_0041,
        "CKR_FUNCTION_CANCELED" => 0x0000_0050,
        "CKR_FUNCTION_NOT_PARALLEL" => 0x0000_0051,
        "CKR_FUNCTION_NOT_SUPPORTED" => 0x0000_0054,
        "CKR_KEY_HANDLE_INVALID" => 0x0000_0060,
        "CKR_KEY_SIZE_RANGE" => 0x0000_0062,
        "CKR_KEY_TYPE_INCONSISTENT" => 0x0000_0063,
        "CKR_KEY_NOT_NEEDED" => 0x0000_0064,
        "CKR_KEY_CHANGED" => 0x0000_0065,
        "CKR_KEY_NEEDED" => 0x0000_0066,
        "CKR_KEY_INDIGESTIBLE" => 0x0000_0067,
        "CKR_KEY_FUNCTION_NOT_PERMITTED" => 0x0000_0068,
        "CKR_KEY_NOT_WRAPPABLE" => 0x0000_0069,
        "CKR_KEY_UNEXTRACTABLE" => 0x0000_006A,
        "CKR_MECHANISM_INVALID" => 0x0000_0070,
        "CKR_MECHANISM_PARAM_INVALID" => 0x0000_0071,
        "CKR_OBJECT_HANDLE_INVALID" => 0x0000_0082,
        "CKR_OPERATION_ACTIVE" => 0x0000_0090,
        "CKR_OPERATION_NOT_INITIALIZED" => 0x0000_0091,
        "CKR_PIN_INCORRECT" => 0x000000A0,
        "CKR_PIN_INVALID" => 0x000000A1,
        "CKR_PIN_LEN_RANGE" => 0x000000A2,
        "CKR_PIN_EXPIRED" => 0x000000A3,
        "CKR_PIN_LOCKED" => 0x000000A4,
        "CKR_SESSION_CLOSED" => 0x000000B0,
        "CKR_SESSION_COUNT" => 0x000000B1,
        "CKR_SESSION_HANDLE_INVALID" => 0x000000B3,
        "CKR_SESSION_PARALLEL_NOT_SUPPORTED" => 0x000000B4,
        "CKR_SESSION_READ_ONLY" => 0x000000B5,
        "CKR_SESSION_EXISTS" => 0x000000B6,
        "CKR_SESSION_READ_ONLY_EXISTS" => 0x000000B7,
        "CKR_SESSION_READ_WRITE_SO_EXISTS" => 0x000000B8,
        "CKR_SIGNATURE_INVALID" => 0x000000C0,
        "CKR_SIGNATURE_LEN_RANGE" => 0x000000C1,
        "CKR_TEMPLATE_INCOMPLETE" => 0x000000D0,
        "CKR_TEMPLATE_INCONSISTENT" => 0x000000D1,
        "CKR_TOKEN_NOT_PRESENT" => 0x000000E0,
        "CKR_TOKEN_NOT_RECOGNIZED" => 0x000000E1,
        "CKR_TOKEN_WRITE_PROTECTED" => 0x000000E2,
        "CKR_UNWRAPPING_KEY_HANDLE_INVALID" => 0x000000F0,
        "CKR_UNWRAPPING_KEY_SIZE_RANGE" => 0x000000F1,
        "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT" => 0x000000F2,
        "CKR_USER_ALREADY_LOGGED_IN" => 0x0000_0100,
        "CKR_USER_NOT_LOGGED_IN" => 0x0000_0101,
        "CKR_USER_PIN_NOT_INITIALIZED" => 0x0000_0102,
        "CKR_USER_TYPE_INVALID" => 0x0000_0103,
        "CKR_USER_ANOTHER_ALREADY_LOGGED_IN" => 0x0000_0104,
        "CKR_USER_TOO_MANY_TYPES" => 0x0000_0105,
        "CKR_WRAPPED_KEY_INVALID" => 0x0000_0110,
        "CKR_WRAPPED_KEY_LEN_RANGE" => 0x0000_0112,
        "CKR_WRAPPING_KEY_HANDLE_INVALID" => 0x0000_0113,
        "CKR_WRAPPING_KEY_SIZE_RANGE" => 0x0000_0114,
        "CKR_WRAPPING_KEY_TYPE_INCONSISTENT" => 0x0000_0115,
        "CKR_RANDOM_SEED_NOT_SUPPORTED" => 0x0000_0120,
        "CKR_RANDOM_NO_RNG" => 0x0000_0121,
        "CKR_DOMAIN_PARAMS_INVALID" => 0x0000_0130,
        "CKR_BUFFER_TOO_SMALL" => 0x0000_0150,
        "CKR_SAVED_STATE_INVALID" => 0x0000_0160,
        "CKR_INFORMATION_SENSITIVE" => 0x0000_0170,
        "CKR_STATE_UNSAVEABLE" => 0x0000_0180,
        "CKR_CRYPTOKI_NOT_INITIALIZED" => 0x0000_0190,
        "CKR_CRYPTOKI_ALREADY_INITIALIZED" => 0x0000_0191,
        "CKR_MUTEX_BAD" => 0x000001A0,
        "CKR_MUTEX_NOT_LOCKED" => 0x000001A1,
        "CKR_NEW_PIN_MODE" => 0x000001B0,
        "CKR_NEXT_OTP" => 0x000001B1,
        "CKR_EXCEEDED_MAX_ITERATIONS" => 0x000001B5,
        "CKR_FIPS_SELF_TEST_FAILED" => 0x000001B6,
        "CKR_LIBRARY_LOAD_FAILED" => 0x000001B7,
        "CKR_PIN_TOO_WEAK" => 0x000001B8,
        "CKR_PUBLIC_KEY_INVALID" => 0x000001B9,
        "CKR_FUNCTION_REJECTED" => 0x0000_0200,
        _ => 0xFFFF_FFFF,
    }
}
