//! TLS alert descriptions as defined in RFC 8446 §6.

use std::fmt;

/// A TLS alert description code (RFC 8446 §6).
///
/// The `Unknown(u8)` catch-all carries any code not listed in RFC 8446,
/// allowing the type to remain forwards-compatible without breaking consumers.
///
/// # Examples
/// ```
/// use oxitls_core::AlertDescription;
///
/// let d = AlertDescription::from(40u8);
/// assert_eq!(d, AlertDescription::HandshakeFailure);
/// assert_eq!(d.to_u8(), 40);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AlertDescription {
    /// `close_notify` (0) — orderly TLS shutdown.
    CloseNotify,
    /// `unexpected_message` (10) — inappropriate message received.
    UnexpectedMessage,
    /// `bad_record_mac` (20) — record authentication failure.
    BadRecordMac,
    /// `record_overflow` (22) — TLSCiphertext record too long.
    RecordOverflow,
    /// `handshake_failure` (40) — unable to negotiate acceptable security parameters.
    HandshakeFailure,
    /// `bad_certificate` (42) — unacceptable certificate.
    BadCertificate,
    /// `unsupported_certificate` (43) — certificate type not supported.
    UnsupportedCertificate,
    /// `certificate_revoked` (44) — certificate has been revoked.
    CertificateRevoked,
    /// `certificate_expired` (45) — certificate has expired.
    CertificateExpired,
    /// `certificate_unknown` (46) — unspecified certificate problem.
    CertificateUnknown,
    /// `illegal_parameter` (47) — field in the handshake was out of range or inconsistent.
    IllegalParameter,
    /// `unknown_ca` (48) — certificate's CA is not trusted.
    UnknownCa,
    /// `access_denied` (49) — valid certificate, but access control denied.
    AccessDenied,
    /// `decode_error` (50) — unable to decode a message.
    DecodeError,
    /// `decrypt_error` (51) — handshake cryptographic operation failed.
    DecryptError,
    /// `protocol_version` (70) — protocol version not supported.
    ProtocolVersion,
    /// `insufficient_security` (71) — server requires ciphers more secure than those supported by client.
    InsufficientSecurity,
    /// `internal_error` (80) — internal error unrelated to the peer or correctness of the protocol.
    InternalError,
    /// `inappropriate_fallback` (86) — TLS_FALLBACK_SCSV in response to version downgrade.
    InappropriateFallback,
    /// `user_canceled` (90) — handshake is being canceled for a reason unrelated to a protocol failure.
    UserCanceled,
    /// `missing_extension` (109) — negotiated extension was missing from the ClientHello.
    MissingExtension,
    /// `unsupported_extension` (110) — extension not permitted for this message.
    UnsupportedExtension,
    /// `unrecognized_name` (112) — SNI name not recognized.
    UnrecognizedName,
    /// `bad_certificate_status_response` (113) — OCSP response invalid.
    BadCertificateStatusResponse,
    /// `unknown_psk_identity` (115) — no acceptable PSK identity was supplied.
    UnknownPskIdentity,
    /// `certificate_required` (116) — client certificate required.
    CertificateRequired,
    /// `no_application_protocol` (120) — no ALPN protocol overlap.
    NoApplicationProtocol,
    /// An alert code not listed in RFC 8446.
    ///
    /// The wrapped value is the raw numeric alert code.
    Unknown(u8),
}

impl AlertDescription {
    /// Return the raw RFC 8446 numeric alert code for this description.
    pub fn to_u8(&self) -> u8 {
        match self {
            AlertDescription::CloseNotify => 0,
            AlertDescription::UnexpectedMessage => 10,
            AlertDescription::BadRecordMac => 20,
            AlertDescription::RecordOverflow => 22,
            AlertDescription::HandshakeFailure => 40,
            AlertDescription::BadCertificate => 42,
            AlertDescription::UnsupportedCertificate => 43,
            AlertDescription::CertificateRevoked => 44,
            AlertDescription::CertificateExpired => 45,
            AlertDescription::CertificateUnknown => 46,
            AlertDescription::IllegalParameter => 47,
            AlertDescription::UnknownCa => 48,
            AlertDescription::AccessDenied => 49,
            AlertDescription::DecodeError => 50,
            AlertDescription::DecryptError => 51,
            AlertDescription::ProtocolVersion => 70,
            AlertDescription::InsufficientSecurity => 71,
            AlertDescription::InternalError => 80,
            AlertDescription::InappropriateFallback => 86,
            AlertDescription::UserCanceled => 90,
            AlertDescription::MissingExtension => 109,
            AlertDescription::UnsupportedExtension => 110,
            AlertDescription::UnrecognizedName => 112,
            AlertDescription::BadCertificateStatusResponse => 113,
            AlertDescription::UnknownPskIdentity => 115,
            AlertDescription::CertificateRequired => 116,
            AlertDescription::NoApplicationProtocol => 120,
            AlertDescription::Unknown(code) => *code,
        }
    }
}

impl From<u8> for AlertDescription {
    fn from(code: u8) -> Self {
        match code {
            0 => AlertDescription::CloseNotify,
            10 => AlertDescription::UnexpectedMessage,
            20 => AlertDescription::BadRecordMac,
            22 => AlertDescription::RecordOverflow,
            40 => AlertDescription::HandshakeFailure,
            42 => AlertDescription::BadCertificate,
            43 => AlertDescription::UnsupportedCertificate,
            44 => AlertDescription::CertificateRevoked,
            45 => AlertDescription::CertificateExpired,
            46 => AlertDescription::CertificateUnknown,
            47 => AlertDescription::IllegalParameter,
            48 => AlertDescription::UnknownCa,
            49 => AlertDescription::AccessDenied,
            50 => AlertDescription::DecodeError,
            51 => AlertDescription::DecryptError,
            70 => AlertDescription::ProtocolVersion,
            71 => AlertDescription::InsufficientSecurity,
            80 => AlertDescription::InternalError,
            86 => AlertDescription::InappropriateFallback,
            90 => AlertDescription::UserCanceled,
            109 => AlertDescription::MissingExtension,
            110 => AlertDescription::UnsupportedExtension,
            112 => AlertDescription::UnrecognizedName,
            113 => AlertDescription::BadCertificateStatusResponse,
            115 => AlertDescription::UnknownPskIdentity,
            116 => AlertDescription::CertificateRequired,
            120 => AlertDescription::NoApplicationProtocol,
            other => AlertDescription::Unknown(other),
        }
    }
}

impl fmt::Display for AlertDescription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AlertDescription::CloseNotify => write!(f, "close_notify"),
            AlertDescription::UnexpectedMessage => write!(f, "unexpected_message"),
            AlertDescription::BadRecordMac => write!(f, "bad_record_mac"),
            AlertDescription::RecordOverflow => write!(f, "record_overflow"),
            AlertDescription::HandshakeFailure => write!(f, "handshake_failure"),
            AlertDescription::BadCertificate => write!(f, "bad_certificate"),
            AlertDescription::UnsupportedCertificate => write!(f, "unsupported_certificate"),
            AlertDescription::CertificateRevoked => write!(f, "certificate_revoked"),
            AlertDescription::CertificateExpired => write!(f, "certificate_expired"),
            AlertDescription::CertificateUnknown => write!(f, "certificate_unknown"),
            AlertDescription::IllegalParameter => write!(f, "illegal_parameter"),
            AlertDescription::UnknownCa => write!(f, "unknown_ca"),
            AlertDescription::AccessDenied => write!(f, "access_denied"),
            AlertDescription::DecodeError => write!(f, "decode_error"),
            AlertDescription::DecryptError => write!(f, "decrypt_error"),
            AlertDescription::ProtocolVersion => write!(f, "protocol_version"),
            AlertDescription::InsufficientSecurity => write!(f, "insufficient_security"),
            AlertDescription::InternalError => write!(f, "internal_error"),
            AlertDescription::InappropriateFallback => write!(f, "inappropriate_fallback"),
            AlertDescription::UserCanceled => write!(f, "user_canceled"),
            AlertDescription::MissingExtension => write!(f, "missing_extension"),
            AlertDescription::UnsupportedExtension => write!(f, "unsupported_extension"),
            AlertDescription::UnrecognizedName => write!(f, "unrecognized_name"),
            AlertDescription::BadCertificateStatusResponse => {
                write!(f, "bad_certificate_status_response")
            }
            AlertDescription::UnknownPskIdentity => write!(f, "unknown_psk_identity"),
            AlertDescription::CertificateRequired => write!(f, "certificate_required"),
            AlertDescription::NoApplicationProtocol => write!(f, "no_application_protocol"),
            AlertDescription::Unknown(code) => write!(f, "unknown_alert({code})"),
        }
    }
}
