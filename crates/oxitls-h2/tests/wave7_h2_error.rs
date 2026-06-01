use oxitls_h2::{H2Error, Reason};

#[test]
fn stream_reset_variant_exists() {
    let err = H2Error::StreamReset(Reason::CANCEL);
    assert!(err.is_stream_reset());
    let s = format!("{err}");
    assert!(!s.is_empty());
}

#[test]
fn h2_reason_reexported() {
    // This test just verifies the re-export compiles
    let _reason = Reason::CANCEL;
    let _refused = Reason::REFUSED_STREAM;
    let _internal = Reason::INTERNAL_ERROR;
}

#[test]
fn h2_error_display_covers_stream_reset() {
    let err = H2Error::StreamReset(Reason::FLOW_CONTROL_ERROR);
    let s = format!("{err}");
    // Just check it doesn't panic and produces non-empty output
    assert!(!s.is_empty());
}

#[test]
fn stream_reset_is_not_io_not_alpn() {
    let err = H2Error::StreamReset(Reason::CANCEL);
    assert!(!err.is_io());
    assert!(!err.is_alpn_not_h2());
}

#[test]
fn is_timeout_covers_both_variants() {
    let timeout = H2Error::Timeout;
    assert!(timeout.is_timeout());
    let graceful = H2Error::GracefulShutdownTimeout;
    assert!(graceful.is_timeout());
}

#[test]
fn stream_reset_display_contains_reason() {
    let err = H2Error::StreamReset(Reason::CANCEL);
    let s = format!("{err}");
    // Must contain some identifier for the reset
    assert!(s.contains("reset") || s.contains("CANCEL") || s.contains("H2"));
}
