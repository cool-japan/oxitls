//! FIPS mode introspection for the aws-lc-rs backend.
//!
//! All items in this module are gated on `#[cfg(feature = "aws-lc")]`.

/// Returns `true` when the underlying aws-lc-rs library was compiled with the
/// `fips` feature **and** the FIPS module has been successfully initialised.
///
/// Under a standard (non-FIPS) build of aws-lc-rs this always returns `false`.
///
/// # Example
/// ```no_run
/// # #[cfg(feature = "aws-lc")]
/// # {
/// use oxitls_adapter_aws_lc::is_fips_mode;
///
/// // Value depends on how aws-lc-rs was compiled.
/// let _: bool = is_fips_mode();
/// # }
/// ```
#[cfg(feature = "aws-lc")]
pub fn is_fips_mode() -> bool {
    // `try_fips_mode` is always available in aws-lc-rs >= 1.x (not gated by
    // the `fips` feature on the aws-lc-rs side). It returns `Ok(())` when the
    // underlying AWS-LC library has FIPS mode active, `Err` otherwise.
    aws_lc_rs::try_fips_mode().is_ok()
}
