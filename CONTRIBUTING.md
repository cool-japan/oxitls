# Contributing to OxiTLS

Thank you for your interest in contributing. OxiTLS is part of the
**COOLJAPAN ecosystem** (https://github.com/cool-japan/oxitls), a
family of Pure Rust libraries that replace common C/C++/Fortran-backed
crates with FFI-free implementations — in this case, a Pure Rust TLS
stack built on `rustls` with a RustCrypto crypto provider.

## Building and testing

```bash
# Build the workspace
cargo build --workspace

# Run the test suite (nextest is required; do not rely on `cargo test` alone)
cargo nextest run --workspace

# Lint — this MUST produce zero warnings before a change is accepted
cargo clippy --all-targets -- -D warnings

# Format
cargo fmt --all
```

## Project rules

These rules are enforced in review and, where possible, in CI:

- **Pure Rust by default.** No new C/C++/Fortran dependency, and no
  non-default C feature, may be added without an explicit, documented
  exception. The `oxitls-adapter-aws-lc`, `oxitls-adapter-pkcs11`, and
  `oxitls-native-certs` crates are the sanctioned, opt-in FFI
  boundaries; the rest of the workspace stays 100% Pure Rust.
- **No panics on untrusted input.** Do not add `.unwrap()`, `.expect()`,
  `panic!()`, `unreachable!()`, or `assert!()` on data derived from
  untrusted input (certificates, OCSP/SCT staples, handshake messages,
  etc.) outside of test code; return the crate's existing typed error
  instead. A panic on attacker-controlled input during a TLS handshake
  is a denial-of-service vector.
- **Zero clippy warnings.** `cargo clippy --all-targets -- -D warnings`
  must pass cleanly with default features.
- **Workspace dependency inheritance.** Shared dependencies are
  declared once in the workspace `[workspace.dependencies]` table and
  pulled in via `dep.workspace = true`; do not pin ad hoc versions in a
  member crate's `Cargo.toml` when the workspace already centralizes
  that dependency. A small number of crypto primitives (e.g. `sha2`)
  are documented exceptions where multiple majors must coexist across
  crates — see the comments in the root `Cargo.toml` before adding
  another one.
- **File size.** Keep individual source files under 2000 lines; split
  oversized files into focused modules.
- **Latest crates.** Prefer the latest versions available on crates.io
  for new or updated dependencies.
- **No hardcoded absolute paths.** Tests must use
  `std::env::temp_dir()` (or an equivalent relative/portable path) for
  any temporary file handling.

## Submitting changes

Open a pull request against the appropriate version branch (not
directly against a release branch, unless the project is pre-0.1.0).
Describe what changed and why, and make sure the build/test/lint
commands above all pass locally first. Changes to certificate
validation, OCSP/CRL/SCT handling, or other security-relevant paths
should include regression tests that demonstrate the specific attack
or bypass being closed.
