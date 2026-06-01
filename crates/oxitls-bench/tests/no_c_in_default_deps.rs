//! Tripwire test: ring and aws-lc-rs must NOT appear in the normal
//! (non-dev) dependency closure of `oxitls-bench`.
//!
//! This test is `#[ignore]` so it is skipped during regular `cargo test` runs.
//! Run it explicitly in CI with:
//!
//!   cargo test -p oxitls-bench -- --ignored no_c_in_default_deps
//!
//! If either crate appears in the normal edge, you accidentally added a
//! non-dev dependency on a C/FFI crate and violated the Pure-Rust policy.

#[test]
#[ignore = "run manually: cargo test -p oxitls-bench -- --ignored no_c_in_default_deps"]
fn no_c_in_default_deps() {
    // Resolve `CARGO_MANIFEST_DIR` to the workspace root.
    // `env!("CARGO_MANIFEST_DIR")` during test compilation is the crate root
    // (`crates/oxitls-bench`); the workspace root is two levels up.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace_root = std::path::Path::new(manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root from CARGO_MANIFEST_DIR");

    let output = std::process::Command::new("cargo")
        .args(["tree", "--edges", "normal", "-p", "oxitls-bench"])
        .current_dir(workspace_root)
        .output()
        .expect("failed to run `cargo tree`");

    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        !stdout.contains("ring v"),
        "ring found in normal deps — it must stay in dev-dependencies only.\n\
         Run `cargo tree -e normal -p oxitls-bench | grep ring` to investigate.\n\n\
         Output:\n{stdout}"
    );
    assert!(
        !stdout.contains("aws-lc-rs v"),
        "aws-lc-rs found in normal deps — it must stay in dev-dependencies only.\n\
         Run `cargo tree -e normal -p oxitls-bench | grep aws-lc-rs` to investigate.\n\n\
         Output:\n{stdout}"
    );
}
