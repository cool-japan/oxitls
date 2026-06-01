//! Purity tripwire: verifies that the default (no-feature) `oxitls` closure
//! does **not** contain aws-lc.
//!
//! If this test fails it means some dependency path has leaked aws-lc into the
//! `oxitls` default feature set, breaking the Pure Rust guarantee.

#[test]
fn oxitls_default_closure_pure() {
    // Walk up two levels: crates/oxitls-adapter-aws-lc → crates/ → workspace root.
    let ws_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("parent of crates/oxitls-adapter-aws-lc should be crates/")
        .parent()
        .expect("parent of crates/ should be workspace root");

    let output = std::process::Command::new("cargo")
        .args(["tree", "-p", "oxitls", "--edges", "normal"])
        .current_dir(ws_root)
        .output()
        .expect("cargo tree failed — is cargo in PATH?");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("aws-lc"),
        "aws-lc leaked into the oxitls default closure:\n{stdout}"
    );
}
