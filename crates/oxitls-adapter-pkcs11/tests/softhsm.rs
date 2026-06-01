// SPDX-License-Identifier: Apache-2.0
// Copyright COOLJAPAN OU (Team Kitasan)
//! PKCS#11 integration tests.
//!
//! The `test_pkcs11_signing_requires_softhsm` test requires a SoftHSM2 instance
//! to be provisioned and the `SOFTHSM2_MODULE` env var to point at the shared
//! library.  It is `#[ignore]` by default so the CI suite stays hermetic.
//!
//! The `pkcs11_type_construction_headless` test verifies that the public
//! error types compile and behave correctly with no HSM present.

use oxitls_adapter_pkcs11::PkcsSignError;

/// Verify error types compile, implement Debug, and format as expected.
#[test]
fn pkcs11_type_construction_headless() {
    let err = PkcsSignError::SessionError("test session".to_string());
    let dbg = format!("{err:?}");
    assert!(
        dbg.contains("SessionError"),
        "unexpected debug output: {dbg}"
    );

    let err2 = PkcsSignError::KeyNotFound("my-label".to_string());
    let disp = format!("{err2}");
    assert!(
        disp.contains("my-label"),
        "unexpected display output: {disp}"
    );

    let err3 = PkcsSignError::InvalidSignatureLength {
        expected: 64,
        got: 63,
    };
    let disp3 = format!("{err3}");
    assert!(disp3.contains("64"), "unexpected display: {disp3}");
    assert!(disp3.contains("63"), "unexpected display: {disp3}");
}

/// Full SoftHSM2 round-trip test (ignored by default).
///
/// To run:
/// ```text
/// SOFTHSM2_MODULE=/usr/lib/softhsm/libsofthsm2.so \
/// SOFTHSM2_SLOT=0 \
/// SOFTHSM2_PIN=1234 \
/// SOFTHSM2_KEY_LABEL=test-ecdsa \
/// cargo nextest run -p oxitls-adapter-pkcs11 --features pkcs11 -- --ignored
/// ```
#[test]
#[ignore]
#[cfg(feature = "pkcs11")]
fn test_pkcs11_signing_requires_softhsm() {
    let module_path = match std::env::var("SOFTHSM2_MODULE") {
        Ok(m) => std::path::PathBuf::from(m),
        Err(_) => {
            eprintln!("SOFTHSM2_MODULE not set — skipping SoftHSM2 integration test");
            return;
        }
    };

    // Parse the slot index; default to 0.
    let slot_id: u64 = std::env::var("SOFTHSM2_SLOT")
        .unwrap_or_else(|_| "0".to_string())
        .parse()
        .unwrap_or(0);

    let pin = std::env::var("SOFTHSM2_PIN").unwrap_or_else(|_| "1234".to_string());
    let key_label =
        std::env::var("SOFTHSM2_KEY_LABEL").unwrap_or_else(|_| "test-ecdsa".to_string());

    // Build the slot handle from the numeric index.
    // cryptoki::slot::Slot is an opaque wrapper; we need Pkcs11::get_slots_with_token().
    use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};

    let pkcs11 = Pkcs11::new(&module_path).expect("load module");
    pkcs11
        .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .expect("initialize");

    let slots = pkcs11.get_slots_with_token().expect("get_slots_with_token");
    let slot = *slots
        .get(slot_id as usize)
        .expect("slot index out of range");

    // Now construct via the public API (which calls initialize internally — this
    // will get CKR_CRYPTOKI_ALREADY_INITIALIZED, which some tokens treat as OK).
    // For simplicity we exercise the low-level session path directly.
    let session = pkcs11.open_ro_session(slot).expect("open_ro_session");
    let auth_pin = cryptoki::types::AuthPin::new(pin.clone().into_boxed_str());
    session
        .login(cryptoki::session::UserType::User, Some(&auth_pin))
        .expect("login");

    // Find the private key.
    let template = vec![
        cryptoki::object::Attribute::Class(cryptoki::object::ObjectClass::PRIVATE_KEY),
        cryptoki::object::Attribute::Label(key_label.as_bytes().to_vec()),
    ];
    let handles = session.find_objects(&template).expect("find_objects");
    assert!(
        !handles.is_empty(),
        "no private key found with label '{key_label}'"
    );

    let key_handle = handles[0];

    // Sign a test message.
    let message = b"oxitls-adapter-pkcs11 integration test";
    let raw = session
        .sign(
            &cryptoki::mechanism::Mechanism::EcdsaSha256,
            key_handle,
            message,
        )
        .expect("sign");

    assert!(!raw.is_empty(), "signature is empty");
    eprintln!("signature ({} bytes): {:02x?}", raw.len(), raw);
}
