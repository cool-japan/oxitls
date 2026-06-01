// SPDX-License-Identifier: Apache-2.0
// Copyright COOLJAPAN OU (Team Kitasan)
//! PKCS#11 session management helpers.
//!
//! This module is only compiled when the `pkcs11` feature is active.

use cryptoki::context::Pkcs11;
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;

use crate::error::PkcsSignError;

/// Open a read-only PKCS#11 session on the given slot and log in as a User.
pub(crate) fn open_user_session(
    pkcs11: &Pkcs11,
    slot: Slot,
    pin: &str,
) -> Result<Session, PkcsSignError> {
    let session = pkcs11
        .open_ro_session(slot)
        .map_err(|e| PkcsSignError::SessionError(e.to_string()))?;

    let auth_pin = AuthPin::new(pin.to_string().into_boxed_str());
    session
        .login(UserType::User, Some(&auth_pin))
        .map_err(|e| PkcsSignError::SessionError(format!("login failed: {e}")))?;

    Ok(session)
}

/// Find a private key object by CKA_LABEL in an open session.
///
/// Returns the first matching private key handle.
pub(crate) fn find_private_key_by_label(
    session: &Session,
    label: &str,
) -> Result<ObjectHandle, PkcsSignError> {
    let template = vec![
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::Label(label.as_bytes().to_vec()),
    ];

    let handles = session
        .find_objects(&template)
        .map_err(|e| PkcsSignError::KeyNotFound(format!("find_objects failed: {e}")))?;

    handles
        .into_iter()
        .next()
        .ok_or_else(|| PkcsSignError::KeyNotFound(label.to_string()))
}

/// Probe the key type of a private key object.
///
/// Returns `Some(KeyType::EC)`, `Some(KeyType::RSA)`, etc.
pub(crate) fn probe_key_type(
    session: &Session,
    handle: ObjectHandle,
) -> Result<KeyType, PkcsSignError> {
    let attrs = session
        .get_attributes(handle, &[AttributeType::KeyType])
        .map_err(|e| PkcsSignError::SessionError(format!("get_attributes failed: {e}")))?;

    for attr in attrs {
        if let Attribute::KeyType(kt) = attr {
            return Ok(kt);
        }
    }

    Err(PkcsSignError::SessionError(
        "CKA_KEY_TYPE attribute not found on private key".to_string(),
    ))
}
