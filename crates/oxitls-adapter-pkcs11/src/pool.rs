// SPDX-License-Identifier: Apache-2.0
// Copyright COOLJAPAN OU (Team Kitasan)
//! PKCS#11 session pool for efficient session reuse.
//!
//! This module is only compiled when the `pkcs11` feature is active.

use std::collections::VecDeque;
use std::num::NonZeroUsize;
use std::sync::Arc;

use cryptoki::context::Pkcs11;
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;

use parking_lot::Mutex;
use secrecy::{ExposeSecret, SecretString};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::error::Pkcs11Error;

/// A pool of pre-logged-in PKCS#11 sessions.
///
/// Sessions are pre-opened and logged in at construction time.  Callers
/// acquire a session via [`Pkcs11SessionPool::acquire`], which returns a
/// [`PooledSession`].  The session is returned to the pool automatically when
/// the [`PooledSession`] is dropped.
///
/// Acquisition is synchronous and uses a `try_acquire_owned()` call so that
/// it can be called from non-async code (e.g. the rustls `Signer::sign`
/// callback).  If no session is available, [`Pkcs11Error::SessionPoolExhausted`]
/// is returned immediately without blocking.
#[derive(Debug)]
pub struct Pkcs11SessionPool {
    sessions: Mutex<VecDeque<Session>>,
    semaphore: Arc<Semaphore>,
}

impl Pkcs11SessionPool {
    /// Create a new session pool.
    ///
    /// Opens `capacity` read-only sessions on `slot`, each logged in with
    /// `pin` as `USER`.  All sessions are created eagerly at construction
    /// time.
    ///
    /// # Errors
    ///
    /// Returns [`Pkcs11Error::SessionError`] if any session cannot be opened
    /// or the login fails.
    pub fn new(
        module: Arc<Pkcs11>,
        slot: Slot,
        pin: SecretString,
        capacity: NonZeroUsize,
    ) -> Result<Self, Pkcs11Error> {
        let cap = capacity.get();
        let mut sessions = VecDeque::with_capacity(cap);

        for _ in 0..cap {
            let session = module
                .open_ro_session(slot)
                .map_err(|e| Pkcs11Error::SessionError(e.to_string()))?;

            let auth_pin = AuthPin::new(pin.expose_secret().to_string().into_boxed_str());
            session
                .login(UserType::User, Some(&auth_pin))
                .map_err(|e| Pkcs11Error::SessionError(format!("login failed: {e}")))?;

            sessions.push_back(session);
        }

        Ok(Self {
            sessions: Mutex::new(sessions),
            semaphore: Arc::new(Semaphore::new(cap)),
        })
    }

    /// Acquire a session from the pool.
    ///
    /// This is a non-blocking call.  If no session is available, returns
    /// [`Pkcs11Error::SessionPoolExhausted`] immediately.
    ///
    /// The returned [`PooledSession`] returns the session to the pool
    /// automatically when dropped.
    pub fn acquire(&self) -> Result<PooledSession<'_>, Pkcs11Error> {
        let permit = Arc::clone(&self.semaphore)
            .try_acquire_owned()
            .map_err(|_| Pkcs11Error::SessionPoolExhausted)?;

        let session = {
            let mut guard = self.sessions.lock();
            guard.pop_front().ok_or(Pkcs11Error::SessionPoolExhausted)?
        };

        Ok(PooledSession {
            session: Some(session),
            pool: self,
            _permit: permit,
        })
    }
}

/// A borrowed PKCS#11 session.
///
/// The session is returned to the pool when this guard is dropped.
pub struct PooledSession<'a> {
    session: Option<Session>,
    pool: &'a Pkcs11SessionPool,
    _permit: OwnedSemaphorePermit,
}

impl<'a> PooledSession<'a> {
    /// Access the underlying [`Session`].
    pub fn session(&self) -> &Session {
        // Safety: `session` is always `Some` until `Drop` runs.
        self.session
            .as_ref()
            .expect("PooledSession: session taken before drop")
    }
}

impl<'a> Drop for PooledSession<'a> {
    fn drop(&mut self) {
        if let Some(session) = self.session.take() {
            let mut guard = self.pool.sessions.lock();
            guard.push_back(session);
        }
        // `_permit` is dropped after `session` is returned, releasing the
        // semaphore permit so the next waiter can proceed.
    }
}

impl<'a> std::fmt::Debug for PooledSession<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PooledSession")
            .field("session", &self.session.is_some())
            .finish()
    }
}
