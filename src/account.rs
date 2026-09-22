//! Accounts: what signing up writes, and what signing in has to check.
//!
//! Everything here is reachable without a socket, so the handlers above it do
//! nothing but read a request and name an error.

pub mod handle;
pub mod password;

use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use jiff::{SignedDuration, Timestamp};

use crate::store;
use crate::syntax::{AtIdentifier, Did};
use crate::xrpc::auth::{REFRESH_LIFETIME, Scope, Tokens};

/// How long a refresh token that has been exchanged stays usable, so that a
/// client that never received the answer can ask again.
const GRACE: SignedDuration = SignedDuration::from_hours(2);

/// How long signing in takes, whatever the answer.
///
/// The hashing is only done for an identifier that exists, so without a fixed
/// budget the time taken says whether it does — and an email address is not
/// something this server confirms any other way.
const LOGIN: Duration = Duration::from_millis(350);

/// What went wrong signing in.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// No account answers to that, or the password is not its password. One
    /// error for both, because saying which is the whole of what an attacker
    /// wanted.
    #[error("Invalid identifier or password")]
    Credentials,
    /// Storage would not answer.
    #[error("{0}")]
    Storage(#[from] store::Error),
}

/// Who signed in, and what with.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Login {
    /// The account the identifier named.
    pub account: store::Account,
    /// The app password it was opened with, if a password was not.
    pub app_password: Option<store::AppPassword>,
}

/// The pair of tokens a session is held open by.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Credentials {
    /// Spent on every other method, and short-lived.
    pub access: String,
    /// Exchanged for the next pair, and nothing else.
    pub refresh: String,
}

/// The accounts on this server, and the sessions open against them.
#[derive(Debug)]
pub struct Manager {
    accounts: Mutex<store::Accounts>,
    tokens: Tokens,
}

impl Manager {
    /// Holds an open account database and the secret sessions are signed
    /// under.
    #[must_use]
    pub fn new(accounts: store::Accounts, tokens: Tokens) -> Self {
        Self {
            accounts: Mutex::new(accounts),
            tokens,
        }
    }

    /// The account a DID names.
    ///
    /// # Errors
    ///
    /// If storage will not answer.
    pub fn account(&self, did: &Did) -> Result<Option<store::Account>, Error> {
        Ok(self.locked().by_did(did)?)
    }

    /// Checks an identifier and a password, taking the same time whichever
    /// way it goes.
    ///
    /// # Errors
    ///
    /// If nothing answers to the identifier, the password is neither the
    /// account's nor one of its app passwords, or storage will not answer.
    pub async fn login(&self, identifier: &str, password: &str) -> Result<Login, Error> {
        let started = Instant::now();
        let outcome = self.check(identifier, password);
        let taken = started.elapsed();
        tokio::time::sleep(remaining(taken)).await;
        outcome
    }

    /// Opens a session, writing down the refresh token that will close it.
    ///
    /// # Errors
    ///
    /// If the write fails.
    pub fn open_session(
        &self,
        did: &Did,
        app_password: Option<&store::AppPassword>,
    ) -> Result<Credentials, Error> {
        let id = token_id();
        let session = store::Session {
            id: id.clone(),
            did: did.clone(),
            expires_at: Timestamp::now() + REFRESH_LIFETIME,
            next_id: None,
            app_password: app_password.cloned(),
        };
        self.locked().store_session(&session)?;
        Ok(self.mint(did, app_password, &id))
    }

    /// Exchanges a refresh token for the next pair, or nothing if the session
    /// has been revoked or has run out.
    ///
    /// A client that retries is handed the same successor rather than a second
    /// session: the row names what replaces it before the replacement is
    /// written, so both attempts arrive at one answer.
    ///
    /// # Errors
    ///
    /// If storage will not answer.
    pub fn refresh_session(&self, id: &str) -> Result<Option<Credentials>, Error> {
        loop {
            let accounts = self.locked();
            let Some(session) = accounts.session(id)? else {
                return Ok(None);
            };

            // Housekeeping, and best-effort: an expired token is refused
            // whether or not its row was still there to delete.
            let now = Timestamp::now();
            accounts.expire_sessions(&session.did, now)?;

            // The token keeps whichever of its own expiry and the grace period
            // comes first, so exchanging one never lengthens it.
            let expires_at = session.expires_at.min(now + GRACE);
            if expires_at <= now {
                return Ok(None);
            }

            let next = session.next_id.clone().unwrap_or_else(token_id);
            if !accounts.hold_session(id, expires_at, &next)? {
                // Another exchange named a different successor. Its row says
                // which, so read it again rather than guessing.
                drop(accounts);
                continue;
            }
            accounts.store_session(&store::Session {
                id: next.clone(),
                did: session.did.clone(),
                expires_at: now + REFRESH_LIFETIME,
                next_id: None,
                app_password: session.app_password.clone(),
            })?;
            drop(accounts);

            return Ok(Some(self.mint(
                &session.did,
                session.app_password.as_ref(),
                &next,
            )));
        }
    }

    /// Ends a session, whether or not its token had already run out.
    ///
    /// # Errors
    ///
    /// If the write fails.
    pub fn revoke_session(&self, id: &str) -> Result<bool, Error> {
        Ok(self.locked().revoke_session(id)?)
    }

    /// Ends every session an account holds.
    ///
    /// # Errors
    ///
    /// If the write fails.
    pub fn revoke_sessions(&self, did: &Did) -> Result<usize, Error> {
        Ok(self.locked().revoke_sessions(did)?)
    }

    /// The account and app password a password proves, without the padding
    /// that makes the answer take the same time either way.
    fn check(&self, identifier: &str, password: &str) -> Result<Login, Error> {
        let identifier = identifier.to_ascii_lowercase();
        let accounts = self.locked();
        let account = if identifier.contains('@') {
            accounts.by_email(&identifier)?
        } else {
            match identifier.parse::<AtIdentifier>() {
                Ok(AtIdentifier::Did(did)) => accounts.by_did(&did)?,
                Ok(AtIdentifier::Handle(handle)) => accounts.by_handle(&handle)?,
                Err(_) => None,
            }
        };
        let account = account.ok_or(Error::Credentials)?;

        if password::verify(password, &account.password_scrypt) {
            return Ok(Login {
                account,
                app_password: None,
            });
        }
        // App passwords are salted with the account, so the hash is the lookup
        // rather than something to compare a row against.
        let app_password = accounts
            .app_password(&account.did, &password::app(&account.did, password))?
            .ok_or(Error::Credentials)?;
        Ok(Login {
            account,
            app_password: Some(app_password),
        })
    }

    /// The pair a session hands back, under the scope its password reaches.
    fn mint(&self, did: &Did, app_password: Option<&store::AppPassword>, id: &str) -> Credentials {
        let scope = match app_password {
            None => Scope::Access,
            Some(password) if password.privileged => Scope::PrivilegedAppPassword,
            Some(_) => Scope::AppPassword,
        };
        Credentials {
            access: self.tokens.access(did, scope),
            refresh: self.tokens.refresh(did, id),
        }
    }

    /// The account database. A poisoned lock is a panic somewhere else, and
    /// the rows it was holding are as good as they ever were.
    fn locked(&self) -> std::sync::MutexGuard<'_, store::Accounts> {
        self.accounts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// How much longer work of this length waits before answering.
///
/// The budget is rounded up to a whole one rather than held to a floor: work
/// slower than a budget waits for the next, where a floor would stop hiding
/// anything at exactly the point the server is loaded enough to be measured.
fn remaining(taken: Duration) -> Duration {
    let whole = u32::try_from(taken.as_nanos() / LOGIN.as_nanos() + 1).unwrap_or(u32::MAX);
    LOGIN
        .checked_mul(whole)
        .unwrap_or(taken)
        .saturating_sub(taken)
}

/// A refresh token's `jti`, which is also the row the session is kept under.
fn token_id() -> String {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    BASE64.encode(bytes)
}
