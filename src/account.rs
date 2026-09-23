//! Accounts: what signing up writes, and what signing in has to check.
//!
//! Everything here is reachable without a socket, so the handlers above it do
//! nothing but read a request and name an error.

pub mod email;
pub mod handle;
pub mod password;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD as BASE64};
use jiff::{SignedDuration, Timestamp};

use crate::config::Config;
use crate::crypto::{self, Algorithm, Keypair, PublicKey};
use crate::event;
use crate::repo::{Cid, Repo};
use crate::store;
use crate::syntax::{AtIdentifier, Did, Handle, Tid, TidClock};
use crate::xrpc::auth::{REFRESH_LIFETIME, Scope, Tokens};
use crate::{plc, repo};

/// How long a refresh token that has been exchanged stays usable, so that a
/// client that never received the answer can ask again.
const GRACE: SignedDuration = SignedDuration::from_hours(2);

/// How long signing in takes, whatever the answer.
///
/// An email is worth hiding here because a server that asks for an invite does
/// not hand one over anywhere else: signing up says an address is taken, but
/// only to somebody holding a code. This budget, the equal work beneath it,
/// and that code are one defense, and it is worth what the weakest of them is.
const LOGIN: Duration = Duration::from_millis(350);

/// Who a code the server itself hands out belongs to, which is nobody.
const ADMINISTRATOR: &str = "admin";

/// The longest password a new account may choose. Anything above it is a
/// client sending something that is not a password.
const PASSWORD: usize = 256;

/// The longest password any account ever chose, which is what signing in is
/// held to: a longer one matches nothing this server could be holding.
const STORED_PASSWORD: usize = 512;

/// What went wrong signing in.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// No account answers to that, or the password is not its password. One
    /// error for both, because saying which is the whole of what an attacker
    /// wanted.
    #[error("Invalid identifier or password")]
    Credentials,
    /// A handle this server will not hand out.
    #[error("{0}")]
    Handle(#[from] handle::Invalid),
    /// An address nothing could be sent to.
    #[error("This email address is not supported, please use a different email.")]
    Email,
    /// A password longer than anything anyone types.
    #[error("Password too long. Maximum length is {PASSWORD} characters.")]
    PasswordTooLong,
    /// A handle or an email somebody else already holds.
    #[error("{0} already taken")]
    Taken(&'static str),
    /// A server that only takes invited accounts, asked without one.
    #[error("No invite code provided")]
    InviteRequired,
    /// A code that is not one, has been spent, or has been disabled.
    #[error("This invite code is not available")]
    Invite,
    /// The directory would not register the identifier.
    #[error("{0}")]
    Plc(#[from] plc::Error),
    /// The repository would not be built.
    #[error("{0}")]
    Repo(#[from] repo::Error),
    /// Storage would not answer.
    #[error("{0}")]
    Storage(store::Error),
}

impl From<store::Error> for Error {
    /// Three of these are a race the check before the write lost, and the
    /// caller is owed the same answer it would have had by arriving second.
    fn from(error: store::Error) -> Self {
        match error {
            store::Error::InviteUnavailable => Self::Invite,
            store::Error::HandleTaken => Self::Taken("Handle"),
            store::Error::EmailTaken => Self::Taken("Email"),
            other => Self::Storage(other),
        }
    }
}

impl Error {
    /// The name its lexicon gives the failure, which is what a client branches
    /// on.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            // A name held back is `HandleNotAvailable`; one somebody already
            // holds is not, on this method. Changing a handle draws the line
            // in the other place, which is the reference's own split.
            Self::Handle(invalid) => invalid.name(),
            Self::InviteRequired | Self::Invite => "InvalidInviteCode",
            Self::Credentials => "AuthenticationRequired",
            Self::Plc(_) | Self::Repo(_) | Self::Storage(_) => "InternalServerError",
            Self::Email | Self::PasswordTooLong | Self::Taken(_) => "InvalidRequest",
        }
    }
}

/// What a signup asks for.
#[derive(Clone, Debug)]
pub struct Signup {
    /// The name it wants, which has to be one this server hands out.
    pub handle: String,
    /// Where password resets and confirmations will go.
    pub email: String,
    /// What it will sign in with.
    pub password: String,
    /// The code it came in on, where the server asks for one.
    pub invite: Option<String>,
    /// A key that outranks this server's, so the account can be taken back.
    pub recovery_key: Option<PublicKey>,
}

/// An account, the moment it exists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Created {
    /// The identifier the genesis operation minted.
    pub did: Did,
    /// The name it answers to.
    pub handle: Handle,
    /// The session it is handed back, so signing up and signing in are one
    /// call.
    pub credentials: Credentials,
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
    config: Arc<Config>,
    login: Duration,
    directory: store::Directory,
    accounts: Mutex<store::Accounts>,
    hashing: Arc<tokio::sync::Semaphore>,
    sequencer: Mutex<store::Sequencer>,
    clock: Mutex<TidClock>,
    plc: plc::Client,
    rules: handle::Rules,
    tokens: Tokens,
}

impl Manager {
    /// Holds an open account database and event log, the directory the rest of
    /// the data sits in, and the secret sessions are signed under.
    #[must_use]
    pub fn new(
        config: Arc<Config>,
        accounts: store::Accounts,
        sequencer: store::Sequencer,
        tokens: Tokens,
    ) -> Self {
        Self {
            directory: store::Directory::new(config.data_directory.clone()),
            plc: plc::Client::new(config.plc_url.clone()),
            rules: handle::Rules::new(&config.handle_domains, &config.reserved_handles),
            accounts: Mutex::new(accounts),
            hashing: Arc::new(tokio::sync::Semaphore::new(hashes_at_once())),
            sequencer: Mutex::new(sequencer),
            clock: Mutex::new(TidClock::new()),
            login: LOGIN,
            tokens,
            config,
        }
    }

    /// Answers a sign-in in this long rather than the usual, which is what a
    /// test wants and nothing else does: the delay is there to hide something
    /// a test has no reason to hide.
    #[must_use]
    pub fn answering_in(mut self, budget: Duration) -> Self {
        self.login = budget;
        self
    }

    /// The rules this server hands handles out under.
    #[must_use]
    pub fn rules(&self) -> &handle::Rules {
        &self.rules
    }

    /// Creates an account: an identifier, a key, a repository with nothing in
    /// it, and a session to go on with.
    ///
    /// The directory is told last bar the log entries; `docs/architecture.md`
    /// has what that order buys and what it does not.
    ///
    /// # Errors
    ///
    /// If the handle, email, password or invite will not do, either is already
    /// held, or storage or the directory will not answer.
    pub async fn create(&self, signup: &Signup) -> Result<Created, Error> {
        if signup.password.chars().count() > PASSWORD {
            return Err(Error::PasswordTooLong);
        }
        if self.config.invite_required && signup.invite.is_none() {
            return Err(Error::InviteRequired);
        }
        if !email::plausible(&signup.email) {
            return Err(Error::Email);
        }
        let handle = self.rules.signup(&signup.handle)?;
        self.available(&handle, signup)?;

        let signing_key = Keypair::generate(Algorithm::Secp256k1);
        // The account's own key first, then the server operator's: the
        // directory settles a fork in favor of the earlier one.
        let recovery: Vec<PublicKey> = [signup.recovery_key, self.config.recovery_key]
            .into_iter()
            .flatten()
            .collect();
        let operation = plc::Operation::create(
            &handle,
            &self.config.public_url(),
            &signing_key.public_key(),
            &recovery,
            &self.config.plc_rotation_key,
        )?;
        let did = operation.did()?;

        // Armed for the whole of `settle`: a dropped request leaves it by a
        // path that returning an error never passes through.
        let mut undo = Undo {
            manager: self,
            did: Some(did.clone()),
        };
        let (credentials, blocks, commit, rev) = self
            .settle(&did, &handle, signup, &signing_key, &operation)
            .await?;
        // Past undoing: the directory has taken the identifier, so anything
        // that fails from here is worth a log line and not worth deleting an
        // account the rest of the network can already see.
        undo.done();

        // todo: nothing tries this again, so a consumer never learns about an
        // account whose entries were refused.
        if let Err(error) = self.log(&did, &handle, commit, &rev, &blocks) {
            tracing::error!(%did, %error, "an account was created and not logged");
        }

        Ok(Created {
            did,
            handle,
            credentials,
        })
    }

    /// Everything after the identifier is known, under the rollback the caller
    /// arms around it.
    async fn settle(
        &self,
        did: &Did,
        handle: &Handle,
        signup: &Signup,
        signing_key: &Keypair,
        operation: &plc::Operation,
    ) -> Result<(Credentials, repo::BlockMap, Cid, Tid), Error> {
        let (root, blocks) = self.start_repo(did, signing_key)?;
        let (commit, rev) = (root.cid, root.rev.clone());

        // Hashed before the lock is taken, and not only by preference: a guard
        // cannot be held across the await this now is.
        let password_scrypt = self.hashing(&signup.password, password::hash).await;
        let id = token_id();
        self.locked().create(&store::Registration {
            account: store::Account {
                did: did.clone(),
                handle: Some(handle.clone()),
                email: signup.email.clone(),
                password_scrypt,
            },
            root,
            invite: signup.invite.clone(),
            session: Some(store::Session {
                id: id.clone(),
                did: did.clone(),
                expires_at: Timestamp::now() + REFRESH_LIFETIME,
                next_id: None,
                app_password: None,
            }),
        })?;

        self.plc.send(did, operation).await?;
        Ok((self.mint(did, None, &id), blocks, commit, rev))
    }

    /// Puts a new account in the log.
    ///
    /// Separate from the writes that make it, because it happens after the
    /// point those can be taken back.
    fn log(
        &self,
        did: &Did,
        handle: &Handle,
        commit: Cid,
        rev: &Tid,
        blocks: &repo::BlockMap,
    ) -> Result<(), Error> {
        let entries = event::account_created(did, handle, commit, rev, blocks)?;
        self.sequencer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend(
                did,
                entries
                    .iter()
                    .map(|entry| (entry.event, entry.bytes.as_slice())),
            )?;
        Ok(())
    }

    /// Writes the account's key and its first commit.
    // todo: this makes a file, migrates it and signs a commit on the thread
    // answering the request, which is the shape `docs/architecture.md` rules
    // out. It is milliseconds where the hashing was tenths, so it waits.
    fn start_repo(
        &self,
        did: &Did,
        signing_key: &Keypair,
    ) -> Result<(store::Root, repo::BlockMap), Error> {
        store::keys::write(&self.directory.actor_key(did), signing_key)?;
        let mut actor = store::Actor::open(&self.directory.actor_store(did), did.clone())?;
        let (repo, blocks) = Repo::create(
            did.clone(),
            signing_key,
            &mut self
                .clock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )?;
        let root = store::Root {
            cid: repo.cid(),
            rev: repo.rev().clone(),
        };
        actor.commit(&root, &blocks)?;
        Ok((root, blocks))
    }

    /// Whether the code, the handle and the email are all still free.
    fn available(&self, handle: &Handle, signup: &Signup) -> Result<(), Error> {
        let accounts = self.locked();
        if let Some(code) = &signup.invite
            && !accounts.invite_available(code)?
        {
            return Err(Error::Invite);
        }
        if accounts.by_handle(handle)?.is_some() {
            return Err(Error::Taken("Handle"));
        }
        if accounts.by_email(&signup.email)?.is_some() {
            return Err(Error::Taken("Email"));
        }
        Ok(())
    }

    /// Takes a half-finished signup back out, best effort: what is left behind
    /// is worth a log line and never worth failing a second attempt.
    fn discard(&self, did: &Did) {
        if let Err(error) = self.locked().delete(did) {
            tracing::error!(%did, %error, "could not undo a failed signup");
        }
        if let Err(error) = std::fs::remove_dir_all(self.directory.actor(did))
            && error.kind() != std::io::ErrorKind::NotFound
        {
            tracing::error!(%did, %error, "could not remove a failed signup's directory");
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

    /// The account a handle names, whatever case it is asked in.
    ///
    /// # Errors
    ///
    /// If storage will not answer.
    pub fn resolve(&self, handle: &Handle) -> Result<Option<Did>, Error> {
        Ok(self.locked().by_handle(handle)?.map(|account| account.did))
    }

    /// Writes fresh invite codes for an account, and says what they are.
    ///
    /// # Errors
    ///
    /// If the write fails.
    pub fn mint_invites(
        &self,
        for_account: &str,
        count: u32,
        uses: u32,
    ) -> Result<Vec<String>, Error> {
        let codes: Vec<String> = (0..count).map(|_| self.invite_code()).collect();
        self.locked()
            .create_invites(&codes, for_account, ADMINISTRATOR, uses)?;
        Ok(codes)
    }

    /// `<hostname>-xxxxx-xxxxx`, with the dots in the hostname written as
    /// dashes, which is the shape the reference writes.
    fn invite_code(&self) -> String {
        let mut bytes = [0u8; 8];
        rand::fill(&mut bytes);
        let token = crypto::base32(&bytes);
        format!(
            "{}-{}-{}",
            self.config.hostname.replace('.', "-"),
            &token[..5],
            &token[5..10]
        )
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
        let outcome = self.check(identifier, password).await;
        let taken = started.elapsed();
        tokio::time::sleep(remaining(self.login, taken)).await;
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
    /// session: the row names what replaces it in the same write that creates
    /// it, so both attempts arrive at one answer.
    ///
    /// # Errors
    ///
    /// If storage will not answer.
    pub fn refresh_session(&self, id: &str) -> Result<Option<Credentials>, Error> {
        loop {
            let mut accounts = self.locked();
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

            let next = store::Session {
                id: session.next_id.clone().unwrap_or_else(token_id),
                did: session.did.clone(),
                expires_at: now + REFRESH_LIFETIME,
                next_id: None,
                app_password: session.app_password.clone(),
            };
            if !accounts.rotate(id, expires_at, &next)? {
                // Another exchange named a different successor. Its row says
                // which, so read it again rather than guessing.
                drop(accounts);
                continue;
            }
            drop(accounts);
            let next = next.id;

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
    async fn check(&self, identifier: &str, password: &str) -> Result<Login, Error> {
        // Refused as a wrong password rather than by length, and refused here
        // rather than at the handler so that it costs the same as any other
        // wrong one.
        if password.chars().count() > STORED_PASSWORD {
            return Err(Error::Credentials);
        }
        let identifier = identifier.to_ascii_lowercase();
        // Scoped so that the hashing below, which is the expensive half, is not
        // done holding the database every other request is waiting for.
        let account = {
            let accounts = self.locked();
            if identifier.contains('@') {
                accounts.by_email(&identifier)?
            } else {
                match identifier.parse::<AtIdentifier>() {
                    Ok(AtIdentifier::Did(did)) => accounts.by_did(&did)?,
                    Ok(AtIdentifier::Handle(handle)) => accounts.by_handle(&handle)?,
                    Err(_) => None,
                }
            }
        };
        let Some(account) = account else {
            // Twice, because that is what a wrong password costs: the row is
            // checked, then the app passwords are looked up by hash. An
            // identifier nobody holds has to spend the same to say nothing.
            //
            // Skipped along with the budget, since a server told not to hide
            // which identifiers exist has nothing to buy with the work.
            if !self.login.is_zero() {
                self.hashing(password, password::nobody).await;
                self.hashing(password, password::nobody).await;
            }
            return Err(Error::Credentials);
        };

        let stored = account.password_scrypt.clone();
        if self
            .hashing(password, move |offered| password::verify(offered, &stored))
            .await
        {
            return Ok(Login {
                account,
                app_password: None,
            });
        }
        // App passwords are salted with the account, so the hash is the lookup
        // rather than something to compare a row against.
        let did = account.did.clone();
        let offered = self
            .hashing(password, move |password| password::app(&did, password))
            .await;
        let app_password = self
            .locked()
            .app_password(&account.did, &offered)?
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

    /// Runs one scrypt on a thread that is allowed to block, waiting for a turn
    /// if enough are already running.
    async fn hashing<T: Send + 'static>(
        &self,
        password: &str,
        work: impl FnOnce(&str) -> T + Send + 'static,
    ) -> T {
        let turn = Arc::clone(&self.hashing)
            .acquire_owned()
            .await
            .expect("the semaphore is never closed");
        let password = password.to_owned();
        // The turn is given up by the work rather than by whoever is waiting on
        // it: a caller that hangs up cannot cancel a blocking task, so handing
        // it back any earlier would let the count run past the bound.
        tokio::task::spawn_blocking(move || {
            let hashed = work(&password);
            drop(turn);
            hashed
        })
        .await
        .expect("the hashing thread")
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
fn remaining(budget: Duration, taken: Duration) -> Duration {
    if budget.is_zero() {
        return Duration::ZERO;
    }
    let whole = u32::try_from(taken.as_nanos() / budget.as_nanos() + 1).unwrap_or(u32::MAX);
    budget
        .checked_mul(whole)
        .unwrap_or(taken)
        .saturating_sub(taken)
}

/// Takes a half-written signup back out unless it is told the signup finished.
///
/// Dropping covers the paths a `match` on the result does not: an early return
/// added later, a panic, and a request the caller abandoned.
struct Undo<'a> {
    manager: &'a Manager,
    did: Option<Did>,
}

impl Undo<'_> {
    /// Stands the rollback down.
    fn done(&mut self) {
        self.did = None;
    }
}

impl Drop for Undo<'_> {
    fn drop(&mut self) {
        if let Some(did) = &self.did {
            self.manager.discard(did);
        }
    }
}

/// How many passwords may be hashed at once.
///
/// Each one holds 16MB for as long as it runs and a blocking task goes to a
/// pool 512 deep, so without a bound a burst of sign-ins is a memory limit
/// rather than a processor one.
fn hashes_at_once() -> usize {
    std::thread::available_parallelism().map_or(4, std::num::NonZeroUsize::get)
}

/// A refresh token's `jti`, which is also the row the session is kept under.
///
/// Unpadded, because the reference spells it through a multibase alphabet that
/// has no padding, and both servers read the same table.
fn token_id() -> String {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    BASE64.encode(bytes)
}
