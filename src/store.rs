//! Storage: the data directory and the SQLite files under it.
//!
//! The layout is the reference implementation's, down to the file names and
//! the migration ledger, so that stopping that server and starting this one on
//! the same directory is all a takeover takes. See `docs/roadmap.md` for what
//! that constraint buys.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::crypto::PublicKey;
use crate::syntax::Did;

/// What went wrong reading or writing storage.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// SQLite refused, or the file underneath it did.
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// A directory could not be made or read.
    #[error("{0}")]
    Io(#[from] std::io::Error),
    /// A database holding something no schema this server knows would write.
    #[error("{0}")]
    Malformed(&'static str),
    /// A database migrated past what this server can read.
    #[error("schema is at {0}, which is newer than this server")]
    TooNew(String),
    /// An invite code that cannot be spent, refused inside the write that
    /// would have spent it.
    #[error("invite code is not available")]
    InviteUnavailable,
    /// A handle somebody else holds, refused the same way. The unique index is
    /// what settles a race the read before it cannot.
    #[error("handle is already taken")]
    HandleTaken,
    /// An email somebody else holds, refused by the index that pairs with it.
    #[error("email is already taken")]
    EmailTaken,
    /// An app password name the account already uses, refused by the key that
    /// pairs the two.
    #[error("app password name is already taken")]
    AppPasswordTaken,
    /// A record naming a blob nothing uploaded.
    #[error("Could not find blob: {0}")]
    BlobMissing(ipld_core::cid::Cid),
    /// A record naming a blob as something other than what was uploaded.
    #[error("Referenced {0} does not match stored blob. Expected: {1}, Got: {2}")]
    BlobMismatch(&'static str, String, String),
    /// A blob whose bytes are not what its CID says.
    #[error("{0} is not the CID of the bytes under it")]
    WrongCid(ipld_core::cid::Cid),
    /// A key file holding something that is not a key.
    #[error("signing key: {0}")]
    Key(#[from] crate::crypto::Error),
}

impl Error {
    /// Whether waiting and asking again is what would help.
    #[must_use]
    pub fn busy(&self) -> bool {
        matches!(self, Self::Sqlite(error) if matches!(
            error.sqlite_error_code(),
            Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
        ))
    }
}

mod accounts;
mod actor;
pub mod blobs;
mod db;
mod did_cache;
pub mod keys;
mod sequencer;

pub use accounts::{Account, Accounts, AppPassword, Cursor, Hosted, Registration, Session};
pub use actor::{
    Actor, Backlink, Blob, Blocks, Committed, Indexed, Mark, MissingBlob, Page, Record, Root,
};
pub use blobs::Blobs;
pub use did_cache::{Cached, DidCache};
pub use sequencer::{Entry, Event, Sequencer};

/// Milliseconds and a `Z`, which is what the other server writes and what
/// makes a text column sort as time. Every time these databases hold.
#[must_use]
pub fn stamp(at: jiff::Timestamp) -> String {
    format!("{at:.3}")
}

/// Makes a directory nobody else can look into, which is what everything
/// holding an account's data wants to be.
fn directory(path: &Path) -> Result<(), std::io::Error> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}

/// The data directory, and where each thing under it lives.
#[derive(Clone, Debug)]
pub struct Directory(PathBuf);

impl Directory {
    /// Names a directory without touching it.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self(path.into())
    }

    /// Accounts, handles, passwords, tokens and invite codes.
    #[must_use]
    pub fn accounts(&self) -> PathBuf {
        self.0.join("account.sqlite")
    }

    /// The outgoing event log.
    #[must_use]
    pub fn sequencer(&self) -> PathBuf {
        self.0.join("sequencer.sqlite")
    }

    /// The file a running server holds; `docs/architecture.md` has what one
    /// left behind means.
    #[must_use]
    pub fn running(&self) -> PathBuf {
        self.0.join("running")
    }

    /// Resolved DID documents, held so the directory is not asked twice.
    #[must_use]
    pub fn did_cache(&self) -> PathBuf {
        self.0.join("did_cache.sqlite")
    }

    /// Everything belonging to an account rather than to the server.
    fn actors(&self) -> PathBuf {
        self.0.join("actors")
    }

    /// One account's directory, under a shard so that no directory holds every
    /// account at once.
    #[must_use]
    pub fn actor(&self, did: &Did) -> PathBuf {
        let hash = Sha256::digest(did.as_str().as_bytes());
        self.actors()
            .join(format!("{:02x}", hash[0]))
            .join(did.as_str())
    }

    /// One account's repository, records, blobs and preferences.
    #[must_use]
    pub fn actor_store(&self, did: &Did) -> PathBuf {
        self.actor(did).join("store.sqlite")
    }

    /// One account's signing key, as raw bytes.
    #[must_use]
    pub fn actor_key(&self, did: &Did) -> PathBuf {
        self.actor(did).join("key")
    }

    /// The operation that minted an account's identifier, in the encoding the
    /// identifier is the hash of.
    #[must_use]
    pub fn actor_op(&self, did: &Did) -> PathBuf {
        self.actor(did).join("did-op")
    }

    /// A signing key under its own identifier, held there while no account
    /// names it yet.
    #[must_use]
    pub fn reserved_key(&self, key: &PublicKey) -> PathBuf {
        self.actors().join("reserved_keys").join(key.to_string())
    }

    /// Every account's blobs. Named for the blocks it does not hold, because
    /// that is what the deployment scripts already set.
    #[must_use]
    pub fn blobs(&self) -> Blobs {
        Blobs::new(self.0.join("blocks"))
    }
}

impl AsRef<Path> for Directory {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

/// A server's hold on a data directory, taken at start and given up on the
/// way out.
#[derive(Debug)]
pub struct Running(PathBuf);

impl Running {
    /// Takes the marker, saying whether one was already there — which is a
    /// server that never got to let go of it.
    ///
    /// # Errors
    ///
    /// If the data directory cannot be made or written to.
    pub fn take(directory: &Directory) -> Result<(Self, bool), Error> {
        self::directory(&directory.0)?;
        let path = directory.running();
        let held = path.try_exists()?;
        // The pid, for whoever finds one left behind.
        std::fs::write(&path, std::process::id().to_string())?;
        Ok((Self(path), held))
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        drop(std::fs::remove_file(&self.0));
    }
}

/// Every row the planner answers with for a query, which is where a sort it
/// had to put in for itself is named.
#[cfg(test)]
pub(crate) fn plan(db: &rusqlite::Connection, query: &str) -> String {
    let mut statement = db
        .prepare(&format!("explain query plan {query}"))
        .expect("prepares");
    let binds: Vec<String> = (0..statement.parameter_count())
        .map(|_| String::new())
        .collect();
    statement
        .query_map(rusqlite::params_from_iter(&binds), |row| {
            row.get::<_, String>(3)
        })
        .expect("a plan")
        .collect::<rusqlite::Result<Vec<_>>>()
        .expect("rows of a plan")
        .join("; ")
}
