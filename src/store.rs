//! Storage: the data directory and the SQLite files under it.
//!
//! The layout is the reference implementation's, down to the file names and
//! the migration ledger, so that stopping that server and starting this one on
//! the same directory is all a takeover takes. See `docs/roadmap.md` for what
//! that constraint buys.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

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
}

mod actor;
mod db;
mod sequencer;

pub use actor::{Actor, Root};
pub use sequencer::{Entry, Event, Sequencer};

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

    /// Resolved DID documents, held so the directory is not asked twice.
    #[must_use]
    pub fn did_cache(&self) -> PathBuf {
        self.0.join("did_cache.sqlite")
    }

    /// One account's directory, under a shard so that no directory holds every
    /// account at once.
    #[must_use]
    pub fn actor(&self, did: &Did) -> PathBuf {
        let hash = Sha256::digest(did.as_str().as_bytes());
        self.0
            .join("actors")
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
}

impl AsRef<Path> for Directory {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}
