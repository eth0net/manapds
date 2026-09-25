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
    /// A blob whose bytes are not what its CID says.
    #[error("{0} is not the CID of the bytes under it")]
    WrongCid(ipld_core::cid::Cid),
    /// A key file holding something that is not a key.
    #[error("signing key: {0}")]
    Key(#[from] crate::crypto::Error),
}

mod accounts;
mod actor;
pub mod blobs;
mod db;
mod did_cache;
pub mod keys;
mod sequencer;

pub use accounts::{Account, Accounts, AppPassword, Registration, Session};
pub use actor::{Actor, Root};
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
