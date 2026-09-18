//! Repositories: the signed, content-addressed tree an account's records live
//! in, and the writes that move one revision to the next.
//!
//! Every block is dag-cbor under the CID of its own bytes, so two servers
//! holding the same records agree on every hash up to the root. See
//! `docs/repo.md` for why that structure is the protocol rather than a
//! storage choice.

use crate::crypto::{Keypair, PublicKey};
use crate::syntax::{Did, Nsid, RecordKey, Tid, TidClock};

pub use ipld_core::{cid::Cid, ipld::Ipld};

/// What went wrong reading or building a repository.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum Error {
    /// A block the tree points at is not in the store it was given.
    #[error("no block for {0}")]
    MissingBlock(Cid),
    /// A value would not encode as dag-cbor.
    #[error("will not encode as dag-cbor: {0}")]
    Encode(String),
    /// Stored bytes are not the shape they were read as.
    #[error("not the dag-cbor expected: {0}")]
    Decode(String),
    /// A key that is not one collection and one record key.
    #[error("not a valid tree key: {0}")]
    InvalidKey(String),
    /// A write that would land on a key already holding something.
    #[error("already a record at {0}")]
    KeyExists(String),
    /// A write or read against a key the tree does not hold.
    #[error("no record at {0}")]
    KeyMissing(String),
    /// A stored node that no sequence of writes could have produced.
    #[error("malformed node: {0}")]
    MalformedNode(&'static str),
    /// A commit at a version this server does not read.
    #[error("commit is version {0}, not 3")]
    WrongVersion(u8),
    /// A commit the key offered did not sign.
    #[error("commit signature: {0}")]
    Signature(#[from] crate::crypto::Error),
    /// A CAR file that does not parse as one.
    #[error("malformed CAR: {0}")]
    MalformedCar(&'static str),
    /// A block that is not what the CID over it says it is.
    #[error("{0} is not the CID of the bytes under it")]
    WrongCid(Cid),
    /// Whatever the blocks are kept in would not answer.
    #[error("store: {0}")]
    Store(String),
    /// The same, but waiting is what would help.
    #[error("store is busy")]
    StoreBusy,
    /// A revision with nothing above it left in the field.
    #[error("no revision follows {0}")]
    NoRevisionAfter(Tid),
}

mod block;
pub mod car;
mod commit;
mod mst;

pub use block::{BlockMap, Store, cid_for, decode, encode, read};
pub use commit::{Commit, VERSION};
pub use mst::{Leaf, Mst};

/// One record operation, to be applied with others under a single commit.
#[derive(Clone, Debug)]
pub enum Write {
    /// Writes a record to a key nothing holds.
    Create {
        /// The collection it belongs to.
        collection: Nsid,
        /// Its key within that collection.
        rkey: RecordKey,
        /// The record itself.
        record: Ipld,
    },
    /// Replaces the record at a key.
    Update {
        /// The collection it belongs to.
        collection: Nsid,
        /// Its key within that collection.
        rkey: RecordKey,
        /// What to put there instead.
        record: Ipld,
    },
    /// Takes the record at a key out.
    Delete {
        /// The collection it belonged to.
        collection: Nsid,
        /// Its key within that collection.
        rkey: RecordKey,
    },
}

impl Write {
    /// Where in the tree this operation lands.
    #[must_use]
    pub fn key(&self) -> String {
        let (Self::Create {
            collection, rkey, ..
        }
        | Self::Update {
            collection, rkey, ..
        }
        | Self::Delete { collection, rkey }) = self;
        format!("{collection}/{rkey}")
    }
}

/// An account's repository at one revision.
///
/// Holding one says nothing about what is stored: every method that reaches
/// past the root takes the store to read from, and a write hands back the
/// blocks the caller has to put somewhere for the next read to work.
#[derive(Clone, Debug)]
pub struct Repo {
    cid: Cid,
    commit: Commit,
    data: Mst,
}

impl Repo {
    /// Signs the first commit, over a tree with nothing in it.
    ///
    /// # Errors
    ///
    /// If the empty tree will not encode, which it always does.
    pub fn create(
        did: Did,
        keypair: &Keypair,
        clock: &mut TidClock,
    ) -> Result<(Self, BlockMap), Error> {
        let mut data = Mst::empty();
        let (root, mut blocks) = data.unstored_blocks(&BlockMap::new())?;
        let commit = Commit::sign(did, clock.mint(), root, keypair)?;
        let cid = blocks.add(&commit)?;
        Ok((Self { cid, commit, data }, blocks))
    }

    /// Reads a repository from the commit a root names.
    ///
    /// # Errors
    ///
    /// If the commit block is missing or is not a commit.
    pub fn load(store: &dyn Store, cid: Cid) -> Result<Self, Error> {
        let commit: Commit = read(store, &cid)?;
        let data = Mst::load(commit.data);
        Ok(Self { cid, commit, data })
    }

    /// Applies writes and signs the commit over what they leave, handing back
    /// every block that has to be stored before this revision can be read.
    ///
    /// Nothing changes here unless all of it does: a write that fails leaves
    /// the repository on the revision it was already on.
    ///
    /// # Errors
    ///
    /// If a key is taken, missing, or not a record path, or a block the tree
    /// reaches for is not in the store.
    pub fn apply(
        &mut self,
        store: &dyn Store,
        writes: &[Write],
        keypair: &Keypair,
        clock: &mut TidClock,
    ) -> Result<BlockMap, Error> {
        let mut blocks = BlockMap::new();
        let mut data = self.data.clone();
        for write in writes {
            let key = write.key();
            data = match write {
                Write::Create { record, .. } => data.add(store, &key, blocks.add(record)?)?,
                Write::Update { record, .. } => data.update(store, &key, blocks.add(record)?)?,
                Write::Delete { .. } => data.delete(store, &key)?,
            };
        }

        // todo: the CIDs this revision drops, so stale blocks can be collected.
        let (root, tree) = data.unstored_blocks(store)?;
        blocks.merge(tree);
        let commit = Commit::sign(
            self.commit.did.clone(),
            clock
                .mint_after(&self.commit.rev)
                .ok_or_else(|| Error::NoRevisionAfter(self.commit.rev.clone()))?,
            root,
            keypair,
        )?;

        self.cid = blocks.add(&commit)?;
        self.commit = commit;
        self.data = data;
        Ok(blocks)
    }

    /// The block this repository's commit is in, which is its root.
    #[must_use]
    pub fn cid(&self) -> Cid {
        self.cid
    }

    /// The commit itself.
    #[must_use]
    pub fn commit(&self) -> &Commit {
        &self.commit
    }

    /// Whose repository this is.
    #[must_use]
    pub fn did(&self) -> &Did {
        &self.commit.did
    }

    /// Which revision it is on.
    #[must_use]
    pub fn rev(&self) -> &Tid {
        &self.commit.rev
    }

    /// Where a record is, if the repository holds one there.
    ///
    /// # Errors
    ///
    /// If a block the tree reaches for is not in the store.
    pub fn get(
        &mut self,
        store: &dyn Store,
        collection: &Nsid,
        rkey: &RecordKey,
    ) -> Result<Option<Cid>, Error> {
        self.data.get(store, &format!("{collection}/{rkey}"))
    }

    /// Every record in the repository, in key order.
    ///
    /// # Errors
    ///
    /// If a block the tree reaches for is not in the store.
    pub fn records(&mut self, store: &dyn Store) -> Result<Vec<Leaf>, Error> {
        self.data.leaves(store)
    }

    /// Checks the commit against a key the account's DID document names.
    ///
    /// # Errors
    ///
    /// If the commit is another version, or that key did not sign it.
    pub fn verify(&self, key: &PublicKey) -> Result<(), Error> {
        self.commit.verify(key)
    }
}
