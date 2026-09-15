//! Repositories: the signed, content-addressed tree an account's records live
//! in.
//!
//! Every block is dag-cbor under the CID of its own bytes, so two servers
//! holding the same records agree on every hash up to the root. See
//! `docs/repo.md` for why that structure is the protocol rather than a
//! storage choice.

pub use ipld_core::cid::Cid;

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
}

mod block;
pub mod car;
mod commit;
mod mst;

pub use block::{BlockMap, Store, cid_for, decode, encode, read};
pub use commit::{Commit, VERSION};
pub use mst::{Leaf, Mst};
