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
}

mod block;

pub use block::{BlockMap, Store, cid_for, decode, encode, read};
