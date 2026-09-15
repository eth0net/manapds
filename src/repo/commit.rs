//! Commits: a tree root, signed by the account it belongs to.

use ipld_core::cid::Cid;
use serde::{Deserialize, Serialize};

use crate::crypto::{Keypair, PublicKey};
use crate::syntax::{Did, Tid};

use super::{Error, encode};

/// The only commit version this server writes or trusts.
pub const VERSION: u8 = 3;

/// A repository at one moment: whose it is, what it holds, and proof the
/// account's signing key agreed to it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Commit {
    /// The account whose repository this is.
    pub did: Did,
    /// Always [`VERSION`].
    pub version: u8,
    /// The root of the record tree.
    pub data: Cid,
    /// Which revision this is, and the order consumers put commits in.
    pub rev: Tid,
    /// Null in everything written since v2, and kept only because the field
    /// is part of the shape a signature covers.
    pub prev: Option<Cid>,
    /// 64 bytes over the dag-cbor of every field above.
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
}

/// What the signature is taken over: the commit without it.
#[derive(Debug, Serialize)]
struct Unsigned<'a> {
    did: &'a Did,
    version: u8,
    data: Cid,
    rev: &'a Tid,
    prev: Option<Cid>,
}

impl Commit {
    /// Signs a tree root into a commit.
    ///
    /// # Errors
    ///
    /// If the fields will not encode, which nothing here can arrange.
    pub fn sign(did: Did, rev: Tid, data: Cid, key: &Keypair) -> Result<Self, Error> {
        let unsigned = Unsigned {
            did: &did,
            version: VERSION,
            data,
            rev: &rev,
            prev: None,
        };
        let sig = key.sign(&encode(&unsigned)?).to_vec();
        Ok(Self {
            did,
            version: VERSION,
            data,
            rev,
            prev: None,
            sig,
        })
    }

    /// Checks the signature against a key, which is only worth anything if the
    /// key came from the DID document this commit names.
    ///
    /// # Errors
    ///
    /// If the commit is another version, or the signature is not this key's
    /// over these fields.
    pub fn verify(&self, key: &PublicKey) -> Result<(), Error> {
        if self.version != VERSION {
            return Err(Error::WrongVersion(self.version));
        }
        let unsigned = Unsigned {
            did: &self.did,
            version: self.version,
            data: self.data,
            rev: &self.rev,
            prev: self.prev,
        };
        key.verify(&encode(&unsigned)?, &self.sig)?;
        Ok(())
    }
}
