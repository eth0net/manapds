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
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Algorithm;
    use crate::repo::tests::record;
    use crate::repo::{BlockMap, Store as _, cid_for, decode};
    use crate::syntax::TidClock;

    #[test]
    fn a_commit_verifies_against_the_key_that_signed_it() {
        let key = Keypair::generate(Algorithm::Secp256k1);
        let did: Did = "did:plc:4cjoyc3cgpal7gnrpzyjhnv3".parse().expect("a DID");
        let commit = Commit::sign(did, TidClock::new().mint(), record(), &key).expect("signs");

        assert_eq!(commit.version, VERSION);
        assert_eq!(commit.prev, None);
        assert_eq!(commit.sig.len(), 64);
        assert_eq!(commit.verify(&key.public_key()), Ok(()));

        let elsewhere = Keypair::generate(Algorithm::Secp256k1);
        assert!(commit.verify(&elsewhere.public_key()).is_err());

        let mut moved = commit.clone();
        moved.data = cid_for(b"\xa0");
        assert!(moved.verify(&key.public_key()).is_err());

        let mut aged = commit;
        aged.version = 2;
        assert_eq!(aged.verify(&key.public_key()), Err(Error::WrongVersion(2)));
    }

    #[test]
    fn a_commit_round_trips_through_a_block() {
        let key = Keypair::generate(Algorithm::Secp256k1);
        let did: Did = "did:plc:4cjoyc3cgpal7gnrpzyjhnv3".parse().expect("a DID");
        let commit = Commit::sign(did, TidClock::new().mint(), record(), &key).expect("signs");

        let mut blocks = BlockMap::new();
        let cid = blocks.add(&commit).expect("encodes");
        let read: Commit = decode(&blocks.get(&cid).expect("stored")).expect("decodes");

        assert_eq!(read, commit);
        assert_eq!(read.verify(&key.public_key()), Ok(()));
        // Six keys, shortest first, so the signature covers a known byte order.
        assert!(
            encode(&commit)
                .expect("encodes")
                .starts_with(b"\xa6\x63did")
        );
    }

    /// A commit block built by the reference's own encoder, so that this server's
    /// idea of the wire format is checked against something other than itself.
    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Golden {
        did: String,
        rev: String,
        data: String,
        signing_key: String,
        unsigned: String,
        block: String,
        cid: String,
    }

    #[test]
    fn a_commit_is_the_bytes_the_reference_would_have_written() {
        let golden: Golden =
            serde_json::from_str(include_str!("../../fixtures/commit/golden.json"))
                .expect("the fixture");
        let block = hex::decode(&golden.block).expect("hex");
        let keypair = Keypair::from_bytes(
            Algorithm::Secp256k1,
            &hex::decode("9085d2bef69286a6cbb51623c8fa258629945cd55ca705cc4e66700396894e0c")
                .expect("hex"),
        )
        .expect("a key");
        assert_eq!(keypair.public_key().to_string(), golden.signing_key);

        // Signing is deterministic on both sides, so the whole block matches and
        // not merely its shape.
        let commit = Commit::sign(
            golden.did.parse().expect("a DID"),
            golden.rev.parse().expect("a TID"),
            golden.data.parse().expect("a CID"),
            &keypair,
        )
        .expect("signs");
        assert_eq!(hex::encode(encode(&commit).expect("encodes")), golden.block);
        assert_eq!(cid_for(&block).to_string(), golden.cid);

        // And what the reference wrote is read back as the same commit.
        let read: Commit = decode(&block).expect("decodes");
        assert_eq!(read, commit);
        assert_eq!(read.version, VERSION);
        assert!(read.prev.is_none());
        read.verify(&keypair.public_key())
            .expect("the key signed it");

        // The signature covers the commit without its signature, which is the one
        // thing a reader cannot check by re-encoding what it was given.
        assert!(golden.unsigned.len() < golden.block.len());
    }
}
