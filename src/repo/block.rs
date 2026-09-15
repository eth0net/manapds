//! Blocks: dag-cbor bytes and the CID that addresses them.

use std::collections::BTreeMap;

use ipld_core::cid::{Cid, multihash::Multihash};
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

use super::Error;

/// dag-cbor, in the multicodec table.
const DAG_CBOR: u64 = 0x71;

/// sha2-256, in the multihash table.
const SHA2_256: u64 = 0x12;

/// The CID for a block: v1, dag-cbor, sha-256.
#[must_use]
#[expect(clippy::missing_panics_doc, reason = "a sha-256 digest is 32 bytes")]
pub fn cid_for(bytes: &[u8]) -> Cid {
    let digest = Sha256::digest(bytes);
    let hash = Multihash::wrap(SHA2_256, &digest).expect("a 32-byte digest fits");
    Cid::new_v1(DAG_CBOR, hash)
}

/// Encodes a value the one way dag-cbor allows, so its CID is a function of
/// the value alone.
///
/// # Errors
///
/// If the value has no dag-cbor form, which a map with non-string keys or a
/// float that is not finite does not.
pub fn encode<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, Error> {
    serde_ipld_dagcbor::to_vec(value).map_err(|e| Error::Encode(e.to_string()))
}

/// Reads bytes back as a value.
///
/// # Errors
///
/// If the bytes are not dag-cbor, or not the shape asked for.
pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, Error> {
    serde_ipld_dagcbor::from_slice(bytes).map_err(|e| Error::Decode(e.to_string()))
}

/// Somewhere blocks are read from by CID.
pub trait Store {
    /// The bytes stored under a CID.
    ///
    /// # Errors
    ///
    /// If nothing is stored there, or the store cannot be reached.
    fn get(&self, cid: &Cid) -> Result<Vec<u8>, Error>;

    /// Whether a block is already stored, which decides if writing it again
    /// would be wasted.
    ///
    /// # Errors
    ///
    /// If the store cannot be reached.
    fn contains(&self, cid: &Cid) -> Result<bool, Error>;
}

/// Reads one block and decodes it.
///
/// # Errors
///
/// If the block is missing, or holds something else.
pub fn read<S: Store + ?Sized, T: DeserializeOwned>(store: &S, cid: &Cid) -> Result<T, Error> {
    decode(&store.get(cid)?)
}

/// Blocks held in memory, which is what a write produces before it is stored
/// and what a CAR file arrives as.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BlockMap(BTreeMap<Cid, Vec<u8>>);

impl BlockMap {
    /// An empty map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Stores bytes under a CID, without checking that the CID is theirs.
    pub fn insert(&mut self, cid: Cid, bytes: Vec<u8>) {
        self.0.insert(cid, bytes);
    }

    /// Encodes a value, stores it, and hands back where it went.
    ///
    /// # Errors
    ///
    /// If the value will not encode.
    pub fn add<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<Cid, Error> {
        let bytes = encode(value)?;
        let cid = cid_for(&bytes);
        self.insert(cid, bytes);
        Ok(cid)
    }

    /// Takes in every block of another map.
    pub fn merge(&mut self, other: Self) {
        self.0.extend(other.0);
    }

    /// How many blocks are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether no blocks are held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Every block, in CID order.
    pub fn iter(&self) -> impl Iterator<Item = (&Cid, &[u8])> {
        self.0.iter().map(|(cid, bytes)| (cid, bytes.as_slice()))
    }
}

impl Store for BlockMap {
    fn get(&self, cid: &Cid) -> Result<Vec<u8>, Error> {
        self.0.get(cid).cloned().ok_or(Error::MissingBlock(*cid))
    }

    fn contains(&self, cid: &Cid) -> Result<bool, Error> {
        Ok(self.0.contains_key(cid))
    }
}

impl<'a> IntoIterator for &'a BlockMap {
    type Item = (&'a Cid, &'a [u8]);
    type IntoIter = Box<dyn Iterator<Item = Self::Item> + 'a>;

    fn into_iter(self) -> Self::IntoIter {
        Box::new(self.iter())
    }
}
