//! CAR v1: the file a repository travels in.
//!
//! A length-prefixed dag-cbor header naming the root, then every block as its
//! CID followed by its bytes. Nothing indexes it, so a reader learns what it
//! has only by reading all of it.

use ipld_core::cid::Cid;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{BlockMap, Error, Store};

/// sha2-256, the only multihash a block here may use.
const SHA2_256: u64 = 0x12;

#[derive(Debug, Deserialize, Serialize)]
struct Header {
    version: u64,
    roots: Vec<Cid>,
}

/// Writes every block under one root.
///
/// # Errors
///
/// If the header will not encode.
pub fn write(root: Cid, blocks: &BlockMap) -> Result<Vec<u8>, Error> {
    let header = super::encode(&Header {
        version: 1,
        roots: vec![root],
    })?;
    let mut car = Vec::new();
    push_varint(&mut car, header.len() as u64);
    car.extend_from_slice(&header);
    for (cid, bytes) in blocks {
        let cid = cid.to_bytes();
        push_varint(&mut car, (cid.len() + bytes.len()) as u64);
        car.extend_from_slice(&cid);
        car.extend_from_slice(bytes);
    }
    Ok(car)
}

/// Reads a file back, checking that every block hashes to the CID it arrived
/// under.
///
/// # Errors
///
/// If the file is truncated or malformed, names other than one root, or holds
/// a block that is not what its CID says.
pub fn read(car: &[u8]) -> Result<(Cid, BlockMap), Error> {
    let (header, mut rest) = take_chunk(car)?;
    let header: Header = super::decode(header)?;
    if header.version != 1 {
        return Err(Error::MalformedCar("not a version 1 file"));
    }
    let [root] = header.roots[..] else {
        return Err(Error::MalformedCar("not exactly one root"));
    };

    let mut blocks = BlockMap::new();
    while !rest.is_empty() {
        let (chunk, next) = take_chunk(rest)?;
        rest = next;
        let mut reading = chunk;
        let cid = Cid::read_bytes(&mut reading)
            .map_err(|_| Error::MalformedCar("a block under something that is not a CID"))?;
        if !hashes_to(&cid, reading) {
            return Err(Error::WrongCid(cid));
        }
        blocks.insert(cid, reading.to_vec());
    }

    if !blocks.contains(&root)? {
        return Err(Error::MissingBlock(root));
    }
    Ok((root, blocks))
}

/// Splits off one length-prefixed chunk, and what follows it.
fn take_chunk(bytes: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    let (len, rest) = unsigned_varint::decode::u64(bytes)
        .map_err(|_| Error::MalformedCar("a length that is not a varint"))?;
    let len = usize::try_from(len).map_err(|_| Error::MalformedCar("a length past the file"))?;
    rest.split_at_checked(len)
        .ok_or(Error::MalformedCar("a length past the file"))
}

fn hashes_to(cid: &Cid, bytes: &[u8]) -> bool {
    cid.hash().code() == SHA2_256 && cid.hash().digest() == Sha256::digest(bytes).as_slice()
}

fn push_varint(out: &mut Vec<u8>, value: u64) {
    let mut buffer = unsigned_varint::encode::u64_buffer();
    out.extend_from_slice(unsigned_varint::encode::u64(value, &mut buffer));
}
