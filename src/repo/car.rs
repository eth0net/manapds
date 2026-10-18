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
    rooted(vec![root], blocks)
}

/// Writes every block under no root, which is what a file carrying a slice of
/// a repository rather than a whole one names.
///
/// # Errors
///
/// If the header will not encode.
pub fn write_blocks(blocks: &BlockMap) -> Result<Vec<u8>, Error> {
    rooted(Vec::new(), blocks)
}

/// What a file opens with, naming the roots the blocks after it add up to.
///
/// # Errors
///
/// If the header will not encode.
pub fn header(roots: Vec<Cid>) -> Result<Vec<u8>, Error> {
    let header = super::encode(&Header { version: 1, roots })?;
    let mut car = Vec::new();
    push_varint(&mut car, header.len() as u64);
    car.extend_from_slice(&header);
    Ok(car)
}

/// Writes one block onto the end of a file.
pub fn push(car: &mut Vec<u8>, cid: &Cid, bytes: &[u8]) {
    let cid = cid.to_bytes();
    push_varint(car, (cid.len() + bytes.len()) as u64);
    car.extend_from_slice(&cid);
    car.extend_from_slice(bytes);
}

fn rooted(roots: Vec<Cid>, blocks: &BlockMap) -> Result<Vec<u8>, Error> {
    let mut car = header(roots)?;
    for (cid, bytes) in blocks {
        push(&mut car, cid, bytes);
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
    let (roots, blocks) = read_roots(car)?;
    let [root] = roots[..] else {
        return Err(Error::MalformedCar("not exactly one root"));
    };
    if !blocks.contains(&root)? {
        return Err(Error::MissingBlock(root));
    }
    Ok((root, blocks))
}

/// The blocks in a file, whatever it names as its roots and whether or not it
/// names any.
///
/// # Errors
///
/// If the file is truncated or malformed, or holds a block that is not what
/// its CID says.
pub fn read_blocks(car: &[u8]) -> Result<BlockMap, Error> {
    Ok(read_roots(car)?.1)
}

fn read_roots(car: &[u8]) -> Result<(Vec<Cid>, BlockMap), Error> {
    let (header, mut rest) = take_chunk(car)?;
    let header: Header = super::decode(header)?;
    if header.version != 1 {
        return Err(Error::MalformedCar("not a version 1 file"));
    }

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
    Ok((header.roots, blocks))
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

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use base64::Engine as _;

    use super::*;
    use crate::repo::cid_for;

    #[derive(Deserialize)]
    struct Fixture {
        root: String,
        blocks: Vec<Block>,
        car: String,
    }

    #[derive(Deserialize)]
    struct Block {
        cid: String,
        bytes: String,
    }

    #[test]
    fn reads_what_the_reference_wrote() {
        for fixture in fixtures() {
            let (root, blocks) = read(&base64(&fixture.car)).expect("reads");
            assert_eq!(root.to_string(), fixture.root);
            assert_eq!(blocks.len(), fixture.blocks.len());
            for block in &fixture.blocks {
                let cid: Cid = block.cid.parse().expect("a CID");
                assert_eq!(
                    blocks.get(&cid).as_deref(),
                    Ok(base64(&block.bytes).as_slice())
                );
            }
        }
    }

    #[test]
    fn writes_a_file_the_same_size_with_the_same_header() {
        for fixture in fixtures() {
            let reference = base64(&fixture.car);
            let (root, blocks) = read(&reference).expect("reads");
            let written = write(root, &blocks).expect("writes");

            // Which order blocks come in is the writer's to choose, so the header
            // is what has to match byte for byte and the rest has to survive a
            // round trip.
            let header = 1 + usize::from(reference[0]);
            assert_eq!(&written[..header], &reference[..header]);
            assert_eq!(written.len(), reference.len());
            assert_eq!(read(&written), Ok((root, blocks)));
        }
    }

    #[test]
    fn a_block_under_the_wrong_cid_is_refused() {
        let cid = cid_for(b"\xa0");
        let mut blocks = BlockMap::new();
        blocks.insert(cid, b"\xa1\x61a\x01".to_vec());
        let car = write(cid, &blocks).expect("writes");

        assert_eq!(read(&car), Err(Error::WrongCid(cid)));
    }

    #[test]
    fn a_truncated_file_is_refused() {
        let car = base64(&fixtures()[0].car);
        let cut = &car[..car.len() - 1];

        assert!(matches!(read(cut), Err(Error::MalformedCar(_))));
    }

    fn fixtures() -> Vec<Fixture> {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/car/car-file-fixtures.json");
        let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        serde_json::from_str(&text).expect("fixtures")
    }

    fn base64(input: &str) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(input)
            .expect("base64")
    }

    use crate::crypto::{Algorithm, Keypair};
    use crate::repo::car;
    use crate::repo::fixture::{account, collection, post, rkey};
    use crate::repo::{Ipld, Repo, Write, decode};
    use crate::syntax::TidClock;

    #[test]
    fn a_repository_survives_the_round_trip_through_a_car() {
        let key = Keypair::generate(Algorithm::Secp256k1);
        let mut clock = TidClock::new();
        let (mut repo, mut store) = Repo::create(account(), &key, &mut clock).expect("creates");

        assert_eq!(repo.verify(&key.public_key()), Ok(()));
        assert_eq!(repo.records(&store), Ok(Vec::new()));
        let first = repo.rev().clone();

        let writes = vec![
            Write::Create {
                collection: collection(),
                rkey: rkey("3jqfcqzm4fc2j"),
                record: post("first"),
            },
            Write::Create {
                collection: collection(),
                rkey: rkey("3jqfcqzm4fd2j"),
                record: post("second"),
            },
        ];
        let (written, _) = repo
            .apply(&store, &writes, &key, &mut clock)
            .expect("applies");
        store.merge(written);

        assert!(repo.rev() > &first, "{} follows {first}", repo.rev());
        assert_eq!(repo.records(&store).expect("reads").len(), 2);
        assert_eq!(repo.verify(&key.public_key()), Ok(()));

        let car = car::write(repo.cid(), &store).expect("writes");
        let (root, blocks) = car::read(&car).expect("reads");
        let mut reloaded = Repo::load(&blocks, root).expect("loads");

        assert_eq!(reloaded.cid(), repo.cid());
        assert_eq!(reloaded.rev(), repo.rev());
        assert_eq!(reloaded.did(), repo.did());
        assert_eq!(reloaded.verify(&key.public_key()), Ok(()));
        assert_eq!(reloaded.records(&blocks), repo.records(&store));

        let found = reloaded
            .get(&blocks, &collection(), &rkey("3jqfcqzm4fc2j"))
            .expect("reads")
            .expect("held");
        assert_eq!(
            decode::<Ipld>(&blocks.get(&found).expect("stored")),
            Ok(post("first"))
        );
    }
}
