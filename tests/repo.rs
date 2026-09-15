//! The repository layer, against the CIDs the reference publishes.

use manapds::repo::{BlockMap, Cid, Error, Store, cid_for, decode, encode};
use serde::{Deserialize, Serialize};

/// The shape of an MST node, which is all this file needs of one: the CID over
/// it with no entries is a number the reference test suite pins.
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
struct Node {
    /// Declared last on purpose — dag-cbor sorts keys however they arrive.
    l: Option<Cid>,
    e: Vec<u8>,
}

#[test]
fn empty_node_hashes_to_the_published_cid() {
    let bytes = encode(&Node { l: None, e: vec![] }).expect("encodes");
    assert_eq!(
        cid_for(&bytes).to_string(),
        "bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm"
    );
}

#[test]
fn keys_sort_the_way_dag_cbor_wants() {
    #[derive(Serialize)]
    struct Commit {
        version: u8,
        did: &'static str,
    }

    // A two-key map, then "did" before "version": shorter keys first.
    assert_eq!(
        encode(&Commit {
            version: 3,
            did: "a"
        })
        .expect("encodes"),
        b"\xa2\x63did\x61a\x67version\x03"
    );
}

#[test]
fn blocks_come_back_as_they_went_in() {
    let node = Node {
        l: None,
        e: vec![7],
    };
    let mut blocks = BlockMap::new();
    let cid = blocks.add(&node).expect("encodes");

    assert_eq!(blocks.len(), 1);
    assert!(blocks.contains(&cid).expect("in memory"));
    assert_eq!(decode::<Node>(&blocks.get(&cid).expect("stored")), Ok(node));
}

#[test]
fn a_block_that_is_not_there_says_which() {
    let cid = cid_for(b"\xa0");
    assert_eq!(BlockMap::new().get(&cid), Err(Error::MissingBlock(cid)));
}
