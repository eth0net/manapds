//! The repository layer, against the CIDs the reference publishes.

use manapds::crypto::{Algorithm, Keypair};
use manapds::repo::{BlockMap, Cid, Commit, Error, Mst, Store, VERSION, cid_for, decode, encode};
use manapds::syntax::{Did, TidClock};
use rand::seq::SliceRandom;
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

/// The record every tree below points its leaves at; only the keys matter to
/// the shape, so one CID does for all of them.
const RECORD: &str = "bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454";

/// Roots the reference test suite pins, so agreeing with them is agreeing with
/// every other server.
const EMPTY: &str = "bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm";
const TRIVIAL: &str = "bafyreibj4lsc3aqnrvphp5xmrnfoorvru4wynt6lwidqbm2623a6tatzdu";
const SINGLE_LAYER_2: &str = "bafyreih7wfei65pxzhauoibu3ls7jgmkju4bspy4t2ha2qdjnzqvoy33ai";
const SIMPLE: &str = "bafyreicmahysq4n6wfuxo522m6dpiy7z7qzym3dzs756t5n7nfdgccwq7m";

fn record() -> Cid {
    RECORD.parse().expect("a CID")
}

fn tree_of(keys: &[&str]) -> Mst {
    let mut mst = Mst::empty();
    for key in keys {
        mst = mst.add(&BlockMap::new(), key, record()).expect("adds");
    }
    mst
}

fn root_of(mst: &mut Mst) -> String {
    mst.root(&BlockMap::new()).expect("hashes").to_string()
}

#[test]
fn known_maps_hash_to_the_published_roots() {
    assert_eq!(root_of(&mut tree_of(&[])), EMPTY);
    assert_eq!(
        root_of(&mut tree_of(&["com.example.record/3jqfcqzm3fo2j"])),
        TRIVIAL
    );
    assert_eq!(
        root_of(&mut tree_of(&["com.example.record/3jqfcqzm3fx2j"])),
        SINGLE_LAYER_2
    );
    assert_eq!(
        root_of(&mut tree_of(&[
            "com.example.record/3jqfcqzm3fp2j",
            "com.example.record/3jqfcqzm3fr2j",
            "com.example.record/3jqfcqzm3fs2j",
            "com.example.record/3jqfcqzm3ft2j",
            "com.example.record/3jqfcqzm4fc2j",
        ])),
        SIMPLE
    );
}

#[test]
fn insertion_order_does_not_show() {
    let forwards = &[
        "com.example.record/3jqfcqzm3fp2j",
        "com.example.record/3jqfcqzm3fr2j",
        "com.example.record/3jqfcqzm3fs2j",
        "com.example.record/3jqfcqzm3ft2j",
        "com.example.record/3jqfcqzm4fc2j",
    ];
    let mut backwards: Vec<&str> = forwards.to_vec();
    backwards.reverse();
    assert_eq!(root_of(&mut tree_of(&backwards)), SIMPLE);
}

#[test]
fn deleting_the_top_layer_trims_it() {
    let store = BlockMap::new();
    let mut mst = tree_of(&[
        "com.example.record/3jqfcqzm3fn2j",
        "com.example.record/3jqfcqzm3fo2j",
        "com.example.record/3jqfcqzm3fp2j",
        "com.example.record/3jqfcqzm3fs2j",
        "com.example.record/3jqfcqzm3ft2j",
        "com.example.record/3jqfcqzm3fu2j",
    ]);
    assert_eq!(
        root_of(&mut mst),
        "bafyreifnqrwbk6ffmyaz5qtujqrzf5qmxf7cbxvgzktl4e3gabuxbtatv4"
    );

    let mut mst = mst
        .delete(&store, "com.example.record/3jqfcqzm3fs2j")
        .expect("deletes");
    assert_eq!(mst.leaves(&store).expect("reads").len(), 5);
    assert_eq!(
        root_of(&mut mst),
        "bafyreie4kjuxbwkhzg2i5dljaswcroeih4dgiqq6pazcmunwt2byd725vi"
    );
}

#[test]
fn an_insert_splits_two_layers_down() {
    let store = BlockMap::new();
    let l1 = "bafyreiettyludka6fpgp33stwxfuwhkzlur6chs4d2v4nkmq2j3ogpdjem";
    let l2 = "bafyreid2x5eqs4w4qxvc5jiwda4cien3gw2q6cshofxwnvv7iucrmfohpm";
    // F, at layer 2, is the gap in the middle.
    let mut mst = tree_of(&[
        "com.example.record/3jqfcqzm3fo2j",
        "com.example.record/3jqfcqzm3fp2j",
        "com.example.record/3jqfcqzm3fr2j",
        "com.example.record/3jqfcqzm3fs2j",
        "com.example.record/3jqfcqzm3ft2j",
        "com.example.record/3jqfcqzm3fz2j",
        "com.example.record/3jqfcqzm4fc2j",
        "com.example.record/3jqfcqzm4fd2j",
        "com.example.record/3jqfcqzm4ff2j",
        "com.example.record/3jqfcqzm4fg2j",
        "com.example.record/3jqfcqzm4fh2j",
    ]);
    assert_eq!(root_of(&mut mst), l1);

    let mut mst = mst
        .add(&store, "com.example.record/3jqfcqzm3fx2j", record())
        .expect("adds");
    assert_eq!(mst.leaves(&store).expect("reads").len(), 12);
    assert_eq!(root_of(&mut mst), l2);

    let mut mst = mst
        .delete(&store, "com.example.record/3jqfcqzm3fx2j")
        .expect("deletes");
    assert_eq!(root_of(&mut mst), l1);
}

#[test]
fn a_new_layer_can_be_two_above_the_old_one() {
    let store = BlockMap::new();
    let l0 = "bafyreidfcktqnfmykz2ps3dbul35pepleq7kvv526g47xahuz3rqtptmky";
    let l2 = "bafyreiavxaxdz7o7rbvr3zg2liox2yww46t7g6hkehx4i4h3lwudly7dhy";
    let with_d = "bafyreig4jv3vuajbsybhyvb7gggvpwh2zszwfyttjrj6qwvcsp24h6popu";

    let mut mst = tree_of(&[
        "com.example.record/3jqfcqzm3ft2j",
        "com.example.record/3jqfcqzm3fz2j",
    ]);
    assert_eq!(root_of(&mut mst), l0);

    let mut mst = mst
        .add(&store, "com.example.record/3jqfcqzm3fx2j", record())
        .expect("adds");
    assert_eq!(root_of(&mut mst), l2);

    let mut mst = mst
        .delete(&store, "com.example.record/3jqfcqzm3fx2j")
        .expect("deletes");
    assert_eq!(root_of(&mut mst), l0);

    let mut mst = mst
        .add(&store, "com.example.record/3jqfcqzm3fx2j", record())
        .expect("adds")
        .add(&store, "com.example.record/3jqfcqzm4fd2j", record())
        .expect("adds");
    assert_eq!(root_of(&mut mst), with_d);

    let mut mst = mst
        .delete(&store, "com.example.record/3jqfcqzm4fd2j")
        .expect("deletes");
    assert_eq!(root_of(&mut mst), l2);
}

#[test]
fn keys_are_a_collection_and_a_record_key() {
    let store = BlockMap::new();
    for key in [
        "coll/3jui7kd54zh2y",
        "coll/self",
        "coll/example.com",
        "com.example/rkey",
        "coll/~1.2-3_",
        "coll/dHJ1ZQ",
        "coll/pre:fix",
        "coll/_",
    ] {
        assert!(Mst::empty().add(&store, key, record()).is_ok(), "{key}");
    }
    for key in [
        "",
        "asdf",
        "nested/collection/asdf",
        "coll/",
        "/rkey",
        "coll/jalapeñoA",
        "coll/coöperative",
        "coll/abc💩",
        "coll/key$",
        "coll/key%",
        "coll/key(",
        "coll/key)",
        "coll/key+",
        "coll/key=",
        "coll/@handle",
        "coll/any space",
        "coll/#extra",
        "coll/any+space",
        "coll/number[3]",
        "coll/number(3)",
        "coll/dHJ1ZQ==",
        "coll/\"quote\"",
        &format!("coll/{}", "a".repeat(1025)),
    ] {
        assert_eq!(
            Mst::empty().add(&store, key, record()).err(),
            Some(Error::InvalidKey(key.to_owned())),
            "{key}"
        );
    }
}

#[test]
fn a_stored_tree_reads_back_the_same() {
    let keys = [
        "com.example.record/3jqfcqzm3fo2j",
        "com.example.record/3jqfcqzm3fp2j",
        "com.example.record/3jqfcqzm3fr2j",
        "com.example.record/3jqfcqzm3fs2j",
        "com.example.record/3jqfcqzm3ft2j",
        "com.example.record/3jqfcqzm3fz2j",
        "com.example.record/3jqfcqzm4fc2j",
        "com.example.record/3jqfcqzm4fd2j",
    ];
    let mut built = tree_of(&keys);
    let (root, blocks) = built.unstored_blocks(&BlockMap::new()).expect("hashes");

    let mut loaded = Mst::load(root);
    assert_eq!(loaded.root(&blocks).expect("hashes"), root);
    let read: Vec<String> = loaded
        .leaves(&blocks)
        .expect("reads")
        .into_iter()
        .map(|leaf| leaf.key)
        .collect();
    assert_eq!(read, keys);

    assert_eq!(loaded.get(&blocks, keys[3]).expect("reads"), Some(record()));
    assert_eq!(loaded.get(&blocks, "com.example.record/nope"), Ok(None));
}

#[test]
fn a_thousand_records_survive_a_shuffle() {
    let store = BlockMap::new();
    let mut clock = TidClock::new();
    let keys: Vec<String> = (0..1000)
        .map(|_| format!("com.example.record/{}", clock.mint()))
        .collect();

    let mut ordered = tree_of(&keys.iter().map(String::as_str).collect::<Vec<_>>());
    let root = root_of(&mut ordered);

    let mut shuffled = keys.clone();
    shuffled.shuffle(&mut rand::rng());
    let mut rebuilt = tree_of(&shuffled.iter().map(String::as_str).collect::<Vec<_>>());
    assert_eq!(root_of(&mut rebuilt), root);

    let mut emptied = rebuilt;
    for key in &shuffled {
        emptied = emptied.delete(&store, key).expect("deletes");
    }
    assert_eq!(root_of(&mut emptied), EMPTY);
}

#[test]
fn a_key_is_written_once_and_edited_after() {
    let store = BlockMap::new();
    let key = "com.example.record/3jqfcqzm3fo2j";
    let other = cid_for(b"\xa0");

    let mst = Mst::empty().add(&store, key, record()).expect("adds");
    assert_eq!(
        mst.add(&store, key, other).err(),
        Some(Error::KeyExists(key.to_owned()))
    );

    let mst = Mst::empty().add(&store, key, record()).expect("adds");
    let mut mst = mst.update(&store, key, other).expect("updates");
    assert_eq!(mst.get(&store, key), Ok(Some(other)));

    let missing = "com.example.record/3jqfcqzm3fp2j";
    assert_eq!(
        mst.update(&store, missing, other).err(),
        Some(Error::KeyMissing(missing.to_owned()))
    );
}

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
