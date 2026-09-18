//! The repository layer, against the CIDs the reference publishes.

use manapds::crypto::{Algorithm, Keypair};
use std::collections::BTreeMap;

use manapds::repo::{
    BlockMap, Cid, Commit, Error, Ipld, Mst, Repo, Store, VERSION, Write, car, cid_for, decode,
    encode,
};
use manapds::syntax::{Did, Nsid, RecordKey, TidClock};
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

fn account() -> Did {
    "did:plc:4cjoyc3cgpal7gnrpzyjhnv3".parse().expect("a DID")
}

fn collection() -> Nsid {
    "com.example.record".parse().expect("an NSID")
}

fn rkey(key: &str) -> RecordKey {
    key.parse().expect("a record key")
}

fn post(text: &str) -> Ipld {
    Ipld::Map(BTreeMap::from([
        (
            "$type".to_owned(),
            Ipld::String("com.example.record".to_owned()),
        ),
        ("text".to_owned(), Ipld::String(text.to_owned())),
    ]))
}

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
    store.merge(
        repo.apply(&store, &writes, &key, &mut clock)
            .expect("applies"),
    );

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

#[test]
fn a_write_that_fails_leaves_the_revision_where_it_was() {
    let key = Keypair::generate(Algorithm::Secp256k1);
    let mut clock = TidClock::new();
    let (mut repo, mut store) = Repo::create(account(), &key, &mut clock).expect("creates");

    let create = |text| Write::Create {
        collection: collection(),
        rkey: rkey("3jqfcqzm4fc2j"),
        record: post(text),
    };
    store.merge(
        repo.apply(&store, &[create("first")], &key, &mut clock)
            .expect("applies"),
    );
    let settled = repo.cid();
    let rev = repo.rev().clone();

    // The second write in the batch is the one that cannot land.
    let clash = repo.apply(
        &store,
        &[
            Write::Delete {
                collection: collection(),
                rkey: rkey("3jqfcqzm4fc2j"),
            },
            create("again"),
            create("and again"),
        ],
        &key,
        &mut clock,
    );

    assert_eq!(
        clash.err(),
        Some(Error::KeyExists(
            "com.example.record/3jqfcqzm4fc2j".to_owned()
        ))
    );
    assert_eq!(repo.cid(), settled);
    assert_eq!(repo.rev(), &rev);
    assert_eq!(repo.records(&store).expect("reads").len(), 1);
}

#[test]
fn updates_and_deletes_move_the_root() {
    let key = Keypair::generate(Algorithm::Secp256k1);
    let mut clock = TidClock::new();
    let (mut repo, mut store) = Repo::create(account(), &key, &mut clock).expect("creates");
    let empty = repo.commit().data;

    let created = Write::Create {
        collection: collection(),
        rkey: rkey("3jqfcqzm4fc2j"),
        record: post("first"),
    };
    let edited = Write::Update {
        collection: collection(),
        rkey: rkey("3jqfcqzm4fc2j"),
        record: post("edited"),
    };
    let deleted = Write::Delete {
        collection: collection(),
        rkey: rkey("3jqfcqzm4fc2j"),
    };

    store.merge(
        repo.apply(&store, &[created], &key, &mut clock)
            .expect("applies"),
    );
    let after_create = repo.commit().data;

    store.merge(
        repo.apply(&store, &[edited], &key, &mut clock)
            .expect("applies"),
    );
    assert_ne!(repo.commit().data, after_create);

    store.merge(
        repo.apply(&store, &[deleted], &key, &mut clock)
            .expect("applies"),
    );
    assert_eq!(
        repo.commit().data,
        empty,
        "an emptied tree is the empty one"
    );
    assert_eq!(repo.verify(&key.public_key()), Ok(()));
}

/// A node whose only content is the subtree to its left.
fn chain(child: Ipld) -> Ipld {
    Ipld::Map(BTreeMap::from([
        ("e".to_owned(), Ipld::List(Vec::new())),
        ("l".to_owned(), child),
    ]))
}

/// A node reaching the same subtree twice, once to the left and once past its
/// one record.
fn forked(child: Cid, value: Cid) -> Ipld {
    Ipld::Map(BTreeMap::from([
        ("l".to_owned(), Ipld::Link(child)),
        (
            "e".to_owned(),
            Ipld::List(vec![Ipld::Map(BTreeMap::from([
                ("p".to_owned(), Ipld::Integer(0)),
                (
                    "k".to_owned(),
                    Ipld::Bytes(b"com.example.record/3jqfcqzm4fc2j".to_vec()),
                ),
                ("v".to_owned(), Ipld::Link(value)),
                ("t".to_owned(), Ipld::Link(child)),
            ]))]),
        ),
    ]))
}

#[test]
fn a_tree_deeper_than_its_keys_allow_is_refused() {
    let mut blocks = BlockMap::new();
    let mut cid = blocks.add(&chain(Ipld::Null)).expect("a node");
    for _ in 0..300 {
        cid = blocks.add(&chain(Ipld::Link(cid))).expect("a node");
    }

    let error = Mst::load(cid)
        .leaves(&blocks)
        .expect_err("a chain no key could have built");
    assert_eq!(
        error,
        Error::MalformedNode("a tree deeper than its keys allow")
    );
}

#[test]
fn a_tree_that_reaches_the_same_node_twice_is_refused() {
    let mut blocks = BlockMap::new();
    let value = blocks.add(&post("a record to point at")).expect("a record");
    let mut cid = blocks.add(&chain(Ipld::Null)).expect("a node");
    // Each level doubles the work of walking it, so twenty-four of them is
    // sixteen million leaves out of a file this size.
    for _ in 0..24 {
        cid = blocks.add(&forked(cid, value)).expect("a node");
    }

    let error = Mst::load(cid)
        .leaves(&blocks)
        .expect_err("a file that unfolds into more tree than it holds");
    assert_eq!(error, Error::MalformedNode("a node under itself"));
}

/// One of the reference's covering-proof cases, read for the roots it pins
/// rather than the proof: a tree built from `keys`, then the same tree after
/// `adds` and `dels` are applied together.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CommitProof {
    comment: String,
    leaf_value: String,
    keys: Vec<String>,
    adds: Vec<String>,
    dels: Vec<String>,
    root_before_commit: String,
    root_after_commit: String,
}

#[test]
fn the_reference_commit_proof_roots_are_the_ones_built_here() {
    let fixtures: Vec<CommitProof> =
        serde_json::from_str(include_str!("fixtures/mst/commit-proof-fixtures.json"))
            .expect("the fixture parses");
    assert_eq!(fixtures.len(), 6);

    for fixture in fixtures {
        let value: Cid = fixture.leaf_value.parse().expect("a CID");
        let mut blocks = BlockMap::new();

        let mut tree = Mst::empty();
        for key in &fixture.keys {
            tree = tree.add(&blocks, key, value).expect("adds");
        }
        let (before, tree_blocks) = tree.unstored_blocks(&blocks).expect("hashes");
        blocks.merge(tree_blocks);
        assert_eq!(
            before.to_string(),
            fixture.root_before_commit,
            "{} before",
            fixture.comment
        );

        // Every operation of the commit lands before the root is taken, which
        // is what makes a merge and a split in the same commit reachable.
        for key in &fixture.dels {
            tree = tree.delete(&blocks, key).expect("deletes");
        }
        for key in &fixture.adds {
            tree = tree.add(&blocks, key, value).expect("adds");
        }
        let (after, tree_blocks) = tree.unstored_blocks(&blocks).expect("hashes");
        blocks.merge(tree_blocks);
        assert_eq!(
            after.to_string(),
            fixture.root_after_commit,
            "{} after",
            fixture.comment
        );
    }
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
        serde_json::from_str(include_str!("fixtures/commit/golden.json")).expect("the fixture");
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
