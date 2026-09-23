//! The entries a signup writes, against what the reference encodes for the
//! same account. `tools/sequencer-fixture.mjs` remakes the file.

use std::str::FromStr;

use manapds::event::account_created;
use manapds::repo::{BlockMap, Cid, Ipld, car, cid_for, decode};
use manapds::store::Event;

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct Fixture {
    did: String,
    handle: String,
    rev: String,
    commit: String,
    commit_block: String,
    tree: String,
    tree_block: String,
    identity: String,
    account: String,
    append: String,
    sync: String,
}

/// Blocks compare by what they hold: this server writes a CAR in CID order and
/// the reference writes it in the order the blocks were made.
fn spread(bytes: &[u8]) -> Ipld {
    let value = decode(bytes).expect("dag-cbor");
    let Ipld::Map(mut map) = value else {
        return value;
    };
    if let Some(Ipld::Bytes(file)) = map.get("blocks") {
        let (root, blocks) = car::read(file).expect("a car file");
        let listed = std::iter::once(Ipld::Link(root))
            .chain(blocks.iter().map(|(cid, bytes)| {
                Ipld::List(vec![Ipld::Link(*cid), Ipld::Bytes(bytes.to_vec())])
            }))
            .collect();
        map.insert("blocks".into(), Ipld::List(listed));
    }
    Ipld::Map(map)
}

fn block(hex: &str, cid: &str) -> (Cid, Vec<u8>) {
    let bytes = hex::decode(hex).expect("hex");
    let found = cid_for(&bytes);
    assert_eq!(found.to_string(), cid, "the fixture disagrees with itself");
    (found, bytes)
}

#[test]
fn a_signup_writes_what_the_reference_writes() {
    let fixture: Fixture =
        serde_json::from_str(include_str!("fixtures/sequencer/account.json")).expect("the fixture");

    let (commit, bytes) = block(&fixture.commit_block, &fixture.commit);
    let (tree, leaves) = block(&fixture.tree_block, &fixture.tree);
    let mut blocks = BlockMap::new();
    blocks.insert(commit, bytes);
    blocks.insert(tree, leaves);

    let bodies = account_created(
        &fixture.did.parse().expect("a did"),
        &fixture.handle.parse().expect("a handle"),
        Cid::from_str(&fixture.commit).expect("a cid"),
        &fixture.rev.parse().expect("a tid"),
        &blocks,
    )
    .expect("the entries");

    let kinds: Vec<Event> = bodies.iter().map(|body| body.event).collect();
    assert_eq!(
        kinds,
        [Event::Identity, Event::Account, Event::Append, Event::Sync]
    );

    // Neither of the first two carries a CAR, so they compare as bytes.
    assert_eq!(hex::encode(&bodies[0].bytes), fixture.identity);
    assert_eq!(hex::encode(&bodies[1].bytes), fixture.account);

    assert_eq!(
        spread(&bodies[2].bytes),
        spread(&hex::decode(&fixture.append).expect("hex"))
    );
    assert_eq!(
        spread(&bodies[3].bytes),
        spread(&hex::decode(&fixture.sync).expect("hex"))
    );
}

#[test]
fn only_the_commit_block_rides_the_sync_entry() {
    let fixture: Fixture =
        serde_json::from_str(include_str!("fixtures/sequencer/account.json")).expect("the fixture");

    let (commit, bytes) = block(&fixture.commit_block, &fixture.commit);
    let (tree, leaves) = block(&fixture.tree_block, &fixture.tree);
    let mut blocks = BlockMap::new();
    blocks.insert(commit, bytes);
    blocks.insert(tree, leaves);

    let bodies = account_created(
        &fixture.did.parse().expect("a did"),
        &fixture.handle.parse().expect("a handle"),
        commit,
        &fixture.rev.parse().expect("a tid"),
        &blocks,
    )
    .expect("the entries");

    let Ipld::Map(append) = decode(&bodies[2].bytes).expect("dag-cbor") else {
        panic!("an append entry is a map")
    };
    let Ipld::Map(sync) = decode(&bodies[3].bytes).expect("dag-cbor") else {
        panic!("a sync entry is a map")
    };
    let car = |map: &std::collections::BTreeMap<String, Ipld>| {
        let Some(Ipld::Bytes(file)) = map.get("blocks") else {
            panic!("an entry carries its blocks")
        };
        car::read(file).expect("a car file")
    };

    assert_eq!(car(&append).1.len(), 2);
    let (root, only) = car(&sync);
    assert_eq!(root, commit);
    assert_eq!(only.len(), 1);
}
