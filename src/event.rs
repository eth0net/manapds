//! Event bodies: what a consumer is handed when something happens to a
//! repository.
//!
//! The log stores these without looking inside one, so the shapes live here
//! rather than next to it. Every field is the reference's, down to the two
//! that are deprecated and still required.

use serde::Serialize;

use crate::repo::{BlockMap, Cid, Error, Store, car, encode};
use crate::store::Event;
use crate::syntax::{Did, Handle, Tid};

/// An entry built and waiting for the log.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Body {
    /// Which kind of entry it is.
    pub event: Event,
    /// The dag-cbor a consumer decodes.
    pub bytes: Vec<u8>,
}

/// What one commit did to one record.
#[derive(Debug, Serialize)]
pub struct Op {
    /// `create`, `update` or `delete`.
    pub action: &'static str,
    /// The collection and the record key, joined by a slash.
    pub path: String,
    /// Where the record landed, or null where it was deleted.
    pub cid: Option<Cid>,
    /// What stood there before, left out entirely where nothing did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev: Option<Cid>,
}

/// A handle or DID document changed.
#[derive(Debug, Serialize)]
struct Identity<'a> {
    did: &'a Did,
    handle: &'a Handle,
}

/// An account became reachable or stopped being.
#[derive(Debug, Serialize)]
struct Account<'a> {
    did: &'a Did,
    active: bool,
}

/// A commit was written.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Append<'a> {
    repo: &'a Did,
    commit: Cid,
    rev: &'a Tid,
    since: Option<&'a Tid>,
    #[serde(with = "serde_bytes")]
    blocks: Vec<u8>,
    ops: &'a [Op],
    /// Left out entirely when there is no revision before this one.
    #[serde(skip_serializing_if = "Option::is_none")]
    prev_data: Option<Cid>,
    rebase: bool,
    too_big: bool,
    blobs: &'a [Cid],
}

/// Where a repository is now, for a consumer that fell behind.
#[derive(Debug, Serialize)]
struct Sync<'a> {
    did: &'a Did,
    rev: &'a Tid,
    #[serde(with = "serde_bytes")]
    blocks: Vec<u8>,
}

/// One commit, as the log carries it.
#[derive(Debug)]
pub struct Commit<'a> {
    /// Whose repository moved.
    pub did: &'a Did,
    /// The commit block it moved onto.
    pub commit: Cid,
    /// The revision that commit carries.
    pub rev: &'a Tid,
    /// The revision before it, absent only on the first.
    pub since: Option<&'a Tid>,
    /// The tree the revision before it held, which is what lets a consumer
    /// check it did not miss one.
    pub prev_data: Option<Cid>,
    /// What the commit did, one entry per record.
    pub ops: &'a [Op],
}

/// The entry one commit puts in the log.
///
/// # Errors
///
/// If the body will not encode, or `blocks` is missing the commit.
pub fn records_written(written: &Commit<'_>, blocks: &BlockMap) -> Result<Body, Error> {
    Ok(Body {
        event: Event::Append,
        bytes: encode(&Append {
            repo: written.did,
            commit: written.commit,
            rev: written.rev,
            since: written.since,
            blocks: car::write(written.commit, blocks)?,
            ops: written.ops,
            prev_data: written.prev_data,
            rebase: false,
            too_big: false,
            blobs: &[],
        })?,
    })
}

/// The four entries a new account puts in the log.
///
/// They are built together because they have to be written together: a
/// consumer that reads the commit before the account exists has no way to ask
/// for what it missed.
///
/// # Errors
///
/// If a body will not encode, or `blocks` is missing the commit.
pub fn account_created(
    did: &Did,
    handle: &Handle,
    commit: Cid,
    rev: &Tid,
    blocks: &BlockMap,
) -> Result<[Body; 4], Error> {
    let mut root = BlockMap::new();
    root.insert(commit, blocks.get(&commit)?.into_owned());

    Ok([
        Body {
            event: Event::Identity,
            bytes: encode(&Identity { did, handle })?,
        },
        Body {
            event: Event::Account,
            bytes: encode(&Account { did, active: true })?,
        },
        Body {
            event: Event::Append,
            bytes: encode(&Append {
                repo: did,
                commit,
                rev,
                since: None,
                blocks: car::write(commit, blocks)?,
                ops: &[],
                prev_data: None,
                rebase: false,
                too_big: false,
                blobs: &[],
            })?,
        },
        Body {
            event: Event::Sync,
            bytes: encode(&Sync {
                did,
                rev,
                blocks: car::write(commit, &root)?,
            })?,
        },
    ])
}
/// The entries a signup writes, against what the reference encodes for the
/// same account. `tools/sequencer-fixture.mjs` remakes the file.
#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::repo::{Ipld, cid_for, decode};

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
            serde_json::from_str(include_str!("../fixtures/sequencer/account.json"))
                .expect("the fixture");

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
            serde_json::from_str(include_str!("../fixtures/sequencer/account.json"))
                .expect("the fixture");

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
}
