//! Storage, against the layout and the ledger the reference leaves behind.
//!
//! One binary, a module per subject, and the fixtures every subject builds on.

mod accounts;
mod blobs;
mod cache;
mod keys;
mod layout;
mod log;
mod repository;

use std::collections::BTreeMap;
use std::path::Path;

use manapds::crypto::{Algorithm, Keypair};
use manapds::repo::{self, Ipld, Repo, Store, Write};
use manapds::store::{
    Account, Accounts, Actor, AppPassword, Blob, Blocks, DidCache, Directory, Error, Event,
    Indexed, Record, Registration, Root, Running, Sequencer, Session,
};
use manapds::syntax::{Did, Nsid, RecordKey, Tid, TidClock};
use rusqlite::Connection;

/// A blob store for a commit that writes no blobs, which touches no file. A
/// test that does hands in one of its own.
fn blobs() -> manapds::store::Blobs {
    Directory::new("/nonexistent/manapds").blobs()
}

fn account() -> Did {
    "did:plc:4cjoyc3cgpal7gnrpzyjhnv3".parse().expect("a DID")
}

fn post(text: &str) -> Ipld {
    post_in("com.example.record", text)
}

fn post_in(collection: &str, text: &str) -> Ipld {
    Ipld::Map(BTreeMap::from([
        ("$type".to_owned(), Ipld::String(collection.to_owned())),
        ("text".to_owned(), Ipld::String(text.to_owned())),
    ]))
}

fn indexed(rkey: &str, text: &str) -> Indexed {
    indexed_in("com.example.record", rkey, text)
}

fn indexed_in(collection: &str, rkey: &str, text: &str) -> Indexed {
    Indexed::Put {
        collection: collection.parse::<Nsid>().expect("an NSID"),
        rkey: rkey.parse::<RecordKey>().expect("a record key"),
        cid: repo::cid_for(&repo::encode(&post_in(collection, text)).expect("encodes")),
        links: Vec::new(),
        blobs: Vec::new(),
    }
}

/// What a write leaves in the block store, as the store wants it.
fn stored(written: &(repo::BlockMap, Vec<repo::Cid>)) -> Blocks<'_> {
    Blocks {
        written: &written.0,
        dropped: &written.1,
    }
}

/// The same for a first commit, which has nothing before it to drop.
fn genesis(blocks: &repo::BlockMap) -> Blocks<'_> {
    Blocks {
        written: blocks,
        dropped: &[],
    }
}

/// Where the repository has got to, as the store wants it.
fn at(repo: &Repo) -> Root {
    Root {
        cid: repo.cid(),
        rev: repo.rev().clone(),
    }
}

/// The index as it stands, read past the writer that keeps it.
fn indexed_rows(path: &Path) -> Vec<(String, String, String, String)> {
    let db = Connection::open(path).expect("opens");
    db.prepare(r#"select "uri", "cid", "collection", "rkey" from "record" order by "rkey""#)
        .expect("prepares")
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .expect("queries")
        .collect::<Result<_, _>>()
        .expect("reads")
}

fn create(rkey: &str, text: &str) -> Write {
    create_in("com.example.record", rkey, text)
}

fn create_in(collection: &str, rkey: &str, text: &str) -> Write {
    Write::Create {
        collection: collection.parse::<Nsid>().expect("an NSID"),
        rkey: rkey.parse::<RecordKey>().expect("a record key"),
        record: Ipld::Map(BTreeMap::from([
            ("$type".to_owned(), Ipld::String(collection.to_owned())),
            ("text".to_owned(), Ipld::String(text.to_owned())),
        ])),
    }
}

/// The keys a page came back in, which is what its order is about.
fn keys(records: &[Record]) -> Vec<&str> {
    records
        .iter()
        .map(|record| record.uri.rsplit('/').next().expect("a key"))
        .collect()
}
