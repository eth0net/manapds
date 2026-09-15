//! Storage, against the layout and the ledger the reference leaves behind.

use std::collections::BTreeMap;
use std::path::Path;

use manapds::crypto::{Algorithm, Keypair};
use manapds::repo::{Ipld, Repo, Store, Write};
use manapds::store::{Actor, Directory, Error, Root};
use manapds::syntax::{Did, Nsid, RecordKey, TidClock};
use rusqlite::Connection;

fn account() -> Did {
    "did:plc:4cjoyc3cgpal7gnrpzyjhnv3".parse().expect("a DID")
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

fn create(rkey: &str, text: &str) -> Write {
    Write::Create {
        collection: "com.example.record".parse::<Nsid>().expect("an NSID"),
        rkey: rkey.parse::<RecordKey>().expect("a record key"),
        record: post(text),
    }
}

#[test]
fn the_layout_is_where_the_reference_puts_it() {
    let directory = Directory::new("/data");
    let did = account();

    assert_eq!(directory.accounts(), Path::new("/data/account.sqlite"));
    assert_eq!(directory.sequencer(), Path::new("/data/sequencer.sqlite"));
    assert_eq!(directory.did_cache(), Path::new("/data/did_cache.sqlite"));
    // The shard is the first byte of the sha-256 of the DID, in hex.
    assert_eq!(
        directory.actor_store(&did),
        Path::new("/data/actors/6c/did:plc:4cjoyc3cgpal7gnrpzyjhnv3/store.sqlite")
    );
    assert_eq!(
        directory.actor_key(&did),
        Path::new("/data/actors/6c/did:plc:4cjoyc3cgpal7gnrpzyjhnv3/key")
    );
}

#[test]
fn a_new_store_writes_the_ledger_the_reference_reads() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let path = Directory::new(home.path()).actor_store(&account());
    Actor::open(&path, account()).expect("opens");

    let db = Connection::open(&path).expect("opens");
    let applied: Vec<String> = db
        .prepare(r#"select "name" from "kysely_migration""#)
        .expect("prepares")
        .query_map([], |row| row.get(0))
        .expect("queries")
        .collect::<Result<_, _>>()
        .expect("reads");
    assert_eq!(applied, ["001"]);

    let (id, locked): (String, i64) = db
        .query_row(
            r#"select "id", "is_locked" from "kysely_migration_lock""#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("reads");
    assert_eq!((id.as_str(), locked), ("migration_lock", 0));

    let mut tables: Vec<String> = db
        .prepare(r#"select "name" from "sqlite_master" where "type" = 'table'"#)
        .expect("prepares")
        .query_map([], |row| row.get(0))
        .expect("queries")
        .collect::<Result<_, _>>()
        .expect("reads");
    tables.sort();
    tables.retain(|name| !name.starts_with("sqlite_"));
    assert_eq!(
        tables,
        [
            "account_pref",
            "backlink",
            "blob",
            "kysely_migration",
            "kysely_migration_lock",
            "record",
            "record_blob",
            "repo_block",
            "repo_root",
        ]
    );
}

#[test]
fn opening_twice_migrates_once() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let path = Directory::new(home.path()).actor_store(&account());

    Actor::open(&path, account()).expect("opens");
    let store = Actor::open(&path, account()).expect("opens again");
    assert_eq!(store.root().expect("reads"), None);

    let db = Connection::open(&path).expect("opens");
    let rows: i64 = db
        .query_row(r#"select count(*) from "kysely_migration""#, [], |row| {
            row.get(0)
        })
        .expect("counts");
    assert_eq!(rows, 1);
}

#[test]
fn a_database_migrated_past_us_is_refused() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let path = Directory::new(home.path()).actor_store(&account());
    Actor::open(&path, account()).expect("opens");

    Connection::open(&path)
        .expect("opens")
        .execute(
            r#"insert into "kysely_migration" ("name", "timestamp") values ('002', '')"#,
            [],
        )
        .expect("writes");

    let refused = Actor::open(&path, account());
    assert!(
        matches!(refused, Err(Error::TooNew(ref name)) if name == "002"),
        "{refused:?}"
    );
}

#[test]
fn a_repository_round_trips_through_a_file() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let path = Directory::new(home.path()).actor_store(&account());
    let key = Keypair::generate(Algorithm::Secp256k1);
    let mut clock = TidClock::new();

    let (mut repo, blocks) = Repo::create(account(), &key, &mut clock).expect("creates");
    {
        let mut store = Actor::open(&path, account()).expect("opens");
        store
            .commit(
                &Root {
                    cid: repo.cid(),
                    rev: repo.rev().clone(),
                },
                &blocks,
            )
            .expect("commits");

        let written = repo
            .apply(
                &store,
                &[
                    create("3jqfcqzm4fc2j", "first"),
                    create("3jqfcqzm4fd2j", "second"),
                ],
                &key,
                &mut clock,
            )
            .expect("applies");
        store
            .commit(
                &Root {
                    cid: repo.cid(),
                    rev: repo.rev().clone(),
                },
                &written,
            )
            .expect("commits");
    }

    // Everything above is gone; only the file is left.
    let store = Actor::open(&path, account()).expect("reopens");
    let root = store.root().expect("reads").expect("a root");
    assert_eq!(root.cid, repo.cid());
    assert_eq!(&root.rev, repo.rev());

    let mut reloaded = Repo::load(&store, root.cid).expect("loads");
    assert_eq!(reloaded.verify(&key.public_key()), Ok(()));
    assert_eq!(reloaded.records(&store), repo.records(&store));
    assert_eq!(reloaded.records(&store).expect("reads").len(), 2);

    let found = reloaded
        .get(
            &store,
            &"com.example.record".parse().expect("an NSID"),
            &"3jqfcqzm4fc2j".parse().expect("a record key"),
        )
        .expect("reads")
        .expect("held");
    assert_eq!(
        manapds::repo::decode::<Ipld>(&store.get(&found).expect("stored")),
        Ok(post("first"))
    );
}
