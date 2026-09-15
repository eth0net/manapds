//! Storage, against the layout and the ledger the reference leaves behind.

use std::collections::BTreeMap;
use std::path::Path;

use manapds::crypto::{Algorithm, Keypair};
use manapds::repo::{Ipld, Repo, Store, Write};
use manapds::store::blobs;
use manapds::store::{
    Account, Accounts, Actor, DidCache, Directory, Error, Event, Root, Sequencer,
};
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

#[test]
fn the_log_numbers_events_in_order() {
    let log = Sequencer::memory().expect("opens");
    assert_eq!(log.latest().expect("reads"), None);
    assert_eq!(log.since(0, 10).expect("reads"), vec![]);

    let first = log
        .append(&account(), Event::Append, b"one")
        .expect("writes");
    let second = log
        .append(&account(), Event::Identity, b"two")
        .expect("writes");
    let third = log
        .append(&account(), Event::Account, b"three")
        .expect("writes");

    assert!(first < second && second < third);
    assert_eq!(log.latest().expect("reads"), Some(third));

    let entries = log.since(first, 10).expect("reads");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].seq, second);
    assert_eq!(entries[0].event, Event::Identity);
    assert_eq!(entries[0].body, b"two");
    assert_eq!(&entries[0].did, &account());
    assert_eq!(entries[1].event, Event::Account);

    assert_eq!(log.since(0, 2).expect("reads").len(), 2, "the limit holds");
}

#[test]
fn a_superseded_entry_is_not_handed_out() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let path = home.path().join("sequencer.sqlite");
    let log = Sequencer::open(&path).expect("opens");
    let skipped = log
        .append(&account(), Event::Account, b"gone")
        .expect("writes");
    let kept = log
        .append(&account(), Event::Account, b"here")
        .expect("writes");

    Connection::open(&path)
        .expect("opens")
        .execute(
            r#"update "repo_seq" set "invalidated" = 1 where "seq" = ?1"#,
            rusqlite::params![skipped],
        )
        .expect("writes");

    let entries = log.since(0, 10).expect("reads");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].seq, kept);
    // The number is still spent, so nothing reuses it.
    assert_eq!(log.latest().expect("reads"), Some(kept));
}

#[test]
fn the_log_keeps_its_numbering_across_a_reopen() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let path = home.path().join("sequencer.sqlite");
    let last = {
        let log = Sequencer::open(&path).expect("opens");
        log.append(&account(), Event::Append, b"one")
            .expect("writes");
        log.append(&account(), Event::Append, b"two")
            .expect("writes")
    };

    let log = Sequencer::open(&path).expect("reopens");
    assert_eq!(log.latest().expect("reads"), Some(last));
    assert!(
        log.append(&account(), Event::Append, b"three")
            .expect("writes")
            > last,
        "a restart must not rewind the sequence"
    );
}

fn registration(handle: &str, email: &str) -> Account {
    Account {
        did: account(),
        handle: Some(handle.parse().expect("a handle")),
        email: email.to_owned(),
        password_scrypt: "not a real hash".to_owned(),
    }
}

#[test]
fn an_account_reads_back_by_did_or_handle() {
    let mut accounts = Accounts::memory().expect("opens");
    let registered = registration("alice.example.com", "alice@example.com");
    accounts.create(&registered).expect("creates");

    assert_eq!(
        accounts.by_did(&account()).expect("reads"),
        Some(registered.clone())
    );
    assert_eq!(
        accounts
            .by_handle(&"alice.example.com".parse().expect("a handle"))
            .expect("reads"),
        Some(registered)
    );
    assert_eq!(
        accounts
            .by_handle(&"bob.example.com".parse().expect("a handle"))
            .expect("reads"),
        None
    );
}

#[test]
fn a_handle_is_taken_whatever_case_it_is_asked_in() {
    let mut accounts = Accounts::memory().expect("opens");
    accounts
        .create(&registration("alice.example.com", "alice@example.com"))
        .expect("creates");

    // The unique index is over lower("handle"), so this is the schema
    // refusing rather than the query.
    let mut clash = registration("ALICE.example.com", "other@example.com");
    clash.did = "did:plc:zzzzzzzzzzzzzzzzzzzzzzzz".parse().expect("a DID");
    assert!(accounts.create(&clash).is_err());

    let found = accounts
        .by_handle(&"alice.example.com".parse().expect("a handle"))
        .expect("reads")
        .expect("held");
    assert_eq!(found.email, "alice@example.com");
}

#[test]
fn an_email_is_taken_whatever_case_it_is_given_in() {
    let mut accounts = Accounts::memory().expect("opens");
    accounts
        .create(&registration("alice.example.com", "alice@example.com"))
        .expect("creates");

    let mut clash = registration("bob.example.com", "ALICE@example.com");
    clash.did = "did:plc:zzzzzzzzzzzzzzzzzzzzzzzz".parse().expect("a DID");
    assert!(accounts.create(&clash).is_err());
}

#[test]
fn the_account_database_refuses_the_oauth_migrations() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let path = home.path().join("account.sqlite");
    Accounts::open(&path).expect("opens");

    Connection::open(&path)
        .expect("opens")
        .execute(
            r#"insert into "kysely_migration" ("name", "timestamp") values ('004', '')"#,
            [],
        )
        .expect("writes");

    let refused = Accounts::open(&path);
    assert!(
        matches!(refused, Err(Error::TooNew(ref name)) if name == "004"),
        "{refused:?}"
    );
}

#[test]
fn a_blob_is_stored_under_the_cid_of_its_bytes() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let blobs = Directory::new(home.path()).blobs();
    let bytes = b"not really a picture";
    let cid = blobs::cid_for(bytes);

    assert!(!blobs.has(&account(), &cid));
    blobs.put(&account(), &cid, bytes).expect("stores");
    assert!(blobs.has(&account(), &cid));
    assert_eq!(blobs.get(&account(), &cid).expect("reads"), bytes);

    // The reference lays them out as <blocks>/<did>/<cid>.
    assert_eq!(
        blobs.path(&account(), &cid),
        home.path()
            .join("blocks")
            .join("did:plc:4cjoyc3cgpal7gnrpzyjhnv3")
            .join(cid.to_string())
    );

    // Upstream spells the temporary directory "tempt", and a blob lands there
    // before its CID is known.
    assert_eq!(
        blobs.temp_path(&account(), "somekey"),
        home.path()
            .join("blocks")
            .join("tempt")
            .join("did:plc:4cjoyc3cgpal7gnrpzyjhnv3")
            .join("somekey")
    );

    blobs.delete(&account(), &cid).expect("deletes");
    assert!(!blobs.has(&account(), &cid));
    blobs
        .delete(&account(), &cid)
        .expect("deleting twice is quiet");
}

#[test]
fn bytes_that_are_not_their_cid_are_refused() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let blobs = Directory::new(home.path()).blobs();
    let cid = blobs::cid_for(b"one thing");

    assert!(blobs.put(&account(), &cid, b"another thing").is_err());
    assert!(!blobs.has(&account(), &cid));
}

#[test]
fn quarantine_hides_a_blob_without_losing_it() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let blobs = Directory::new(home.path()).blobs();
    let bytes = b"not really a picture";
    let cid = blobs::cid_for(bytes);
    blobs.put(&account(), &cid, bytes).expect("stores");

    blobs.quarantine(&account(), &cid).expect("quarantines");
    assert!(!blobs.has(&account(), &cid));
    assert!(blobs.quarantine_path(&account(), &cid).is_file());

    blobs.unquarantine(&account(), &cid).expect("restores");
    assert!(blobs.has(&account(), &cid));
    assert_eq!(blobs.get(&account(), &cid).expect("reads"), bytes);
}

#[test]
fn a_cached_document_comes_back_with_its_age() {
    let cache = DidCache::memory().expect("opens");
    let before = jiff::Timestamp::now().as_millisecond();
    assert_eq!(cache.get(&account()).expect("reads"), None);

    cache.put(&account(), r#"{"id":"one"}"#).expect("writes");
    let held = cache.get(&account()).expect("reads").expect("held");
    assert_eq!(held.document, r#"{"id":"one"}"#);
    assert!(held.updated_at >= before, "the write time is recorded");

    cache
        .put(&account(), r#"{"id":"two"}"#)
        .expect("overwrites");
    assert_eq!(
        cache
            .get(&account())
            .expect("reads")
            .expect("held")
            .document,
        r#"{"id":"two"}"#
    );

    cache.forget(&account()).expect("forgets");
    assert_eq!(cache.get(&account()).expect("reads"), None);
}
