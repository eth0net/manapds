//! Storage, against the layout and the ledger the reference leaves behind.

use std::collections::BTreeMap;
use std::path::Path;

use manapds::crypto::{Algorithm, Keypair};
use manapds::repo::{self, Ipld, Repo, Store, Write};
use manapds::store::{
    Account, Accounts, Actor, AppPassword, Blob, Blocks, DidCache, Directory, Error, Event,
    Indexed, Record, Registration, Root, Sequencer, Session,
};
use manapds::store::{blobs, keys};
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
    Ipld::Map(BTreeMap::from([
        (
            "$type".to_owned(),
            Ipld::String("com.example.record".to_owned()),
        ),
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
        cid: repo::cid_for(&repo::encode(&post(text)).expect("encodes")),
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

    // The account database carries all seven, so the reference opening it next
    // finds nothing left to run.
    let account_db = home.path().join("account.sqlite");
    Accounts::open(&account_db).expect("opens");
    let applied: Vec<String> = Connection::open(&account_db)
        .expect("opens")
        .prepare(r#"select "name" from "kysely_migration" order by "name""#)
        .expect("prepares")
        .query_map([], |row| row.get(0))
        .expect("queries")
        .collect::<Result<_, _>>()
        .expect("reads");
    assert_eq!(applied, ["001", "002", "003", "004", "005", "006", "007"]);

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
                None,
                &Root {
                    cid: repo.cid(),
                    rev: repo.rev().clone(),
                },
                genesis(&blocks),
                &[],
                &blobs(),
            )
            .expect("commits");

        let from = at(&repo);
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
                Some(&from),
                &Root {
                    cid: repo.cid(),
                    rev: repo.rev().clone(),
                },
                stored(&written),
                &[
                    indexed("3jqfcqzm4fc2j", "first"),
                    indexed("3jqfcqzm4fd2j", "second"),
                ],
                &blobs(),
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
fn a_database_already_at_the_schema_opens_under_somebody_else_s_write_lock() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let path = Directory::new(home.path()).actor_store(&account());
    Actor::open(&path, account()).expect("opens");

    let writer = Connection::open(&path).expect("opens");
    writer
        .execute_batch("begin immediate")
        .expect("takes the write lock");

    // Opening one that needs no migration writes nothing, so a lock somebody
    // else is holding is not in the way of it. Every record read opens one.
    Actor::open(&path, account()).expect("opens again");
}

#[test]
fn the_index_follows_what_the_commit_did() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let path = Directory::new(home.path()).actor_store(&account());
    let key = Keypair::generate(Algorithm::Secp256k1);
    let mut clock = TidClock::new();
    let collection = "com.example.record".parse::<Nsid>().expect("an NSID");
    let rkey = "3jqfcqzm4fc2j".parse::<RecordKey>().expect("a record key");
    let uri = format!("at://{}/{collection}/{rkey}", account());

    let (mut repo, blocks) = Repo::create(account(), &key, &mut clock).expect("creates");
    let mut store = Actor::open(&path, account()).expect("opens");
    store
        .commit(None, &at(&repo), genesis(&blocks), &[], &blobs())
        .expect("commits");
    assert_eq!(indexed_rows(&path), vec![]);

    let from = at(&repo);
    let written = repo
        .apply(
            &store,
            &[create("3jqfcqzm4fc2j", "first")],
            &key,
            &mut clock,
        )
        .expect("applies");
    store
        .commit(
            Some(&from),
            &at(&repo),
            stored(&written),
            &[indexed("3jqfcqzm4fc2j", "first")],
            &blobs(),
        )
        .expect("commits");
    assert_eq!(
        indexed_rows(&path),
        vec![(
            uri.clone(),
            repo::cid_for(&repo::encode(&post("first")).expect("encodes")).to_string(),
            collection.to_string(),
            rkey.to_string(),
        )]
    );

    let from = at(&repo);
    let written = repo
        .apply(
            &store,
            &[Write::Update {
                collection: collection.clone(),
                rkey: rkey.clone(),
                record: post("second"),
            }],
            &key,
            &mut clock,
        )
        .expect("applies");
    store
        .commit(
            Some(&from),
            &at(&repo),
            stored(&written),
            &[indexed("3jqfcqzm4fc2j", "second")],
            &blobs(),
        )
        .expect("commits");
    // The same row, moved on rather than written twice.
    assert_eq!(
        indexed_rows(&path),
        vec![(
            uri,
            repo::cid_for(&repo::encode(&post("second")).expect("encodes")).to_string(),
            collection.to_string(),
            rkey.to_string(),
        )]
    );

    let from = at(&repo);
    let written = repo
        .apply(
            &store,
            &[Write::Delete {
                collection: collection.clone(),
                rkey: rkey.clone(),
            }],
            &key,
            &mut clock,
        )
        .expect("applies");
    store
        .commit(
            Some(&from),
            &at(&repo),
            stored(&written),
            &[Indexed::Delete { collection, rkey }],
            &blobs(),
        )
        .expect("commits");
    assert_eq!(indexed_rows(&path), vec![]);
}

#[test]
fn four_connections_opening_one_new_file_migrate_it_once() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let path = Directory::new(home.path()).actor_store(&account());

    // Every record write opens a database, so the first four requests against
    // a new account arrive here together.
    let refused: Vec<Error> = std::thread::scope(|scope| {
        let opens: Vec<_> = (0..4)
            .map(|_| scope.spawn(|| Actor::open(&path, account())))
            .collect();
        opens
            .into_iter()
            .filter_map(|open| open.join().expect("a thread").err())
            .collect()
    });
    assert!(refused.is_empty(), "{refused:?}");

    let db = Connection::open(&path).expect("opens");
    let applied: Vec<String> = db
        .prepare(r#"select "name" from "kysely_migration""#)
        .expect("prepares")
        .query_map([], |row| row.get(0))
        .expect("queries")
        .collect::<Result<_, _>>()
        .expect("reads");
    assert_eq!(applied, ["001"]);
}

#[test]
fn a_commit_built_on_a_root_somebody_else_moved_is_refused() {
    let key = Keypair::generate(Algorithm::Secp256k1);
    let mut clock = TidClock::new();

    let (repo, blocks) = Repo::create(account(), &key, &mut clock).expect("creates");
    let mut store = Actor::memory(account()).expect("opens");
    store
        .commit(None, &at(&repo), genesis(&blocks), &[], &blobs())
        .expect("commits");

    // Two writers, both working from the root the genesis left.
    let from = at(&repo);
    let (mut first, mut second) = (repo.clone(), repo);
    let one = first
        .apply(&store, &[create("3jqfcqzm4fa2j", "mine")], &key, &mut clock)
        .expect("applies");
    let other = second
        .apply(
            &store,
            &[create("3jqfcqzm4fb2j", "theirs")],
            &key,
            &mut clock,
        )
        .expect("applies");

    assert!(
        store
            .commit(
                Some(&from),
                &at(&first),
                stored(&one),
                &[indexed("3jqfcqzm4fa2j", "mine")],
                &blobs(),
            )
            .expect("commits")
            .is_some()
    );
    // The second was worked out against a tree that has moved, so taking it
    // would drop the first write rather than land beside it.
    assert!(
        store
            .commit(
                Some(&from),
                &at(&second),
                stored(&other),
                &[indexed("3jqfcqzm4fb2j", "theirs")],
                &blobs(),
            )
            .expect("answers")
            .is_none()
    );

    assert_eq!(store.root().expect("reads"), Some(at(&first)));
    let collection = "com.example.record".parse::<Nsid>().expect("an NSID");
    assert_eq!(
        store
            .records(&collection, 10, None, false)
            .expect("reads")
            .len(),
        1
    );
}

#[test]
fn a_collection_pages_newest_first_unless_asked_the_other_way() {
    let key = Keypair::generate(Algorithm::Secp256k1);
    let mut clock = TidClock::new();
    let collection = "com.example.record".parse::<Nsid>().expect("an NSID");

    let (mut repo, blocks) = Repo::create(account(), &key, &mut clock).expect("creates");
    let mut store = Actor::memory(account()).expect("opens");
    store
        .commit(None, &at(&repo), genesis(&blocks), &[], &blobs())
        .expect("commits");

    let from = at(&repo);
    let written = repo
        .apply(
            &store,
            &[
                create("3jqfcqzm4fa2j", "first"),
                create("3jqfcqzm4fb2j", "second"),
                create("3jqfcqzm4fc2j", "third"),
                create_in("com.example.other", "3jqfcqzm4fd2j", "elsewhere"),
            ],
            &key,
            &mut clock,
        )
        .expect("applies");
    store
        .commit(
            Some(&from),
            &at(&repo),
            stored(&written),
            &[
                indexed("3jqfcqzm4fa2j", "first"),
                indexed("3jqfcqzm4fb2j", "second"),
                indexed("3jqfcqzm4fc2j", "third"),
                indexed_in("com.example.other", "3jqfcqzm4fd2j", "elsewhere"),
            ],
            &blobs(),
        )
        .expect("commits");

    assert_eq!(
        store.collections().expect("reads"),
        ["com.example.other", "com.example.record"]
            .map(|nsid| nsid.parse::<Nsid>().expect("an NSID"))
    );

    // A TID sorts as time, so the default page is the most recent first and a
    // collection nobody asked about stays out of it.
    let page = store.records(&collection, 10, None, false).expect("reads");
    assert_eq!(
        keys(&page),
        ["3jqfcqzm4fc2j", "3jqfcqzm4fb2j", "3jqfcqzm4fa2j"]
    );

    let page = store.records(&collection, 2, None, false).expect("reads");
    assert_eq!(keys(&page), ["3jqfcqzm4fc2j", "3jqfcqzm4fb2j"]);
    let next = store
        .records(&collection, 2, Some("3jqfcqzm4fb2j"), false)
        .expect("reads");
    assert_eq!(keys(&next), ["3jqfcqzm4fa2j"]);

    let page = store.records(&collection, 10, None, true).expect("reads");
    assert_eq!(
        keys(&page),
        ["3jqfcqzm4fa2j", "3jqfcqzm4fb2j", "3jqfcqzm4fc2j"]
    );
    let next = store
        .records(&collection, 10, Some("3jqfcqzm4fb2j"), true)
        .expect("reads");
    assert_eq!(keys(&next), ["3jqfcqzm4fc2j"]);

    let held = store
        .record(&collection, &"3jqfcqzm4fb2j".parse().expect("a record key"))
        .expect("reads")
        .expect("held");
    assert_eq!(repo::decode::<Ipld>(&held.value), Ok(post("second")));
    assert_eq!(
        store
            .record(&collection, &"3jqfcqzm4fz2j".parse().expect("a record key"))
            .expect("reads"),
        None
    );
}

/// A revision of `count` blocks nothing else points at, rooted at the first
/// of them.
fn revision(store: &mut Actor, from: Option<&Root>, rev: &str, count: usize) -> Root {
    let mut blocks = repo::BlockMap::new();
    let mut first = None;
    for n in 0..count {
        let cid = blocks.add(&post(&format!("{rev}-{n}"))).expect("encodes");
        first.get_or_insert(cid);
    }
    let root = Root {
        cid: first.expect("a block"),
        rev: rev.parse::<Tid>().expect("a TID"),
    };
    store
        .commit(from, &root, genesis(&blocks), &[], &blobs())
        .expect("commits");
    root
}

/// Every block a download would carry, read a page at a time.
fn walked(store: &Actor, since: Option<&Tid>, limit: u32) -> Vec<(repo::Cid, Vec<u8>)> {
    let mut carried = Vec::new();
    let mut from = None;
    loop {
        let page = store
            .blocks_since(since, from.as_ref(), limit)
            .expect("reads");
        carried.extend(page.blocks);
        match page.next {
            Some(mark) => from = Some(mark),
            None => return carried,
        }
    }
}

#[test]
fn a_download_pages_through_every_block_once() {
    let mut store = Actor::memory(account()).expect("opens");
    let first = revision(&mut store, None, "3jqfcqzm4fa2j", 7);
    let second = revision(&mut store, Some(&first), "3jqfcqzm4fb2j", 5);
    revision(&mut store, Some(&second), "3jqfcqzm4fc2j", 9);

    let whole = walked(&store, None, 1000);
    assert_eq!(whole.len(), 21);

    // A page is where the read stops, not what it answers: the same blocks
    // come out in the same order whatever it holds, including the page that
    // ends on the last block.
    for limit in [1, 2, 4, 7, 20, 21] {
        assert_eq!(walked(&store, None, limit), whole, "{limit} to a page");
    }

    // A download since a revision leaves out what that revision wrote, across
    // pages as much as in one.
    let after = walked(&store, Some(&first.rev), 1000);
    assert_eq!(after.len(), 14);
    for limit in [1, 3, 14] {
        assert_eq!(walked(&store, Some(&first.rev), limit), after, "{limit}");
    }
    assert_eq!(walked(&store, Some(&second.rev), 4).len(), 9);
}

#[test]
fn the_blocks_a_caller_names_come_back_across_as_many_reads_as_it_takes() {
    let mut store = Actor::memory(account()).expect("opens");
    // Past the batch a read asks about at once, and not a multiple of it.
    revision(&mut store, None, "3jqfcqzm4fa2j", 1200);
    let held: Vec<repo::Cid> = walked(&store, None, 2000)
        .into_iter()
        .map(|(cid, _)| cid)
        .collect();
    assert_eq!(held.len(), 1200);

    let absent = [
        repo::cid_for(b"nothing is stored under this"),
        repo::cid_for(b"nor under this"),
    ];
    let mut asked = held[..600].to_vec();
    asked.push(absent[0]);
    asked.extend_from_slice(&held[600..]);
    asked.push(absent[1]);
    // A caller naming one twice is answered for it twice.
    asked.push(held[0]);

    let (blocks, missing) = store.blocks(&asked).expect("reads");
    assert_eq!(missing, absent);
    assert_eq!(blocks.len(), held.len());
    for cid in &held {
        assert_eq!(repo::cid_for(&blocks.get(cid).expect("stored")), *cid);
    }
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

/// Where a repository starts, which every account is written with.
fn root() -> Root {
    let mut clock = TidClock::new();
    let key = Keypair::generate(Algorithm::Secp256k1);
    let (repo, _) = Repo::create(account(), &key, &mut clock).expect("creates");
    Root {
        cid: repo.cid(),
        rev: repo.rev().clone(),
    }
}

fn registration(handle: &str, email: &str) -> Registration {
    Registration {
        account: Account {
            did: account(),
            handle: Some(handle.parse().expect("a handle")),
            email: email.to_owned(),
            password_scrypt: "not a real hash".to_owned(),
        },
        root: root(),
        invite: None,
        session: None,
    }
}

#[test]
fn an_account_reads_back_by_did_handle_or_email() {
    let mut accounts = Accounts::memory().expect("opens");
    let registered = registration("alice.example.com", "alice@example.com");
    accounts.create(&registered).expect("creates");

    assert_eq!(
        accounts.by_did(&account()).expect("reads"),
        Some(registered.account.clone())
    );
    assert_eq!(
        accounts
            .by_handle(&"alice.example.com".parse().expect("a handle"))
            .expect("reads"),
        Some(registered.account)
    );
    assert_eq!(
        accounts
            .by_handle(&"bob.example.com".parse().expect("a handle"))
            .expect("reads"),
        None
    );
    // Signing in takes either, and the email is matched the way the index
    // holds it rather than the way it is typed.
    assert!(
        accounts
            .by_email("ALICE@example.com")
            .expect("reads")
            .is_some()
    );
    assert_eq!(accounts.by_email("bob@example.com").expect("reads"), None);
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
    clash.account.did = "did:plc:zzzzzzzzzzzzzzzzzzzzzzzz".parse().expect("a DID");
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
    clash.account.did = "did:plc:zzzzzzzzzzzzzzzzzzzzzzzz".parse().expect("a DID");
    assert!(accounts.create(&clash).is_err());
}

fn session(id: &str, expires_at: &str) -> Session {
    Session {
        id: id.to_owned(),
        did: account(),
        expires_at: expires_at.parse().expect("a timestamp"),
        next_id: None,
        app_password: None,
    }
}

#[test]
fn a_session_reads_back_until_it_is_revoked() {
    let mut accounts = Accounts::memory().expect("opens");
    accounts
        .create(&registration("alice.example.com", "alice@example.com"))
        .expect("creates");
    let opened = session("first", "2026-12-01T00:00:00Z");
    accounts.store_session(&opened).expect("stores");

    assert_eq!(accounts.session("first").expect("reads"), Some(opened));
    assert_eq!(accounts.session("second").expect("reads"), None);
    assert!(accounts.revoke_session("first").expect("revokes"));
    assert!(!accounts.revoke_session("first").expect("revokes"));
    assert_eq!(accounts.session("first").expect("reads"), None);
}

#[test]
fn storing_a_session_again_leaves_the_one_already_there() {
    let mut accounts = Accounts::memory().expect("opens");
    accounts
        .create(&registration("alice.example.com", "alice@example.com"))
        .expect("creates");
    let opened = session("first", "2026-12-01T00:00:00Z");
    accounts.store_session(&opened).expect("stores");
    accounts
        .store_session(&session("first", "2027-12-01T00:00:00Z"))
        .expect("stores");

    assert_eq!(accounts.session("first").expect("reads"), Some(opened));
}

#[test]
fn a_session_names_one_successor_and_refuses_a_second() {
    let mut accounts = Accounts::memory().expect("opens");
    accounts
        .create(&registration("alice.example.com", "alice@example.com"))
        .expect("creates");
    accounts
        .store_session(&session("first", "2026-12-01T00:00:00Z"))
        .expect("stores");
    let grace: jiff::Timestamp = "2026-09-01T02:00:00Z".parse().expect("a timestamp");

    assert!(
        accounts
            .rotate("first", grace, &session("second", "2026-12-01T00:00:00Z"))
            .expect("rotates")
    );
    // The same exchange arriving twice is answered with the same session.
    assert!(
        accounts
            .rotate("first", grace, &session("second", "2026-12-01T00:00:00Z"))
            .expect("rotates")
    );
    assert!(
        !accounts
            .rotate("first", grace, &session("third", "2026-12-01T00:00:00Z"))
            .expect("rotates")
    );

    let held = accounts.session("first").expect("reads").expect("held");
    assert_eq!(held.next_id.as_deref(), Some("second"));
    assert_eq!(held.expires_at, grace);

    // The successor it named exists, and the one it refused does not.
    assert!(accounts.session("second").expect("reads").is_some());
    assert!(accounts.session("third").expect("reads").is_none());
}

#[test]
fn only_the_sessions_that_have_run_out_are_cleared() {
    let mut accounts = Accounts::memory().expect("opens");
    accounts
        .create(&registration("alice.example.com", "alice@example.com"))
        .expect("creates");
    accounts
        .store_session(&session("old", "2026-01-01T00:00:00Z"))
        .expect("stores");
    accounts
        .store_session(&session("current", "2027-01-01T00:00:00Z"))
        .expect("stores");
    let now: jiff::Timestamp = "2026-09-01T00:00:00Z".parse().expect("a timestamp");

    assert_eq!(
        accounts.expire_sessions(&account(), now).expect("clears"),
        1
    );
    assert_eq!(accounts.session("old").expect("reads"), None);
    assert!(accounts.session("current").expect("reads").is_some());
    assert_eq!(accounts.revoke_sessions(&account()).expect("revokes"), 1);
    assert_eq!(accounts.session("current").expect("reads"), None);
}

#[test]
fn an_invite_code_is_spent_until_it_runs_out() {
    let mut accounts = Accounts::memory().expect("opens");
    accounts
        .create(&registration("alice.example.com", "alice@example.com"))
        .expect("creates");
    accounts
        .create_invites(&["code-one".to_owned()], account().as_str(), "admin", 2)
        .expect("writes");

    assert!(accounts.invite_available("code-one").expect("reads"));
    assert!(!accounts.invite_available("code-two").expect("reads"));

    let first: Did = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa".parse().expect("a DID");
    let second: Did = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb".parse().expect("a DID");
    accounts.spend_invite("code-one", &first).expect("spends");
    assert!(accounts.invite_available("code-one").expect("reads"));
    accounts.spend_invite("code-one", &second).expect("spends");
    assert!(!accounts.invite_available("code-one").expect("reads"));

    // One account cannot spend the same code twice, which the key enforces
    // rather than the count.
    assert!(accounts.spend_invite("code-one", &first).is_err());
}

#[test]
fn a_code_that_was_disabled_or_taken_down_with_its_account_is_not_available() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let path = home.path().join("account.sqlite");
    let mut accounts = Accounts::open(&path).expect("opens");
    accounts
        .create(&registration("alice.example.com", "alice@example.com"))
        .expect("creates");
    accounts
        .create_invites(
            &["disabled".to_owned(), "held".to_owned()],
            account().as_str(),
            "admin",
            1,
        )
        .expect("writes");
    let db = Connection::open(&path).expect("opens");

    db.execute(
        r#"update "invite_code" set "disabled" = 1 where "code" = 'disabled'"#,
        [],
    )
    .expect("writes");
    assert!(!accounts.invite_available("disabled").expect("reads"));

    assert!(accounts.invite_available("held").expect("reads"));
    db.execute(r#"update "actor" set "takedownRef" = 'held'"#, [])
        .expect("writes");
    assert!(!accounts.invite_available("held").expect("reads"));
}

#[test]
fn an_app_password_is_found_by_its_hash_and_revoked_by_its_name() {
    let mut accounts = Accounts::memory().expect("opens");
    accounts
        .create(&registration("alice.example.com", "alice@example.com"))
        .expect("creates");
    let password = AppPassword {
        name: "phone".to_owned(),
        privileged: false,
    };
    accounts
        .create_app_password(&account(), &password, "a hash")
        .expect("writes");

    assert_eq!(
        accounts.app_password(&account(), "a hash").expect("reads"),
        Some(password.clone())
    );
    assert_eq!(
        accounts
            .app_password(&account(), "another hash")
            .expect("reads"),
        None
    );

    let held = accounts.app_passwords(&account()).expect("reads");
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].0, password);

    // A session opened with it goes when it does, which is the only way a
    // client holding one is shut out.
    accounts
        .store_session(&Session {
            app_password: Some(password),
            ..session("phone session", "2027-01-01T00:00:00Z")
        })
        .expect("stores");
    assert!(
        accounts
            .revoke_app_password(&account(), "phone")
            .expect("revokes")
    );
    assert_eq!(accounts.session("phone session").expect("reads"), None);
    assert_eq!(
        accounts.app_passwords(&account()).expect("reads"),
        Vec::new()
    );
    assert!(
        !accounts
            .revoke_app_password(&account(), "phone")
            .expect("revokes")
    );
}

#[test]
fn a_session_carries_what_its_app_password_may_do_now() {
    let mut accounts = Accounts::memory().expect("opens");
    accounts
        .create(&registration("alice.example.com", "alice@example.com"))
        .expect("creates");
    let password = AppPassword {
        name: "phone".to_owned(),
        privileged: true,
    };
    accounts
        .create_app_password(&account(), &password, "a hash")
        .expect("writes");
    accounts
        .store_session(&Session {
            app_password: Some(AppPassword {
                name: "phone".to_owned(),
                privileged: false,
            }),
            ..session("phone session", "2027-01-01T00:00:00Z")
        })
        .expect("stores");

    // The row holds only the name, so what it reaches is read from the
    // password rather than from whatever was true when the session opened.
    let held = accounts
        .session("phone session")
        .expect("reads")
        .expect("held");
    assert_eq!(held.app_password, Some(password));
}

#[test]
fn a_database_migrated_past_the_account_schema_is_refused() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let path = home.path().join("account.sqlite");
    Accounts::open(&path).expect("opens");

    Connection::open(&path)
        .expect("opens")
        .execute(
            r#"insert into "kysely_migration" ("name", "timestamp") values ('008', '')"#,
            [],
        )
        .expect("writes");

    let refused = Accounts::open(&path);
    assert!(
        matches!(refused, Err(Error::TooNew(ref name)) if name == "008"),
        "{refused:?}"
    );
}

#[test]
fn a_blob_is_stored_under_the_cid_of_its_bytes() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let blobs = Directory::new(home.path()).blobs();
    let bytes = b"not really a picture";
    let cid = blobs::cid_for(bytes);

    // An upload holds nothing, so it is not yet served from its own name.
    blobs
        .put(&account(), "somekey", &cid, bytes)
        .expect("stores");
    assert!(!blobs.has(&account(), &cid));

    // A record claiming it is what puts it where it is served from, and the
    // upload stays until that commit is on disk.
    blobs.claim(&account(), "somekey", &cid).expect("claims");
    assert!(blobs.has(&account(), &cid));
    assert_eq!(blobs.get(&account(), &cid).expect("reads"), bytes);
    blobs
        .claim(&account(), "somekey", &cid)
        .expect("claiming twice is claiming once");
    blobs
        .delete_upload(&account(), "somekey")
        .expect("clears the upload");
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

    assert!(
        blobs
            .put(&account(), "somekey", &cid, b"another thing")
            .is_err()
    );
    assert!(!blobs.has(&account(), &cid));
}

#[test]
fn quarantine_hides_a_blob_without_losing_it() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let blobs = Directory::new(home.path()).blobs();
    let bytes = b"not really a picture";
    let cid = blobs::cid_for(bytes);
    blobs
        .put(&account(), "somekey", &cid, bytes)
        .expect("stores");
    blobs.claim(&account(), "somekey", &cid).expect("claims");

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

#[test]
fn a_signing_key_survives_the_file_it_is_kept_in() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let path = Directory::new(home.path()).actor_key(&account());
    let keypair = Keypair::generate(Algorithm::Secp256k1);

    keys::write(&path, &keypair).expect("writes");
    let read = keys::read(&path).expect("reads");
    assert_eq!(read.public_key(), keypair.public_key());

    // The reference writes 32 raw bytes and nothing else.
    assert_eq!(std::fs::read(&path).expect("reads").len(), 32);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path)
            .expect("reads")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "nobody else reads a signing key");
    }
}

/// The schema a database ends up with, in the form the fixtures hold.
fn schema(path: &std::path::Path) -> Vec<String> {
    let db = Connection::open(path).expect("opens");
    let mut objects: Vec<String> = db
        .prepare(r#"select "sql" from "sqlite_master" where "sql" is not null"#)
        .expect("prepares")
        .query_map([], |row| row.get::<_, String>(0))
        .expect("queries")
        .collect::<Result<_, _>>()
        .expect("reads");
    objects.retain(|sql| !sql.starts_with("CREATE TABLE sqlite_sequence"));
    objects.sort();
    objects
}

fn reference_schema(name: &str) -> Vec<String> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/schema")
        .join(format!("{name}.sql"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    // `.schema` ends each statement with a semicolon; `sqlite_master` does not.
    let mut objects: Vec<String> = text
        .lines()
        .map(|line| line.trim_end_matches(';').to_owned())
        .collect();
    objects.sort();
    objects
}

#[test]
fn every_schema_is_the_one_the_reference_builds() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let at = |name: &str| home.path().join(format!("{name}.sqlite"));

    Actor::open(&at("actor"), account()).expect("opens");
    Sequencer::open(&at("sequencer")).expect("opens");
    DidCache::open(&at("did_cache")).expect("opens");
    Accounts::open(&at("account")).expect("opens");
    for name in ["actor", "sequencer", "did_cache", "account"] {
        assert_eq!(schema(&at(name)), reference_schema(name), "{name}");
    }
}

#[test]
fn a_signing_key_is_never_written_over() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let path = home
        .path()
        .join("actors")
        .join("aa")
        .join("did")
        .join("key");
    let keypair = Keypair::generate(Algorithm::Secp256k1);
    keys::write(&path, &keypair).expect("writes");

    let second = Keypair::generate(Algorithm::Secp256k1);
    keys::write(&path, &second).expect_err("a key is written once");
    assert_eq!(
        keys::read(&path).expect("reads").to_bytes(),
        keypair.to_bytes()
    );
}

#[cfg(unix)]
#[test]
fn nothing_under_the_data_directory_is_open_to_anyone_else() {
    use std::os::unix::fs::PermissionsExt;

    let home = tempfile::tempdir().expect("a temporary directory");
    let directory = Directory::new(home.path().join("data"));
    Accounts::open(&directory.accounts()).expect("opens");

    let mode = |path: &std::path::Path| {
        std::fs::metadata(path)
            .expect("a directory")
            .permissions()
            .mode()
            & 0o777
    };
    assert_eq!(mode(home.path().join("data").as_path()), 0o700);
}

/// Builds a database where the reference left one: schema at 004, ledger
/// stamped to match, and whatever rows the caller wants in it.
fn account_database_at_004(path: &Path, rows: &str) {
    let schema = include_str!("fixtures/schema/account-004.sql");
    let db = Connection::open(path).expect("opens");
    // The fixture is sorted for comparing, so the indexes come before the
    // tables they are on.
    for kind in ["CREATE TABLE", "CREATE INDEX", "CREATE UNIQUE INDEX"] {
        for line in schema.lines().filter(|line| line.starts_with(kind)) {
            db.execute_batch(&format!("{line};")).expect("the schema");
        }
    }
    db.execute_batch(
        r#"create table if not exists "kysely_migration" ("name" varchar(255) not null primary key, "timestamp" varchar(255) not null);
           insert into "kysely_migration" ("name", "timestamp") values
             ('001', ''), ('002', ''), ('003', ''), ('004', '');"#,
    )
    .expect("the ledger");
    db.execute_batch(rows).expect("the rows");
}

#[test]
fn the_migration_that_replaces_device_sessions_carries_the_right_ones() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let path = home.path().join("account.sqlite");
    let long_ago = "2020-01-01T00:00:00.000Z";
    let recent = format!("{:.3}", jiff::Timestamp::now());

    account_database_at_004(
        &path,
        &format!(
            r#"
            insert into "account" ("did", "email", "passwordScrypt", "invitesDisabled") values
              ('did:plc:kept', 'kept@example.com', 'x', 0),
              ('did:plc:forgotten', 'forgotten@example.com', 'x', 0);
            insert into "device" ("id", "sessionId", "ipAddress", "lastSeenAt") values
              ('dev-1', 's1', '1.2.3.4', '{recent}'),
              ('dev-2', 's2', '1.2.3.4', '{recent}'),
              ('dev-3', 's3', '1.2.3.4', '{recent}'),
              ('dev-4', 's4', '1.2.3.4', '{recent}');
            insert into "device_account" ("did", "deviceId", "authenticatedAt", "remember", "authorizedClients") values
              ('did:plc:kept', 'dev-1', '{recent}', 1, '[]'),
              ('did:plc:gone', 'dev-2', '{recent}', 1, '[]'),
              ('did:plc:forgotten', 'dev-3', '{recent}', 0, '[]'),
              ('did:plc:forgotten', 'dev-4', '{long_ago}', 0, '[]');
            "#
        ),
    );

    Accounts::open(&path).expect("migrates the rest of the way");

    let db = Connection::open(&path).expect("opens");
    let carried: Vec<String> = db
        .prepare(r#"select "did" || '/' || "deviceId" from "account_device" order by "deviceId""#)
        .expect("a statement")
        .query_map([], |row| row.get(0))
        .expect("rows")
        .collect::<Result<_, _>>()
        .expect("rows");
    // Only the remembered session of an account still here: the one belonging
    // to nobody would not satisfy the foreign key the new table carries.
    assert_eq!(carried, ["did:plc:kept/dev-1"]);

    let left: Vec<String> = db
        .prepare(r#"select "deviceId" from "device_account" order by "deviceId""#)
        .expect("a statement")
        .query_map([], |row| row.get(0))
        .expect("rows")
        .collect::<Result<_, _>>()
        .expect("rows");
    // The session nobody asked to remember is gone once it is an hour old.
    assert_eq!(left, ["dev-1", "dev-2", "dev-3"]);

    // And a database taken over at 004 ends up shaped like one built here
    // from nothing, which the route through 005 could otherwise miss.
    drop(db);
    assert_eq!(schema(&path), reference_schema("account"));
}

#[test]
fn an_account_comes_in_on_its_code_and_leaves_with_its_session() {
    let mut accounts = Accounts::memory().expect("opens");
    accounts
        .create_invites(&["pds-test-aaaaa-bbbbb".to_owned()], "admin", "admin", 1)
        .expect("writes the code");

    let mut registered = registration("alice.example.com", "alice@example.com");
    registered.invite = Some("pds-test-aaaaa-bbbbb".to_owned());
    registered.session = Some(session("a session", "2030-01-01T00:00:00.000Z"));
    accounts.create(&registered).expect("creates");

    assert!(
        !accounts
            .invite_available("pds-test-aaaaa-bbbbb")
            .expect("reads")
    );
    assert!(accounts.session("a session").expect("reads").is_some());
    assert_eq!(
        accounts.by_did(&account()).expect("reads"),
        Some(registered.account)
    );
}

#[test]
fn a_code_with_nothing_left_takes_the_account_down_with_it() {
    let mut accounts = Accounts::memory().expect("opens");

    let mut registered = registration("alice.example.com", "alice@example.com");
    registered.invite = Some("pds-test-aaaaa-bbbbb".to_owned());
    assert!(matches!(
        accounts.create(&registered),
        Err(Error::InviteUnavailable)
    ));

    // The code was checked inside the write, so nothing else in it landed
    // either.
    assert_eq!(accounts.by_did(&account()).expect("reads"), None);
}

#[test]
fn deleting_an_account_takes_everything_hanging_off_it() {
    let mut accounts = Accounts::memory().expect("opens");
    let mut registered = registration("alice.example.com", "alice@example.com");
    registered.session = Some(session("a session", "2030-01-01T00:00:00.000Z"));
    accounts.create(&registered).expect("creates");
    accounts
        .create_app_password(
            &account(),
            &AppPassword {
                name: "phone".to_owned(),
                privileged: false,
            },
            "not a real hash",
        )
        .expect("writes");

    accounts.delete(&account()).expect("deletes");

    assert_eq!(accounts.by_did(&account()).expect("reads"), None);
    assert_eq!(accounts.session("a session").expect("reads"), None);
    assert_eq!(
        accounts.app_passwords(&account()).expect("reads"),
        Vec::new()
    );
    // And the handle is free again, which is the point of undoing a signup.
    accounts.create(&registered).expect("creates again");
}

#[test]
fn a_handle_lost_to_a_race_is_named_as_taken() {
    let mut accounts = Accounts::memory().expect("opens");
    accounts
        .create(&registration("alice.test", "alice@example.com"))
        .expect("the first account");

    let mut second = registration("ALICE.test", "bob@example.com");
    second.account.did = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb".parse().expect("a did");

    assert!(matches!(
        accounts.create(&second).expect_err("a clash"),
        Error::HandleTaken
    ));
}

#[test]
fn an_email_lost_to_a_race_is_named_as_taken() {
    let mut accounts = Accounts::memory().expect("opens");
    accounts
        .create(&registration("alice.test", "alice@example.com"))
        .expect("the first account");

    let mut second = registration("bob.test", "ALICE@example.com");
    second.account.did = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb".parse().expect("a did");

    assert!(matches!(
        accounts.create(&second).expect_err("a clash"),
        Error::EmailTaken
    ));
}

#[test]
fn a_stored_blob_leaves_nothing_beside_it_and_no_way_in() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let blobs = Directory::new(home.path()).blobs();
    let bytes = b"a blob, written whole or not at all";
    let cid = blobs::cid_for(bytes);
    blobs
        .put(&account(), "somekey", &cid, bytes)
        .expect("stores");
    blobs.claim(&account(), "somekey", &cid).expect("claims");

    let path = blobs.path(&account(), &cid);
    let parent = path.parent().expect("a parent");
    let held: Vec<_> = std::fs::read_dir(parent)
        .expect("reads")
        .map(|entry| entry.expect("an entry").file_name())
        .collect();
    assert_eq!(held, [path.file_name().expect("a name")]);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(parent)
            .expect("reads")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700, "{mode:o}");
    }
}

#[test]
fn a_blob_that_cannot_be_put_in_place_leaves_nothing_behind() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let blobs = Directory::new(home.path()).blobs();
    let bytes = b"a blob that never lands";
    let cid = blobs::cid_for(bytes);

    // Something already occupies the name, and is not a file, so the move onto
    // it cannot succeed.
    let path = blobs.temp_path(&account(), "somekey");
    std::fs::create_dir_all(&path).expect("a directory in the way");

    blobs
        .put(&account(), "somekey", &cid, bytes)
        .expect_err("cannot land");

    let parent = path.parent().expect("a parent");
    let held: Vec<_> = std::fs::read_dir(parent)
        .expect("reads")
        .map(|entry| entry.expect("an entry").file_name())
        .collect();
    assert_eq!(held, [path.file_name().expect("a name")]);
}

#[test]
fn an_upload_file_outlives_its_row_only_as_long_as_the_window() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let blobs = Directory::new(home.path()).blobs();
    blobs
        .put(&account(), "heldkey", &blobs::cid_for(b"held"), b"held")
        .expect("stores");
    blobs
        .put(
            &account(),
            "strandedkey",
            &blobs::cid_for(b"loose"),
            b"loose",
        )
        .expect("stores");
    let held = std::collections::HashSet::from(["heldkey".to_owned()]);

    // An upload arrives before the row naming it, so one written since the
    // cutoff is not the sweep's to take.
    assert_eq!(
        blobs
            .sweep_uploads(
                &account(),
                &held,
                jiff::Timestamp::now() - jiff::SignedDuration::from_hours(1)
            )
            .expect("sweeps"),
        Vec::<String>::new()
    );
    assert!(blobs.temp_path(&account(), "strandedkey").is_file());

    assert_eq!(
        blobs
            .sweep_uploads(
                &account(),
                &held,
                jiff::Timestamp::now() + jiff::SignedDuration::from_hours(1)
            )
            .expect("sweeps"),
        vec!["strandedkey".to_owned()]
    );
    assert!(blobs.temp_path(&account(), "heldkey").is_file());
    assert!(!blobs.temp_path(&account(), "strandedkey").exists());
}

#[test]
fn a_sweep_of_an_account_that_has_uploaded_nothing_finds_nothing() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let blobs = Directory::new(home.path()).blobs();
    assert_eq!(
        blobs
            .sweep_uploads(
                &account(),
                &std::collections::HashSet::new(),
                jiff::Timestamp::now() + jiff::SignedDuration::from_hours(1)
            )
            .expect("sweeps"),
        Vec::<String>::new()
    );
}

#[test]
fn every_key_an_upload_is_held_under_is_named() {
    let store = Actor::memory(account()).expect("opens");
    let blob = Blob {
        cid: blobs::cid_for(b"held"),
        mime: "image/png".to_owned(),
        size: 4,
    };
    store.add_blob(&blob, "firstkey").expect("writes");
    assert_eq!(
        store.upload_keys().expect("reads"),
        std::collections::HashSet::from(["firstkey".to_owned()])
    );

    // A second upload of the same bytes moves the row, and the key it moved
    // off is what nothing names any more.
    store.add_blob(&blob, "secondkey").expect("writes again");
    assert_eq!(
        store.upload_keys().expect("reads"),
        std::collections::HashSet::from(["secondkey".to_owned()])
    );
}

#[test]
fn a_blob_nothing_ever_named_is_swept_and_one_a_record_holds_is_not() {
    let store = Actor::memory(account()).expect("opens");
    let held = Blob {
        cid: manapds::store::blobs::cid_for(b"held"),
        mime: "image/png".to_owned(),
        size: 4,
    };
    let loose = Blob {
        cid: manapds::store::blobs::cid_for(b"loose"),
        mime: "image/png".to_owned(),
        size: 5,
    };
    // Both uploaded, so a record claiming one has something to claim.
    let home = tempfile::tempdir().expect("a temporary directory");
    let blobs = Directory::new(home.path()).blobs();
    blobs
        .put(&account(), "heldkey", &held.cid, b"held")
        .expect("stores");
    blobs
        .put(&account(), "loosekey", &loose.cid, b"loose")
        .expect("stores");
    store.add_blob(&held, "heldkey").expect("writes");
    store.add_blob(&loose, "loosekey").expect("writes");

    // Nothing is old enough yet, which is what the window is for.
    assert_eq!(
        store
            .sweep_unclaimed(jiff::Timestamp::now() - jiff::SignedDuration::from_hours(1))
            .expect("sweeps"),
        Vec::<String>::new()
    );

    // One of them is claimed by a record, the way a write claims it.
    let key = Keypair::generate(Algorithm::Secp256k1);
    let mut clock = TidClock::new();
    let (repo, blocks) = Repo::create(account(), &key, &mut clock).expect("creates");
    let mut store = store;
    store
        .commit(
            None,
            &at(&repo),
            genesis(&blocks),
            &[Indexed::Put {
                collection: "com.example.record".parse().expect("an NSID"),
                rkey: "3jqfcqzm4fc2j".parse().expect("a record key"),
                cid: repo::cid_for(&repo::encode(&post("first")).expect("encodes")),
                links: Vec::new(),
                blobs: vec![held.clone()],
            }],
            &blobs,
        )
        .expect("commits");

    let waited = jiff::Timestamp::now() + jiff::SignedDuration::from_hours(1);
    assert_eq!(
        store.sweep_unclaimed(waited).expect("sweeps"),
        vec!["loosekey".to_owned()]
    );
    store.add_blob(&loose, "loosekey").expect("writes again");
    assert_eq!(
        store
            .sweep_unclaimed(jiff::Timestamp::now() - jiff::SignedDuration::from_hours(1))
            .expect("sweeps"),
        Vec::<String>::new()
    );

    // Past the window, the one nothing named goes and the held one stays.
    let swept = store
        .sweep_unclaimed(jiff::Timestamp::now() + jiff::SignedDuration::from_hours(1))
        .expect("sweeps");
    assert_eq!(swept, vec!["loosekey".to_owned()]);
    assert_eq!(store.blob(&held.cid).expect("reads"), Some(held));
    assert_eq!(store.blob(&loose.cid).expect("reads"), None);
}

#[test]
fn a_commit_hands_back_the_uploads_it_took_and_the_blobs_it_let_go() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let blobs = Directory::new(home.path()).blobs();
    let blob = Blob {
        cid: manapds::store::blobs::cid_for(b"held"),
        mime: "image/png".to_owned(),
        size: 4,
    };
    blobs
        .put(&account(), "heldkey", &blob.cid, b"held")
        .expect("stores");

    let mut store = Actor::memory(account()).expect("opens");
    store.add_blob(&blob, "heldkey").expect("writes");

    let key = Keypair::generate(Algorithm::Secp256k1);
    let mut clock = TidClock::new();
    let (repo, blocks) = Repo::create(account(), &key, &mut clock).expect("creates");
    let rkey = "3jqfcqzm4fc2j".parse().expect("a record key");
    let collection = "com.example.record".parse().expect("an NSID");
    let taken = store
        .commit(
            None,
            &at(&repo),
            genesis(&blocks),
            &[Indexed::Put {
                collection,
                rkey,
                cid: repo::cid_for(&repo::encode(&post("first")).expect("encodes")),
                links: Vec::new(),
                blobs: vec![blob.clone()],
            }],
            &blobs,
        )
        .expect("commits")
        .expect("lands");

    // Without these the upload's name is never dropped, and because it is a
    // link to the same bytes the blob is served from, nothing can free them.
    assert_eq!(taken.taken, vec!["heldkey".to_owned()]);
    assert_eq!(taken.orphaned, []);

    let let_go = store
        .commit(
            Some(&at(&repo)),
            &at(&repo),
            genesis(&blocks),
            &[Indexed::Delete {
                collection: "com.example.record".parse().expect("an NSID"),
                rkey: "3jqfcqzm4fc2j".parse().expect("a record key"),
            }],
            &blobs,
        )
        .expect("commits")
        .expect("lands");

    assert_eq!(let_go.orphaned, vec![blob.cid]);
}

#[test]
fn a_record_that_names_no_collection_is_refused_before_it_can_be_a_node() {
    let key = Keypair::generate(Algorithm::Secp256k1);
    let mut clock = TidClock::new();
    let (mut repo, blocks) = Repo::create(account(), &key, &mut clock).expect("creates");
    let mut store = Actor::memory(account()).expect("opens");
    store
        .commit(None, &at(&repo), genesis(&blocks), &[], &blobs())
        .expect("commits");

    // A record shaped like a node of the tree holding it. Taking one in would
    // let a later delete of it take the node, and nothing downstream could
    // tell the two apart.
    for shape in [
        Ipld::Map(BTreeMap::from([
            ("e".to_owned(), Ipld::List(Vec::new())),
            ("l".to_owned(), Ipld::Null),
        ])),
        Ipld::Map(BTreeMap::from([(
            "text".to_owned(),
            Ipld::String("no type at all".to_owned()),
        )])),
        Ipld::Map(BTreeMap::from([(
            "$type".to_owned(),
            Ipld::String("com.example.other".to_owned()),
        )])),
    ] {
        let refused = repo.apply(
            &store,
            &[Write::Create {
                collection: "com.example.record".parse().expect("an NSID"),
                rkey: "3jqfcqzm4fa2j".parse().expect("a record key"),
                record: shape,
            }],
            &key,
            &mut clock,
        );
        assert!(refused.is_err(), "took a record naming no collection");
    }
}

#[test]
fn a_read_sees_one_revision_even_while_another_lands() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let path = Directory::new(home.path()).actor_store(&account());
    let key = Keypair::generate(Algorithm::Secp256k1);
    let mut clock = TidClock::new();

    let (mut repo, blocks) = Repo::create(account(), &key, &mut clock).expect("creates");
    let mut store = Actor::open(&path, account()).expect("opens");
    store
        .commit(None, &at(&repo), genesis(&blocks), &[], &blobs())
        .expect("commits");
    let before = at(&repo);

    // A second handle on the same file, which is what a reader and a writer
    // are: the write lands partway through the read's two queries.
    let reader = Actor::open(&path, account()).expect("opens again");
    let held = reader
        .reading(|reader| {
            let root = reader.root()?.expect("a root");

            let written = repo
                .apply(
                    &store,
                    &[create("3jqfcqzm4fa2j", "first")],
                    &key,
                    &mut clock,
                )
                .expect("applies");
            store
                .commit(
                    Some(&before),
                    &at(&repo),
                    stored(&written),
                    &[indexed("3jqfcqzm4fa2j", "first")],
                    &blobs(),
                )
                .expect("commits");

            // Still the revision the read opened on, not the one that landed.
            Ok::<_, manapds::store::Error>((root, reader.root()?.expect("a root")))
        })
        .expect("reads");

    assert_eq!(held.0.cid, held.1.cid);
    assert_eq!(held.0.cid, before.cid);
    assert_ne!(at(&repo).cid, before.cid);
}

#[test]
fn a_download_seeks_to_its_page_rather_than_walking_to_it() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let path = Directory::new(home.path()).actor_store(&account());
    Actor::open(&path, account()).expect("opens");

    // The planner is what this is about, so ask it. A predicate handed in on
    // every call is a filter over the whole index; one that is only there when
    // it has a value is a range the index can start at.
    let db = Connection::open(&path).expect("opens");
    for (what, query) in [
        (
            "a page after the first",
            r#"select "cid" from "repo_block" where ("repoRev", "cid") < (?1, ?2)
               order by "repoRev" desc, "cid" desc limit 500"#,
        ),
        (
            "a page of a download since a revision",
            r#"select "cid" from "repo_block" where "repoRev" > ?1
               and ("repoRev", "cid") < (?2, ?3)
               order by "repoRev" desc, "cid" desc limit 500"#,
        ),
    ] {
        let mut statement = db
            .prepare(&format!("explain query plan {query}"))
            .expect("prepares");
        let count = statement.parameter_count();
        let binds: Vec<String> = (0..count).map(|_| String::new()).collect();
        let plan: String = statement
            .query_row(rusqlite::params_from_iter(&binds), |row| row.get(3))
            .expect("a plan");
        assert!(plan.contains("SEARCH"), "{what}: {plan}");
        assert!(!plan.contains("SCAN"), "{what}: {plan}");
    }
}
