//! Storage, against the layout and the ledger the reference leaves behind.

use std::collections::BTreeMap;
use std::path::Path;

use manapds::crypto::{Algorithm, Keypair};
use manapds::repo::{Ipld, Repo, Store, Write};
use manapds::store::{
    Account, Accounts, Actor, DidCache, Directory, Error, Event, Root, Sequencer, Session,
};
use manapds::store::{blobs, keys};
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
fn an_account_reads_back_by_did_handle_or_email() {
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
            .hold_session("first", grace, "second")
            .expect("holds")
    );
    // The same exchange arriving twice is answered with the same session.
    assert!(
        accounts
            .hold_session("first", grace, "second")
            .expect("holds")
    );
    assert!(
        !accounts
            .hold_session("first", grace, "third")
            .expect("holds")
    );

    let held = accounts.session("first").expect("reads").expect("held");
    assert_eq!(held.next_id.as_deref(), Some("second"));
    assert_eq!(held.expires_at, grace);
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
        .create_invites(&["code-one".to_owned()], &account(), "admin", 2)
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
            &account(),
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
