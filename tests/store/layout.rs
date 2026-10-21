//! Where the files go, what the ledger says, and what opening one twice does.

use super::*;

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
        .join("fixtures/schema")
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

/// Builds a database where the reference left one: schema at 004, ledger
/// stamped to match, and whatever rows the caller wants in it.
fn account_database_at_004(path: &Path, rows: &str) {
    let schema = include_str!("../../fixtures/schema/account-004.sql");
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
    assert_eq!(
        applied,
        ["001", "002", "003", "004", "005", "006", "007", "008"]
    );

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
fn a_database_migrated_past_the_account_schema_is_refused() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let path = home.path().join("account.sqlite");
    Accounts::open(&path).expect("opens");

    Connection::open(&path)
        .expect("opens")
        .execute(
            r#"insert into "kysely_migration" ("name", "timestamp") values ('009', '')"#,
            [],
        )
        .expect("writes");

    let refused = Accounts::open(&path);
    assert!(
        matches!(refused, Err(Error::TooNew(ref name)) if name == "009"),
        "{refused:?}"
    );
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
fn the_marker_is_there_afterwards_only_where_the_server_did_not_stop() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let directory = Directory::new(home.path().join("data"));

    let (running, held) = Running::take(&directory).expect("takes the marker");
    assert!(!held, "nothing has run here");
    assert!(directory.running().is_file());
    drop(running);
    assert!(!directory.running().exists());

    let (running, held) = Running::take(&directory).expect("takes the marker");
    assert!(!held);
    // What a process that is killed leaves, since nothing of its runs.
    std::mem::forget(running);
    let (_running, held) = Running::take(&directory).expect("takes the marker");
    assert!(held);
}
