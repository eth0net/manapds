//! Opening a database and bringing it to the schema this server reads.

use std::path::Path;

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use super::Error;

/// The ledger the reference's migrator keeps. Writing it is what lets that
/// server open the same file and agree it is already migrated.
const LEDGER: &str = r#"
create table if not exists "kysely_migration" ("name" varchar(255) not null primary key, "timestamp" varchar(255) not null);
create table if not exists "kysely_migration_lock" ("id" varchar(255) not null primary key, "is_locked" integer default 0 not null);
insert or ignore into "kysely_migration_lock" ("id", "is_locked") values ('migration_lock', 0);
"#;

/// How long to wait for another writer before giving up.
const BUSY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// One migration: the name the ledger records it under, and what it does. Most
/// are a batch of DDL, but one has data to carry across as well.
pub(super) type Migration = (
    &'static str,
    fn(&rusqlite::Transaction) -> Result<(), Error>,
);

/// Opens a database file, making its directory if it is not there.
pub(super) fn open(path: &Path, migrations: &[Migration]) -> Result<Connection, Error> {
    if let Some(parent) = path.parent() {
        super::directory(parent)?;
    }
    prepare(Connection::open(path)?, migrations)
}

/// A database held in memory, which is what tests want and nothing else does.
pub(super) fn memory(migrations: &[Migration]) -> Result<Connection, Error> {
    prepare(Connection::open_in_memory()?, migrations)
}

fn prepare(db: Connection, migrations: &[Migration]) -> Result<Connection, Error> {
    db.busy_timeout(BUSY_TIMEOUT)?;
    // Changing the journal mode wants the database to itself, and one already
    // in WAL wants nothing changed, so it is read before it is written.
    let journal: String = db.query_row("pragma journal_mode", [], |row| row.get(0))?;
    if !journal.eq_ignore_ascii_case("wal") {
        waiting(|| db.pragma_update(None, "journal_mode", "WAL"))?;
    }
    // SQLite leaves these off per connection and the reference never asks for
    // them, but better-sqlite3 turns them on as it opens, so the cascades the
    // schema declares do fire over there.
    db.pragma_update(None, "foreign_keys", "ON")?;
    let mut db = db;
    migrate(&mut db, migrations)?;
    Ok(db)
}

/// Applies whatever the ledger says is outstanding, and refuses a database
/// that has been taken somewhere this server cannot follow.
///
/// A database already at the schema is opened without a single write, which is
/// what makes opening one per call affordable: every write here takes the lock
/// that every other connection is waiting on.
fn migrate(db: &mut Connection, migrations: &[Migration]) -> Result<(), Error> {
    if holds_ledger(db)? && outstanding(&applied(db)?, migrations)?.is_empty() {
        return Ok(());
    }

    // Anything left to do is done holding the write lock, and what is left is
    // worked out again inside it: two connections opening one new file would
    // otherwise both find the same migration outstanding and both run it.
    let stamp = format!("{:.3}", jiff::Timestamp::now());
    let transaction = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(LEDGER)?;
    let applied = applied(&transaction)?;
    for name in outstanding(&applied, migrations)? {
        let apply = migrations
            .iter()
            .find_map(|(known, apply)| (*known == name).then_some(apply))
            .expect("the name came from this list");
        apply(&transaction)?;
        transaction.execute(
            r#"insert into "kysely_migration" ("name", "timestamp") values (?1, ?2)"#,
            params![name, stamp],
        )?;
    }
    transaction.commit()?;
    Ok(())
}

/// Every migration the ledger records, in the order it records them.
fn applied(db: &Connection) -> Result<Vec<String>, Error> {
    Ok(db
        .prepare(r#"select "name" from "kysely_migration" order by "name""#)?
        .query_map([], |row| row.get(0))?
        .collect::<Result<_, _>>()?)
}

/// The ones this server still owes the file, refusing one it has never heard
/// of rather than writing under a schema somebody else moved on.
fn outstanding(applied: &[String], migrations: &[Migration]) -> Result<Vec<&'static str>, Error> {
    if let Some(unknown) = applied
        .iter()
        .find(|name| !migrations.iter().any(|(known, _)| known == name))
    {
        return Err(Error::TooNew(unknown.clone()));
    }
    Ok(migrations
        .iter()
        .map(|(name, _)| *name)
        .filter(|name| !applied.iter().any(|done| done == name))
        .collect())
}

/// Runs something that wants the database to itself, which a busy timeout does
/// not cover: the pragma that sets the journal mode refuses rather than waits.
fn waiting(mut work: impl FnMut() -> rusqlite::Result<()>) -> Result<(), Error> {
    let until = std::time::Instant::now() + BUSY_TIMEOUT;
    loop {
        match work() {
            Ok(()) => return Ok(()),
            Err(error) => {
                let busy = matches!(
                    error.sqlite_error_code(),
                    Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
                );
                if !busy || std::time::Instant::now() >= until {
                    return Err(error.into());
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        }
    }
}

/// Whether the ledger is there to be read, asked without writing it.
fn holds_ledger(db: &Connection) -> Result<bool, Error> {
    Ok(db
        .query_row(
            r#"select 1 from "sqlite_master" where "type" = 'table' and "name" = 'kysely_migration'"#,
            [],
            |_| Ok(true),
        )
        .optional()?
        .unwrap_or(false))
}
