//! Opening a database and bringing it to the schema this server reads.

use std::path::Path;

use rusqlite::{Connection, params};

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
    db.pragma_update(None, "journal_mode", "WAL")?;
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
fn migrate(db: &mut Connection, migrations: &[Migration]) -> Result<(), Error> {
    db.execute_batch(LEDGER)?;
    let applied: Vec<String> = db
        .prepare(r#"select "name" from "kysely_migration" order by "name""#)?
        .query_map([], |row| row.get(0))?
        .collect::<Result<_, _>>()?;

    if let Some(unknown) = applied
        .iter()
        .find(|name| !migrations.iter().any(|(known, _)| known == name))
    {
        return Err(Error::TooNew(unknown.clone()));
    }

    let stamp = format!("{:.3}", jiff::Timestamp::now());
    let transaction = db.transaction()?;
    for (name, apply) in migrations {
        if applied.iter().any(|done| done == name) {
            continue;
        }
        apply(&transaction)?;
        transaction.execute(
            r#"insert into "kysely_migration" ("name", "timestamp") values (?1, ?2)"#,
            params![name, stamp],
        )?;
    }
    transaction.commit()?;
    Ok(())
}
