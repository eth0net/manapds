//! Resolved DID documents, held so the directory is not asked the same
//! question twice.
//!
//! Nothing here decides what is stale. The document and the time it was
//! written come back together, and how long that is good for is the caller's
//! configuration to read.

use rusqlite::{Connection, OptionalExtension, params};

use crate::syntax::Did;

use super::{Error, db};

/// The schema as the reference's first migration leaves it.
const SCHEMA: &str = r#"
create table "did_doc" ("did" varchar primary key, "doc" text not null, "updatedAt" bigint not null);
"#;

/// Every migration this server knows, in the order they are applied.
const MIGRATIONS: [db::Migration; 1] = [("001", SCHEMA)];

/// A document and when it was last fetched.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Cached {
    /// The DID document, as the JSON it arrived as.
    pub document: String,
    /// Milliseconds since the epoch, which is the unit the column holds.
    pub updated_at: i64,
}

/// The cache.
#[derive(Debug)]
pub struct DidCache {
    db: Connection,
}

impl DidCache {
    /// Opens the cache, making the file and its directory if they are not
    /// there.
    ///
    /// # Errors
    ///
    /// If the file cannot be opened or has been migrated past this server.
    pub fn open(path: &std::path::Path) -> Result<Self, Error> {
        Ok(Self {
            db: db::open(path, &MIGRATIONS)?,
        })
    }

    /// A cache held in memory, which is what tests want and nothing else does.
    ///
    /// # Errors
    ///
    /// If SQLite will not open a database at all.
    pub fn memory() -> Result<Self, Error> {
        Ok(Self {
            db: db::memory(&MIGRATIONS)?,
        })
    }

    /// Stores a document, replacing whatever was there.
    ///
    /// # Errors
    ///
    /// If the write fails.
    pub fn put(&self, did: &Did, document: &str) -> Result<(), Error> {
        self.db.execute(
            r#"insert into "did_doc" ("did", "doc", "updatedAt") values (?1, ?2, ?3)
               on conflict("did") do update set "doc" = ?2, "updatedAt" = ?3"#,
            params![
                did.as_str(),
                document,
                jiff::Timestamp::now().as_millisecond()
            ],
        )?;
        Ok(())
    }

    /// What is held for a DID, if anything.
    ///
    /// # Errors
    ///
    /// If the read fails.
    pub fn get(&self, did: &Did) -> Result<Option<Cached>, Error> {
        Ok(self
            .db
            .query_row(
                r#"select "doc", "updatedAt" from "did_doc" where "did" = ?1"#,
                params![did.as_str()],
                |row| {
                    Ok(Cached {
                        document: row.get(0)?,
                        updated_at: row.get(1)?,
                    })
                },
            )
            .optional()?)
    }

    /// Drops one entry, so the next question goes to the directory.
    ///
    /// # Errors
    ///
    /// If the delete fails.
    pub fn forget(&self, did: &Did) -> Result<(), Error> {
        self.db.execute(
            r#"delete from "did_doc" where "did" = ?1"#,
            params![did.as_str()],
        )?;
        Ok(())
    }

    /// Drops everything.
    ///
    /// # Errors
    ///
    /// If the delete fails.
    pub fn clear(&self) -> Result<(), Error> {
        self.db.execute(r#"delete from "did_doc""#, [])?;
        Ok(())
    }
}
