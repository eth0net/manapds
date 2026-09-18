//! One account's database: its repository blocks, record index, blobs and
//! preferences, in a file of its own.

use std::path::Path;

use ipld_core::cid::Cid;
use rusqlite::{Connection, OptionalExtension, params};

use crate::repo::{BlockMap, Store};
use crate::syntax::{Did, Tid};

use super::{Error, db};

/// The schema as the reference's first migration leaves it. Kysely quotes its
/// identifiers and writes `varchar`, and both are kept so that a server reading
/// this file back finds the columns it declared.
const SCHEMA: &str = r#"
create table "repo_root" ("did" varchar primary key, "cid" varchar not null, "rev" varchar not null, "indexedAt" varchar not null);

create table "repo_block" ("cid" varchar primary key, "repoRev" varchar not null, "size" integer not null, "content" blob not null);
create index "repo_block_repo_rev_idx" on "repo_block" ("repoRev", "cid");

create table "record" ("uri" varchar primary key, "cid" varchar not null, "collection" varchar not null, "rkey" varchar not null, "repoRev" varchar not null, "indexedAt" varchar not null, "takedownRef" varchar);
create index "record_cid_idx" on "record" ("cid");
create index "record_collection_idx" on "record" ("collection");
create index "record_repo_rev_idx" on "record" ("repoRev");

create table "blob" ("cid" varchar primary key, "mimeType" varchar not null, "size" integer not null, "tempKey" varchar, "width" integer, "height" integer, "createdAt" varchar not null, "takedownRef" varchar);
create index "blob_tempkey_idx" on "blob" ("tempKey");

create table "record_blob" ("blobCid" varchar not null, "recordUri" varchar not null, constraint "record_blob_pkey" primary key ("blobCid", "recordUri"));

create table "backlink" ("uri" varchar not null, "path" varchar not null, "linkTo" varchar not null, constraint "backlinks_pkey" primary key ("uri", "path"));
create index "backlink_link_to_idx" on "backlink" ("path", "linkTo");

create table "account_pref" ("id" integer primary key autoincrement, "name" varchar not null, "valueJson" text not null);
"#;

/// Every migration this server knows, in the order they are applied.
const MIGRATIONS: [db::Migration; 1] = [("001", |tx| Ok(tx.execute_batch(SCHEMA)?))];

/// Where a repository has got to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Root {
    /// The commit block.
    pub cid: Cid,
    /// The revision that commit carries.
    pub rev: Tid,
}

/// One account's store.
#[derive(Debug)]
pub struct Actor {
    did: Did,
    db: Connection,
}

impl Actor {
    /// Opens an account's database, creating the file and its directory if
    /// they are not there and migrating it if it is behind.
    ///
    /// # Errors
    ///
    /// If the directory cannot be made, the file cannot be opened, or the
    /// database has been migrated past what this server reads.
    pub fn open(path: &Path, did: Did) -> Result<Self, Error> {
        Ok(Self {
            did,
            db: db::open(path, &MIGRATIONS)?,
        })
    }

    /// A store held in memory, which is what tests want and nothing else does.
    ///
    /// # Errors
    ///
    /// If SQLite will not open a database at all.
    pub fn memory(did: Did) -> Result<Self, Error> {
        Ok(Self {
            did,
            db: db::memory(&MIGRATIONS)?,
        })
    }

    /// The commit the repository is on, or `None` before the first one.
    ///
    /// # Errors
    ///
    /// If the row holds something that is not a CID and a TID.
    pub fn root(&self) -> Result<Option<Root>, Error> {
        let row: Option<(String, String)> = self
            .db
            .query_row(
                r#"select "cid", "rev" from "repo_root" where "did" = ?1"#,
                params![self.did.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;

        row.map(|(cid, rev)| {
            Ok(Root {
                cid: cid
                    .parse()
                    .map_err(|_| Error::Malformed("a repo root that is not a CID"))?,
                rev: rev
                    .parse()
                    .map_err(|_| Error::Malformed("a repo revision that is not a TID"))?,
            })
        })
        .transpose()
    }

    /// Stores a revision's blocks and moves the root onto it, together or not
    /// at all.
    ///
    /// # Errors
    ///
    /// If the write fails.
    pub fn commit(&mut self, root: &Root, blocks: &BlockMap) -> Result<(), Error> {
        let stamp = jiff::Timestamp::now();
        let transaction = self.db.transaction()?;
        {
            let mut insert = transaction.prepare(
                r#"insert or ignore into "repo_block" ("cid", "repoRev", "size", "content") values (?1, ?2, ?3, ?4)"#,
            )?;
            for (cid, bytes) in blocks {
                insert.execute(params![
                    cid.to_string(),
                    root.rev.as_str(),
                    i64::try_from(bytes.len()).unwrap_or(i64::MAX),
                    bytes
                ])?;
            }
        }
        transaction.execute(
            r#"insert into "repo_root" ("did", "cid", "rev", "indexedAt") values (?1, ?2, ?3, ?4)
               on conflict("did") do update set "cid" = ?2, "rev" = ?3, "indexedAt" = ?4"#,
            params![
                self.did.as_str(),
                root.cid.to_string(),
                root.rev.as_str(),
                format!("{stamp:.3}")
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Whose store this is.
    #[must_use]
    pub fn did(&self) -> &Did {
        &self.did
    }
}

impl Store for Actor {
    fn get(&self, cid: &Cid) -> Result<std::borrow::Cow<'_, [u8]>, crate::repo::Error> {
        self.db
            .query_row(
                r#"select "content" from "repo_block" where "cid" = ?1"#,
                params![cid.to_string()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(|error| unreachable(&error))?
            .map(std::borrow::Cow::Owned)
            .ok_or(crate::repo::Error::MissingBlock(*cid))
    }

    fn contains(&self, cid: &Cid) -> Result<bool, crate::repo::Error> {
        self.db
            .query_row(
                r#"select 1 from "repo_block" where "cid" = ?1"#,
                params![cid.to_string()],
                |_| Ok(true),
            )
            .optional()
            .map(|found| found.unwrap_or(false))
            .map_err(|error| unreachable(&error))
    }
}

/// A database that would not answer. Whether waiting would help is the one
/// thing a caller needs from this, since the answer decides between telling a
/// client to come back and telling it something is broken.
fn unreachable(error: &rusqlite::Error) -> crate::repo::Error {
    if matches!(
        error.sqlite_error_code(),
        Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
    ) {
        return crate::repo::Error::StoreBusy;
    }
    crate::repo::Error::Store(error.to_string())
}
