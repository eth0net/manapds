//! One account's database: its repository blocks, record index, blobs and
//! preferences, in a file of its own.

use std::path::Path;

use ipld_core::cid::Cid;
use rusqlite::{Connection, OptionalExtension, params};

use crate::repo::{BlockMap, Store};
use crate::syntax::{Did, Nsid, RecordKey, Tid};

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

/// A record as the index holds it, beside the block it points at.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Record {
    /// Where it is, as a client is told.
    pub uri: String,
    /// The block the record is in.
    pub cid: Cid,
    /// That block, which is the record in dag-cbor.
    pub value: Vec<u8>,
}

/// What a revision has put on disk before it is known to have landed.
#[derive(Debug, Default)]
struct Leaving {
    cleared: Committed,
    linked: Vec<Cid>,
}

/// What a commit leaves for the caller to clear up on disk.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Committed {
    /// Blobs no record names any more, whose files are nobody's.
    pub orphaned: Vec<Cid>,
    /// Uploads a record took, which are served from their own name now.
    pub taken: Vec<String>,
}

/// A blob this account has uploaded, as the index holds it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Blob {
    /// What the bytes are addressed by.
    pub cid: Cid,
    /// What the uploader said they are.
    pub mime: String,
    /// How many of them there are.
    pub size: u64,
}

/// A blob a record names that this account never uploaded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissingBlob {
    /// What the record addresses it by.
    pub cid: Cid,
    /// One of the records naming it.
    pub uri: String,
}

/// What a record points at that it may only point at once.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Backlink {
    /// Where in the record the subject sits, spelled the way the other server
    /// spells it.
    pub path: &'static str,
    /// The subject itself: a DID for a follow or a block, an AT-URI for a like
    /// or a repost.
    pub link_to: String,
}

/// Where one commit leaves a record in the index.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Indexed {
    /// The key this commit wrote, and the block it now points at.
    Put {
        /// The collection it belongs to.
        collection: Nsid,
        /// Its key within that collection.
        rkey: RecordKey,
        /// The block the record is in.
        cid: Cid,
        /// What it points at that it may only point at once.
        links: Vec<Backlink>,
        /// The blobs it names, as it names them.
        blobs: Vec<Blob>,
    },
    /// The key this commit emptied.
    Delete {
        /// The collection it belonged to.
        collection: Nsid,
        /// Its key within that collection.
        rkey: RecordKey,
    },
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

    /// Stores a revision's blocks, indexes the records it touched, and moves
    /// the root onto it, together or not at all.
    ///
    /// `from` is the root this revision was built on, and the move lands only
    /// while that is still the one there. Answering `None` leaves the caller
    /// to work the revision out again; `docs/architecture.md` has why.
    ///
    /// What comes back are the blobs no record holds any more, whose files are
    /// the caller's to unlink once this has committed.
    ///
    /// # Errors
    ///
    /// If the write fails.
    pub fn commit(
        &mut self,
        from: Option<&Root>,
        root: &Root,
        blocks: &BlockMap,
        records: &[Indexed],
        blobs: &super::Blobs,
    ) -> Result<Option<Committed>, Error> {
        // A link is not part of the transaction, so one made by a revision
        // that does not land has to be taken back by hand, or a blob nothing
        // took stays readable under its own name.
        let did = self.did.clone();
        let mut leaving = Leaving::default();
        let landed = self.landing(from, root, blocks, records, blobs, &mut leaving);
        if !matches!(landed, Ok(Some(_))) {
            for cid in leaving.linked {
                if let Err(error) = blobs.delete(&did, &cid) {
                    tracing::error!(%cid, %error, "a blob no revision took was left readable");
                }
            }
        }
        landed
    }

    fn landing(
        &mut self,
        from: Option<&Root>,
        root: &Root,
        blocks: &BlockMap,
        records: &[Indexed],
        blobs: &super::Blobs,
        leaving: &mut Leaving,
    ) -> Result<Option<Committed>, Error> {
        let stamp = jiff::Timestamp::now();
        let did = &self.did;
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
        let kept = Self::index(&transaction, blobs, did, root, records, &stamp, leaving)?;

        // `kept` spares a blob for a record a later write may have replaced, so
        // each of them is asked for once every record has had its turn.
        for cid in kept {
            if Self::held(&transaction, &cid)? {
                continue;
            }
            transaction.execute(r#"delete from "blob" where "cid" = ?1"#, params![cid])?;
            leaving.cleared.orphaned.push(
                cid.parse()
                    .map_err(|_| Error::Malformed("a blob that is not a CID"))?,
            );
        }

        let moved = match from {
            Some(from) => transaction.execute(
                r#"update "repo_root" set "cid" = ?2, "rev" = ?3, "indexedAt" = ?4
                   where "did" = ?1 and "cid" = ?5"#,
                params![
                    self.did.as_str(),
                    root.cid.to_string(),
                    root.rev.as_str(),
                    format!("{stamp:.3}"),
                    from.cid.to_string()
                ],
            )?,
            None => transaction.execute(
                r#"insert into "repo_root" ("did", "cid", "rev", "indexedAt") values (?1, ?2, ?3, ?4)"#,
                params![
                    self.did.as_str(),
                    root.cid.to_string(),
                    root.rev.as_str(),
                    format!("{stamp:.3}")
                ],
            )?,
        };
        if moved == 0 {
            transaction.rollback()?;
            return Ok(None);
        }
        transaction.commit()?;
        Ok(Some(std::mem::take(&mut leaving.cleared)))
    }

    /// Every block this repository holds, or only those a revision after
    /// `since` wrote.
    ///
    /// Blocks no revision reaches any more are in here too, since nothing
    /// collects them.
    ///
    /// # Errors
    ///
    /// If the read fails, or a row names a block that is not a CID.
    // todo: hand these back a page at a time, so a large repository is not
    // held in memory twice over on its way out.
    pub fn blocks_since(&self, since: Option<&Tid>) -> Result<BlockMap, Error> {
        let mut blocks = BlockMap::new();
        let rows = self
            .db
            .prepare(
                r#"select "cid", "content" from "repo_block"
                   where ?1 is null or "repoRev" > ?1"#,
            )?
            .query_map(params![since.map(Tid::as_str)], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (cid, content) in rows {
            let cid = cid
                .parse()
                .map_err(|_| Error::Malformed("a stored block that is not a CID"))?;
            blocks.insert(cid, content);
        }
        Ok(blocks)
    }

    /// The blocks a caller named, beside the CIDs this repository has nothing
    /// under.
    ///
    /// # Errors
    ///
    /// If the read fails.
    pub fn blocks(&self, cids: &[Cid]) -> Result<(BlockMap, Vec<Cid>), Error> {
        let mut statement = self
            .db
            .prepare(r#"select "content" from "repo_block" where "cid" = ?1"#)?;
        let mut blocks = BlockMap::new();
        let mut missing = Vec::new();
        for cid in cids {
            match statement
                .query_row(params![cid.to_string()], |row| row.get::<_, Vec<u8>>(0))
                .optional()?
            {
                Some(content) => blocks.insert(*cid, content),
                None => missing.push(*cid),
            }
        }
        Ok((blocks, missing))
    }

    /// The record at a key, if the index holds one there.
    ///
    /// # Errors
    ///
    /// If the read fails, or the row names a block that is not a CID.
    pub fn record(&self, collection: &Nsid, rkey: &RecordKey) -> Result<Option<Record>, Error> {
        self.db
            .query_row(
                r#"select "record"."uri", "record"."cid", "repo_block"."content"
                   from "record" join "repo_block" on "repo_block"."cid" = "record"."cid"
                   where "record"."uri" = ?1"#,
                params![uri(&self.did, collection, rkey)],
                read,
            )
            .optional()?
            .transpose()
    }

    /// One page of a collection, newest key first unless `reverse` asks for the
    /// other end, starting after `cursor` in whichever direction that is.
    ///
    /// # Errors
    ///
    /// If the read fails, or a row names a block that is not a CID.
    pub fn records(
        &self,
        collection: &Nsid,
        limit: u32,
        cursor: Option<&str>,
        reverse: bool,
    ) -> Result<Vec<Record>, Error> {
        let query = format!(
            r#"select "record"."uri", "record"."cid", "repo_block"."content"
               from "record" join "repo_block" on "repo_block"."cid" = "record"."cid"
               where "record"."collection" = ?1 and (?2 is null or "record"."rkey" {} ?2)
               order by "record"."rkey" {} limit ?3"#,
            if reverse { ">" } else { "<" },
            if reverse { "asc" } else { "desc" },
        );
        self.db
            .prepare(&query)?
            .query_map(params![collection.as_str(), cursor, limit], read)?
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .collect()
    }

    /// The keys in a collection already pointing where this record would.
    ///
    /// # Errors
    ///
    /// If the read fails, or a row holds a key nothing here writes.
    pub fn pointing_at(
        &self,
        collection: &Nsid,
        backlink: &Backlink,
    ) -> Result<Vec<RecordKey>, Error> {
        self.db
            .prepare(
                r#"select "record"."rkey" from "record"
                   join "backlink" on "backlink"."uri" = "record"."uri"
                   where "backlink"."path" = ?1 and "backlink"."linkTo" = ?2
                     and "record"."collection" = ?3"#,
            )?
            .query_map(
                params![backlink.path, backlink.link_to, collection.as_str()],
                |row| row.get::<_, String>(0),
            )?
            .map(|rkey| {
                rkey?
                    .parse()
                    .map_err(|_| Error::Malformed("an indexed key that is not a record key"))
            })
            .collect()
    }

    /// Every collection the index has a record in.
    ///
    /// # Errors
    ///
    /// If the read fails, or a row names a collection that is not an NSID.
    pub fn collections(&self) -> Result<Vec<Nsid>, Error> {
        self.db
            .prepare(r#"select distinct "collection" from "record" order by "collection""#)?
            .query_map([], |row| row.get::<_, String>(0))?
            .map(|collection| {
                collection?
                    .parse()
                    .map_err(|_| Error::Malformed("an indexed collection that is not an NSID"))
            })
            .collect()
    }

    /// Writes down a blob that has been stored, or leaves the row that is
    /// already there.
    ///
    /// `tempKey` is set because no record has claimed it yet, and uploading
    /// one again puts it back at the start of the window it is kept for. A
    /// blob a record already claimed is left alone.
    ///
    /// # Errors
    ///
    /// If the write fails.
    pub fn add_blob(&self, blob: &Blob, key: &str) -> Result<(), Error> {
        self.db.execute(
            r#"insert into "blob" ("cid", "mimeType", "size", "tempKey", "createdAt") values (?1, ?2, ?3, ?4, ?5)
               on conflict("cid") do update set "tempKey" = ?4, "createdAt" = ?5 where "tempKey" is not null"#,
            params![
                blob.cid.to_string(),
                blob.mime,
                i64::try_from(blob.size).unwrap_or(i64::MAX),
                key,
                super::stamp(jiff::Timestamp::now())
            ],
        )?;
        Ok(())
    }

    /// Lets go of every blob a record was holding, and says which of them
    /// nothing holds any more.
    ///
    /// `kept` is what the same commit leaves another record holding, so a blob
    /// moved from one record to another is not dropped between the two.
    ///
    /// # Errors
    ///
    /// If the write fails.
    fn dereference(
        transaction: &rusqlite::Transaction<'_>,
        uri: &str,
        kept: &std::collections::HashSet<String>,
    ) -> Result<Vec<Cid>, Error> {
        let held: Vec<String> = transaction
            .prepare(r#"delete from "record_blob" where "recordUri" = ?1 returning "blobCid""#)?
            .query_map(params![uri], |row| row.get(0))?
            .collect::<Result<_, _>>()?;

        let mut orphaned = Vec::new();
        for cid in held {
            // Asked after the rows are gone, so what comes back is what some
            // other record is holding rather than the row just removed.
            if kept.contains(&cid) || Self::held(transaction, &cid)? {
                continue;
            }
            transaction.execute(r#"delete from "blob" where "cid" = ?1"#, params![cid])?;
            orphaned.push(
                cid.parse()
                    .map_err(|_| Error::Malformed("a blob that is not a CID"))?,
            );
        }
        Ok(orphaned)
    }

    /// Writes what one commit did to the record index, the links and the blobs,
    /// and says which blobs the batch spared so the caller can ask again.
    fn index(
        transaction: &rusqlite::Transaction<'_>,
        blobs: &super::Blobs,
        did: &Did,
        root: &Root,
        records: &[Indexed],
        stamp: &jiff::Timestamp,
        leaving: &mut Leaving,
    ) -> Result<std::collections::HashSet<String>, Error> {
        let Leaving { cleared, linked } = leaving;
        let (orphaned, taken) = (&mut cleared.orphaned, &mut cleared.taken);
        let mut put = transaction.prepare(
            r#"insert into "record" ("uri", "cid", "collection", "rkey", "repoRev", "indexedAt") values (?1, ?2, ?3, ?4, ?5, ?6)
               on conflict("uri") do update set "cid" = ?2, "repoRev" = ?5, "indexedAt" = ?6"#,
        )?;
        let mut remove = transaction.prepare(r#"delete from "record" where "uri" = ?1"#)?;
        // Rewritten for every record, so one that stops pointing anywhere
        // loses its links.
        let mut unlink = transaction.prepare(r#"delete from "backlink" where "uri" = ?1"#)?;
        let mut link = transaction.prepare(
            r#"insert or ignore into "backlink" ("uri", "path", "linkTo") values (?1, ?2, ?3)"#,
        )?;
        let kept: std::collections::HashSet<String> = records
            .iter()
            .filter_map(|record| match record {
                Indexed::Put { blobs, .. } => Some(blobs),
                Indexed::Delete { .. } => None,
            })
            .flatten()
            .map(|blob| blob.cid.to_string())
            .collect();

        for record in records {
            match record {
                Indexed::Put {
                    collection,
                    rkey,
                    cid,
                    links,
                    blobs: named,
                } => {
                    let at = uri(did, collection, rkey);
                    unlink.execute(params![at])?;
                    for backlink in links {
                        link.execute(params![at, backlink.path, backlink.link_to])?;
                    }
                    orphaned.extend(Self::dereference(transaction, &at, &kept)?);
                    for blob in named {
                        Self::claim(transaction, blobs, did, &at, blob, taken, linked)?;
                    }
                    put.execute(params![
                        at,
                        cid.to_string(),
                        collection.as_str(),
                        rkey.as_str(),
                        root.rev.as_str(),
                        format!("{stamp:.3}")
                    ])?
                }
                Indexed::Delete { collection, rkey } => {
                    let at = uri(did, collection, rkey);
                    unlink.execute(params![at])?;
                    orphaned.extend(Self::dereference(transaction, &at, &kept)?);
                    remove.execute(params![at])?
                }
            };
        }
        Ok(kept)
    }

    /// Whether no row is left under this blob, which is what makes its file
    /// nobody's.
    ///
    /// # Errors
    ///
    /// If the read fails.
    pub fn unheld(&self, cid: &Cid) -> Result<bool, Error> {
        Ok(self
            .db
            .query_row(
                r#"select 1 from "blob" where "cid" = ?1"#,
                params![cid.to_string()],
                |_| Ok(true),
            )
            .optional()?
            .is_none())
    }

    /// Whether any record still names this blob.
    fn held(transaction: &rusqlite::Transaction<'_>, cid: &str) -> Result<bool, Error> {
        Ok(transaction
            .query_row(
                r#"select 1 from "record_blob" where "blobCid" = ?1"#,
                params![cid],
                |_| Ok(true),
            )
            .optional()?
            .unwrap_or(false))
    }

    /// Ties a blob to the record naming it, and takes it out of the state an
    /// upload leaves it in.
    ///
    /// # Errors
    ///
    /// If nothing uploaded that blob, or the record names it as something
    /// other than what was uploaded.
    fn claim(
        transaction: &rusqlite::Transaction<'_>,
        blobs: &super::Blobs,
        did: &Did,
        uri: &str,
        blob: &Blob,
        taken: &mut Vec<String>,
        linked: &mut Vec<Cid>,
    ) -> Result<(), Error> {
        let held: Option<(Option<String>, String, i64)> = transaction
            .query_row(
                r#"select "tempKey", "mimeType", "size" from "blob" where "cid" = ?1 and "takedownRef" is null"#,
                params![blob.cid.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((unclaimed, mime, size)) = held else {
            return Err(Error::BlobMissing(blob.cid));
        };

        // Only while it is still an upload: a second record naming a blob takes
        // what the first one settled.
        if let Some(key) = &unclaimed {
            if mime != blob.mime {
                return Err(Error::BlobMismatch("Mimetype", mime, blob.mime.clone()));
            }
            if u64::try_from(size).unwrap_or_default() != blob.size {
                return Err(Error::BlobMismatch(
                    "Size",
                    size.to_string(),
                    blob.size.to_string(),
                ));
            }
            // Linked under the transaction that claims it, so nothing is
            // served from a name no row has taken.
            if blobs.claim(did, key, &blob.cid)? {
                linked.push(blob.cid);
            }
            taken.push(key.clone());
        }

        transaction.execute(
            r#"insert or ignore into "record_blob" ("blobCid", "recordUri") values (?1, ?2)"#,
            params![blob.cid.to_string(), uri],
        )?;
        transaction.execute(
            r#"update "blob" set "tempKey" = null where "cid" = ?1"#,
            params![blob.cid.to_string()],
        )?;
        Ok(())
    }

    /// Blobs uploaded before `cutoff` that no record ever named, taken out of
    /// the index so their files can go.
    ///
    /// `docs/architecture.md` has why this server sweeps and the other does
    /// not.
    ///
    /// # Errors
    ///
    /// If the read or the write fails, or a row names something that is not a
    /// CID.
    pub fn sweep_unclaimed(&self, cutoff: jiff::Timestamp) -> Result<Vec<String>, Error> {
        let stale: Vec<(String, String)> = self
            .db
            .prepare(
                r#"select "cid", "tempKey" from "blob" where "tempKey" is not null and "createdAt" < ?1"#,
            )?
            .query_map(params![super::stamp(cutoff)], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })?
            .collect::<Result<_, _>>()?;

        let mut swept = Vec::new();
        for (cid, key) in stale {
            // Named, not just unclaimed: an upload that arrived since the read
            // is a different promise and its own window.
            let gone = self.db.execute(
                r#"delete from "blob" where "cid" = ?1 and "tempKey" = ?2"#,
                params![cid, key],
            )?;
            if gone > 0 {
                swept.push(key);
            }
        }
        Ok(swept)
    }

    /// What is known about a blob, if this account uploaded one.
    ///
    /// # Errors
    ///
    /// If the read fails, or the row names something that is not a CID.
    pub fn blob(&self, cid: &Cid) -> Result<Option<Blob>, Error> {
        self.db
            .query_row(
                r#"select "cid", "mimeType", "size" from "blob" where "cid" = ?1"#,
                params![cid.to_string()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()?
            .map(|(cid, mime, size)| {
                Ok(Blob {
                    cid: cid
                        .parse()
                        .map_err(|_| Error::Malformed("a blob that is not a CID"))?,
                    mime,
                    size: u64::try_from(size).unwrap_or_default(),
                })
            })
            .transpose()
    }

    /// One page of the blobs this account's records name, in CID order and
    /// starting after `cursor`.
    ///
    /// `since` keeps only the blobs named by a record a later revision wrote.
    /// An upload no record has claimed is not here at all.
    ///
    /// # Errors
    ///
    /// If the read fails, or a row names something that is not a CID.
    pub fn blobs(
        &self,
        since: Option<&str>,
        limit: u32,
        cursor: Option<&str>,
    ) -> Result<Vec<Cid>, Error> {
        let query = format!(
            r#"select "blobCid" from "record_blob" {}
               where (?2 is null or "blobCid" > ?2)
               group by "blobCid" order by "blobCid" asc limit ?3"#,
            match since {
                Some(_) => {
                    r#"join "record" on "record"."uri" = "record_blob"."recordUri"
                       and "record"."repoRev" > ?1"#
                }
                None => "",
            },
        );
        self.db
            .prepare(&query)?
            .query_map(params![since, cursor, limit], |row| row.get::<_, String>(0))?
            .map(|cid| {
                cid?.parse()
                    .map_err(|_| Error::Malformed("a blob that is not a CID"))
            })
            .collect()
    }

    /// One page of the blobs this account's records name that it never
    /// uploaded, in CID order and starting after `cursor`.
    ///
    /// # Errors
    ///
    /// If the read fails, or a row names something that is not a CID.
    pub fn missing_blobs(
        &self,
        limit: u32,
        cursor: Option<&str>,
    ) -> Result<Vec<MissingBlob>, Error> {
        // The record named is chosen, not whichever row the group yields.
        self.db
            .prepare(
                r#"select "blobCid", min("recordUri") from "record_blob"
                   where not exists (select 1 from "blob" where "blob"."cid" = "record_blob"."blobCid")
                     and (?1 is null or "blobCid" > ?1)
                   group by "blobCid" order by "blobCid" asc limit ?2"#,
            )?
            .query_map(params![cursor, limit], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .map(|row| {
                let (cid, uri) = row?;
                Ok(MissingBlob {
                    cid: cid
                        .parse()
                        .map_err(|_| Error::Malformed("a blob that is not a CID"))?,
                    uri,
                })
            })
            .collect()
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

/// One indexed row, left for the caller to fault on the CID it holds.
fn read(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<Record, Error>> {
    let (uri, cid, value): (String, String, Vec<u8>) = (row.get(0)?, row.get(1)?, row.get(2)?);
    Ok(match cid.parse() {
        Ok(cid) => Ok(Record { uri, cid, value }),
        Err(_) => Err(Error::Malformed("an indexed record that is not a CID")),
    })
}

/// What the index keys a record under, which is what a client is handed back
/// and what a backlink points at.
fn uri(did: &Did, collection: &Nsid, rkey: &RecordKey) -> String {
    format!("at://{did}/{collection}/{rkey}")
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
