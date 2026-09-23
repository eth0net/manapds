//! The event log: what happened to which repository, in the order a consumer
//! would be told about it.
//!
//! Nothing reads this over a socket yet. It is written from the start anyway,
//! because a log with a gap in it is worse than no log, and turning the
//! firehose on later should be a reader rather than a migration.

use rusqlite::{Connection, OptionalExtension, params};

use crate::syntax::Did;

use super::{Error, db};

/// The schema as the reference's first migration leaves it.
const SCHEMA: &str = r#"
create table "repo_seq" ("seq" integer primary key autoincrement, "did" varchar not null, "eventType" varchar not null, "event" blob not null, "invalidated" int2 default 0 not null, "sequencedAt" varchar not null);
create index "repo_seq_did_idx" on "repo_seq" ("did");
create index "repo_seq_event_type_idx" on "repo_seq" ("eventType");
create index "repo_seq_sequenced_at_index" on "repo_seq" ("sequencedAt");
"#;

/// Every migration this server knows, in the order they are applied.
const MIGRATIONS: [db::Migration; 1] = [("001", |tx| Ok(tx.execute_batch(SCHEMA)?))];

/// What kind of thing an entry records.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Event {
    /// A commit was written to a repository.
    Append,
    /// A repository's current state, for a consumer that fell behind.
    Sync,
    /// A handle or DID document changed.
    Identity,
    /// An account was activated, deactivated, or taken down.
    Account,
}

impl Event {
    /// The string the column holds.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Append => "append",
            Self::Sync => "sync",
            Self::Identity => "identity",
            Self::Account => "account",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "append" => Some(Self::Append),
            "sync" => Some(Self::Sync),
            "identity" => Some(Self::Identity),
            "account" => Some(Self::Account),
            _ => None,
        }
    }
}

/// One entry, as a consumer would be handed it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Entry {
    /// Where it falls in the log. Consumers resume from this.
    pub seq: i64,
    /// Whose repository it is about.
    pub did: Did,
    /// What happened.
    pub event: Event,
    /// The event body, encoded by whoever emitted it.
    pub body: Vec<u8>,
    /// When it was written.
    pub sequenced_at: String,
}

/// The log, and the counter that orders it.
#[derive(Debug)]
pub struct Sequencer {
    db: Connection,
}

impl Sequencer {
    /// Opens the log, making the file and its directory if they are not there.
    ///
    /// # Errors
    ///
    /// If the file cannot be opened or has been migrated past this server.
    pub fn open(path: &std::path::Path) -> Result<Self, Error> {
        Ok(Self {
            db: db::open(path, &MIGRATIONS)?,
        })
    }

    /// A log held in memory, which is what tests want and nothing else does.
    ///
    /// # Errors
    ///
    /// If SQLite will not open a database at all.
    pub fn memory() -> Result<Self, Error> {
        Ok(Self {
            db: db::memory(&MIGRATIONS)?,
        })
    }

    /// Appends an event and hands back the number it was sequenced under.
    ///
    /// The body is written as given: what belongs in it is the business of
    /// whatever emitted the event, not of the log.
    ///
    /// # Errors
    ///
    /// If the write fails.
    pub fn append(&self, did: &Did, event: Event, body: &[u8]) -> Result<i64, Error> {
        self.db.execute(
            r#"insert into "repo_seq" ("did", "eventType", "event", "invalidated", "sequencedAt")
               values (?1, ?2, ?3, 0, ?4)"#,
            params![
                did.as_str(),
                event.as_str(),
                body,
                format!("{:.3}", jiff::Timestamp::now())
            ],
        )?;
        Ok(self.db.last_insert_rowid())
    }

    /// Appends several entries at once, all of them or none.
    ///
    /// Events that describe one thing happening have to be read together, so a
    /// consumer must not be able to see the log partway through them.
    ///
    /// # Errors
    ///
    /// If the write fails.
    pub fn extend<'a>(
        &mut self,
        did: &Did,
        bodies: impl IntoIterator<Item = (Event, &'a [u8])>,
    ) -> Result<Vec<i64>, Error> {
        let transaction = self.db.transaction()?;
        let now = format!("{:.3}", jiff::Timestamp::now());
        let mut numbers = Vec::new();
        for (event, body) in bodies {
            transaction.execute(
                r#"insert into "repo_seq" ("did", "eventType", "event", "invalidated", "sequencedAt")
                   values (?1, ?2, ?3, 0, ?4)"#,
                params![did.as_str(), event.as_str(), body, now],
            )?;
            numbers.push(transaction.last_insert_rowid());
        }
        transaction.commit()?;
        Ok(numbers)
    }

    /// The highest number handed out, or `None` while the log is empty.
    ///
    /// # Errors
    ///
    /// If the read fails.
    pub fn latest(&self) -> Result<Option<i64>, Error> {
        Ok(self
            .db
            .query_row(r#"select max("seq") from "repo_seq""#, [], |row| row.get(0))
            .optional()?
            .flatten())
    }

    /// Entries after a sequence number, oldest first, skipping any that were
    /// superseded.
    ///
    /// # Errors
    ///
    /// If a row holds a DID or an event type nothing here writes.
    pub fn since(&self, seq: i64, limit: u32) -> Result<Vec<Entry>, Error> {
        self.db
            .prepare(
                r#"select "seq", "did", "eventType", "event", "sequencedAt" from "repo_seq"
                   where "seq" > ?1 and "invalidated" = 0 order by "seq" limit ?2"#,
            )?
            .query_map(params![seq, limit], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })?
            .map(|row| {
                let (seq, did, event, body, sequenced_at) = row?;
                Ok(Entry {
                    seq,
                    did: did
                        .parse()
                        .map_err(|_| Error::Malformed("a logged DID that is not one"))?,
                    event: Event::parse(&event)
                        .ok_or(Error::Malformed("an event type nothing writes"))?,
                    body,
                    sequenced_at,
                })
            })
            .collect()
    }
}
