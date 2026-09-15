//! The account database: who has an account here, what they are called, and
//! what they sign in with.
//!
//! Migrations 004 to 007 are the reference's OAuth tables, which land with the
//! authorization server. Until they do, a database that server created is
//! refused rather than half-read.

use rusqlite::{Connection, OptionalExtension, params};

use crate::syntax::{Did, Handle};

use super::{Error, db};

/// The schema as the reference's first migration leaves it.
const INIT: &str = r#"
create table "app_password" ("did" varchar not null, "name" varchar not null, "passwordScrypt" varchar not null, "createdAt" varchar not null, constraint "app_password_pkey" primary key ("did", "name"));

create table "invite_code" ("code" varchar primary key, "availableUses" integer not null, "disabled" int2 default 0, "forAccount" varchar not null, "createdBy" varchar not null, "createdAt" varchar not null);
create index "invite_code_for_account_idx" on "invite_code" ("forAccount");

create table "invite_code_use" ("code" varchar not null, "usedBy" varchar not null, "usedAt" varchar not null, constraint "invite_code_use_pkey" primary key ("code", "usedBy"));

create table "refresh_token" ("id" varchar primary key, "did" varchar not null, "expiresAt" varchar not null, "nextId" varchar, "appPasswordName" varchar);
create index "refresh_token_did_idx" on "refresh_token" ("did");

create table "repo_root" ("did" varchar primary key, "cid" varchar not null, "rev" varchar not null, "indexedAt" varchar not null);

create table "actor" ("did" varchar primary key, "handle" varchar, "createdAt" varchar not null, "takedownRef" varchar);
create unique index "actor_handle_lower_idx" on "actor" (lower("handle"));
create index "actor_cursor_idx" on "actor" ("createdAt", "did");

create table "account" ("did" varchar primary key, "email" varchar not null, "passwordScrypt" varchar not null, "emailConfirmedAt" varchar, "invitesDisabled" int2 default 0 not null);
create unique index "account_email_lower_idx" on "account" (lower("email"));

create table "email_token" ("purpose" varchar not null, "did" varchar not null, "token" varchar not null, "requestedAt" varchar not null, constraint "email_token_pkey" primary key ("purpose", "did"), constraint "email_token_purpose_token_unique" unique ("purpose", "token"));
"#;

/// Deactivation, which an account can be put into and taken out of.
const DEACTIVATION: &str = r#"
alter table "actor" add column "deactivatedAt" varchar;
alter table "actor" add column "deleteAfter" varchar;
"#;

/// App passwords that may do more than post.
const PRIVILEGED_APP_PASSWORDS: &str = r#"
alter table "app_password" add column "privileged" integer default 0 not null;
"#;

/// Every migration this server knows, in the order they are applied.
const MIGRATIONS: [db::Migration; 3] = [
    ("001", INIT),
    ("002", DEACTIVATION),
    ("003", PRIVILEGED_APP_PASSWORDS),
];

/// An account, as the two tables hold it between them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Account {
    /// The identity everything else hangs off.
    pub did: Did,
    /// What it is called, which is `None` between creation and resolution.
    pub handle: Option<Handle>,
    /// Where password resets and confirmations go.
    pub email: String,
    /// The password as it is stored, which is never the password.
    pub password_scrypt: String,
}

/// The accounts this server holds.
#[derive(Debug)]
pub struct Accounts {
    db: Connection,
}

impl Accounts {
    /// Opens the database, making the file and its directory if they are not
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

    /// A database held in memory, which is what tests want and nothing else
    /// does.
    ///
    /// # Errors
    ///
    /// If SQLite will not open a database at all.
    pub fn memory() -> Result<Self, Error> {
        Ok(Self {
            db: db::memory(&MIGRATIONS)?,
        })
    }

    /// Writes a new account, or fails if the handle or the email is taken.
    ///
    /// Handles and emails are unique without regard to case, which is the
    /// index's doing rather than this function's.
    ///
    /// # Errors
    ///
    /// If either is already in use, or the write fails.
    pub fn create(&mut self, account: &Account) -> Result<(), Error> {
        let transaction = self.db.transaction()?;
        transaction.execute(
            r#"insert into "actor" ("did", "handle", "createdAt") values (?1, ?2, ?3)"#,
            params![
                account.did.as_str(),
                account.handle.as_ref().map(Handle::as_str),
                format!("{:.3}", jiff::Timestamp::now())
            ],
        )?;
        transaction.execute(
            r#"insert into "account" ("did", "email", "passwordScrypt", "invitesDisabled")
               values (?1, ?2, ?3, 0)"#,
            params![account.did.as_str(), account.email, account.password_scrypt],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// The account with this DID.
    ///
    /// # Errors
    ///
    /// If a row holds a DID or handle nothing here writes.
    pub fn by_did(&self, did: &Did) -> Result<Option<Account>, Error> {
        self.query(
            r#"select "actor"."did", "actor"."handle", "account"."email", "account"."passwordScrypt"
               from "actor" join "account" on "account"."did" = "actor"."did"
               where "actor"."did" = ?1"#,
            did.as_str(),
        )
    }

    /// The account answering to this handle, whatever case it is asked in.
    ///
    /// # Errors
    ///
    /// If a row holds a DID or handle nothing here writes.
    pub fn by_handle(&self, handle: &Handle) -> Result<Option<Account>, Error> {
        self.query(
            r#"select "actor"."did", "actor"."handle", "account"."email", "account"."passwordScrypt"
               from "actor" join "account" on "account"."did" = "actor"."did"
               where lower("actor"."handle") = lower(?1)"#,
            handle.as_str(),
        )
    }

    fn query(&self, sql: &str, value: &str) -> Result<Option<Account>, Error> {
        let row: Option<(String, Option<String>, String, String)> = self
            .db
            .query_row(sql, params![value], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .optional()?;

        row.map(|(did, handle, email, password_scrypt)| {
            Ok(Account {
                did: did
                    .parse()
                    .map_err(|_| Error::Malformed("a stored DID that is not one"))?,
                handle: handle
                    .map(|handle| handle.parse())
                    .transpose()
                    .map_err(|_| Error::Malformed("a stored handle that is not one"))?,
                email,
                password_scrypt,
            })
        })
        .transpose()
    }
}
