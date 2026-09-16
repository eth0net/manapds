//! The account database: who has an account here, what they are called, what
//! they sign in with, and what they have authorized.
//!
//! The OAuth tables are built even though nothing serves OAuth yet, because a
//! database has to be the shape the reference left it in whichever server
//! opens it next.

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

/// The authorization server's own tables.
const OAUTH: &str = r#"
create table "authorization_request" ("id" varchar primary key, "did" varchar, "deviceId" varchar, "clientId" varchar not null, "clientAuth" varchar not null, "parameters" varchar not null, "expiresAt" varchar not null, "code" varchar);
create unique index "authorization_request_code_idx" on "authorization_request" (code DESC) WHERE (code IS NOT NULL);
create index "authorization_request_expires_at_idx" on "authorization_request" ("expiresAt");

create table "device" ("id" varchar primary key, "sessionId" varchar not null, "userAgent" varchar, "ipAddress" varchar not null, "lastSeenAt" varchar not null, constraint "device_session_id_idx" unique ("sessionId"));

create table "device_account" ("did" varchar not null, "deviceId" varchar not null, "authenticatedAt" varchar not null, "remember" boolean not null, "authorizedClients" varchar not null, constraint "device_account_pk" primary key ("deviceId", "did"), constraint "device_account_device_id_fk" foreign key ("deviceId") references "device" ("id") on delete cascade on update cascade);

create table "token" ("id" integer primary key autoincrement, "did" varchar not null, "tokenId" varchar not null, "createdAt" varchar not null, "updatedAt" varchar not null, "expiresAt" varchar not null, "clientId" varchar not null, "clientAuth" varchar not null, "deviceId" varchar, "parameters" varchar not null, "details" varchar, "code" varchar, "currentRefreshToken" varchar, constraint "token_current_refresh_token_unique_idx" unique ("currentRefreshToken"), constraint "token_id_unique_idx" unique ("tokenId"));
create index "token_did_idx" on "token" ("did");
create unique index "token_code_idx" on "token" (code DESC) WHERE (code IS NOT NULL);

create table "used_refresh_token" ("refreshToken" varchar primary key, "tokenId" integer not null, constraint "used_refresh_token_fk" foreign key ("tokenId") references "token" ("id") on delete cascade on update cascade);
create index "used_refresh_token_id_idx" on "used_refresh_token" ("tokenId");
"#;

/// What replaces `device_account`, which this migration empties into it.
const ACCOUNT_DEVICE: &str = r#"
create table if not exists "account_device" ("did" varchar not null, "deviceId" varchar not null, "createdAt" varchar not null, "updatedAt" varchar not null, constraint "account_device_pk" primary key ("deviceId", "did"), constraint "account_device_did_fk" foreign key ("did") references "account" ("did") on delete cascade on update cascade, constraint "account_device_device_id_fk" foreign key ("deviceId") references "device" ("id") on delete cascade on update cascade);
"#;

/// Everything 005 adds once the old table has been carried across.
const AUTHORIZED_CLIENT: &str = r#"
create index "account_device_did_idx" on "account_device" ("did");

create table "authorized_client" ("did" varchar not null, "clientId" varchar not null, "createdAt" varchar not null, "updatedAt" varchar not null, "data" varchar not null, constraint "authorized_client_pk" primary key ("did", "clientId"), constraint "authorized_client_did_fk" foreign key ("did") references "account" ("did") on delete cascade on update cascade);
"#;

/// Scopes on a token, and the lexicons an account has published.
const PERMISSION_SETS: &str = r#"
alter table "token" add column "scope" varchar;

create table "lexicon" ("nsid" varchar primary key, "createdAt" varchar not null, "updatedAt" varchar not null, "lastSucceededAt" varchar, "uri" varchar, "lexicon" varchar);
"#;

/// Finding the lexicons that failed to resolve.
const LEXICON_FAILURES: &str = r#"
create index "lexicon_failures_idx" on "lexicon" ("updatedAt" DESC) WHERE ("lexicon" is NULL);
"#;

/// A device session nobody asked to be remembered is not kept past the hour.
const FORGET_UNREMEMBERED: &str =
    r#"delete from "device_account" where "remember" = 0 and "authenticatedAt" < ?1"#;

/// Only sessions asked to be remembered, and only for accounts still here,
/// which is what the foreign key the new table carries would require.
const CARRY_DEVICES: &str = r#"
insert into "account_device" ("did", "deviceId", "createdAt", "updatedAt")
select "did", "deviceId", "authenticatedAt", "authenticatedAt" from "device_account"
where "remember" = 1
  and exists (select 1 from "account" where "account"."did" = "device_account"."did")
on conflict do nothing
"#;

/// Every migration this server knows, in the order they are applied.
const MIGRATIONS: [db::Migration; 7] = [
    ("001", |tx| Ok(tx.execute_batch(INIT)?)),
    ("002", |tx| Ok(tx.execute_batch(DEACTIVATION)?)),
    ("003", |tx| Ok(tx.execute_batch(PRIVILEGED_APP_PASSWORDS)?)),
    ("004", |tx| Ok(tx.execute_batch(OAUTH)?)),
    ("005", |tx| {
        let hour_ago = jiff::Timestamp::now() - jiff::SignedDuration::from_hours(1);
        tx.execute(FORGET_UNREMEMBERED, params![format!("{hour_ago:.3}")])?;
        tx.execute_batch(ACCOUNT_DEVICE)?;
        tx.execute(CARRY_DEVICES, [])?;
        tx.execute_batch(AUTHORIZED_CLIENT)?;
        Ok(())
    }),
    ("006", |tx| Ok(tx.execute_batch(PERMISSION_SETS)?)),
    ("007", |tx| Ok(tx.execute_batch(LEXICON_FAILURES)?)),
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
