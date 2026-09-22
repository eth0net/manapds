//! The account database: who has an account here, what they are called, what
//! they sign in with, and what they have authorized.
//!
//! The OAuth tables are built even though nothing serves OAuth yet, because a
//! database has to be the shape the reference left it in whichever server
//! opens it next.

use jiff::Timestamp;
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
        let hour_ago = Timestamp::now() - jiff::SignedDuration::from_hours(1);
        tx.execute(FORGET_UNREMEMBERED, params![stamp(hour_ago)])?;
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

/// An app password, by what it is called and what it is trusted with.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppPassword {
    /// What the account called it when it asked for one.
    pub name: String,
    /// Whether it reaches more than posting.
    pub privileged: bool,
}

/// A session, held open by the refresh token this row is keyed on.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Session {
    /// The `jti` the refresh token carries.
    pub id: String,
    /// Whose session it is.
    pub did: Did,
    /// When the token stops being exchangeable.
    pub expires_at: Timestamp,
    /// The id the next exchange will hand out, once one has been asked for.
    pub next_id: Option<String>,
    /// The app password the session was opened with, if a password was not.
    pub app_password: Option<AppPassword>,
}

/// Everything written the moment an account exists: who it is, where its
/// repository starts, the invite it came in on, and the session it leaves
/// with.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Registration {
    /// The account itself.
    pub account: Account,
    /// The commit its repository was created at.
    pub root: super::Root,
    /// The code spent to get in, where one was needed.
    pub invite: Option<String>,
    /// The session the caller is handed back.
    pub session: Option<Session>,
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

    /// Writes a new account and everything that comes with it, or none of it.
    ///
    /// The invite is checked here rather than before, so that two signups
    /// cannot both spend the last use of one code.
    ///
    /// Handles and emails are unique without regard to case, which is the
    /// index's doing rather than this function's.
    ///
    /// # Errors
    ///
    /// If the handle or email is already in use, the code cannot be spent, or
    /// the write fails.
    pub fn create(&mut self, registration: &Registration) -> Result<(), Error> {
        let account = &registration.account;
        let now = stamp(Timestamp::now());
        let transaction = self.db.transaction()?;

        if let Some(code) = &registration.invite {
            if !available(&transaction, code)? {
                return Err(Error::InviteUnavailable);
            }
            transaction.execute(
                r#"insert into "invite_code_use" ("code", "usedBy", "usedAt")
                   values (?1, ?2, ?3)"#,
                params![code, account.did.as_str(), now],
            )?;
        }

        transaction.execute(
            r#"insert into "actor" ("did", "handle", "createdAt") values (?1, ?2, ?3)"#,
            params![
                account.did.as_str(),
                account.handle.as_ref().map(Handle::as_str),
                now
            ],
        )?;
        transaction.execute(
            r#"insert into "account" ("did", "email", "passwordScrypt", "invitesDisabled")
               values (?1, ?2, ?3, 0)"#,
            params![account.did.as_str(), account.email, account.password_scrypt],
        )?;
        transaction.execute(
            r#"insert into "repo_root" ("did", "cid", "rev", "indexedAt") values (?1, ?2, ?3, ?4)
               on conflict("did") do update set "cid" = ?2, "rev" = ?3"#,
            params![
                account.did.as_str(),
                registration.root.cid.to_string(),
                registration.root.rev.as_str(),
                now
            ],
        )?;
        if let Some(session) = &registration.session {
            store_session(&transaction, session)?;
        }

        transaction.commit()?;
        Ok(())
    }

    /// Takes an account and everything hanging off it back out, which is what
    /// undoing a half-finished signup means.
    ///
    /// # Errors
    ///
    /// If the write fails.
    pub fn delete(&mut self, did: &Did) -> Result<(), Error> {
        let transaction = self.db.transaction()?;
        for table in [
            "refresh_token",
            "app_password",
            "invite_code_use",
            "repo_root",
            "account",
            "actor",
        ] {
            // The column naming the account is `usedBy` in one table and `did`
            // in the rest.
            let column = if table == "invite_code_use" {
                "usedBy"
            } else {
                "did"
            };
            transaction.execute(
                &format!(r#"delete from "{table}" where "{column}" = ?1"#),
                params![did.as_str()],
            )?;
        }
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

    /// Writes a session, leaving any row already under that id alone.
    ///
    /// # Errors
    ///
    /// If the write fails.
    pub fn store_session(&self, session: &Session) -> Result<(), Error> {
        store_session(&self.db, session)
    }

    /// The session a refresh token names, carrying what its app password may
    /// do now rather than what it could when the session opened.
    ///
    /// # Errors
    ///
    /// If a row holds a DID or a timestamp nothing here writes.
    pub fn session(&self, id: &str) -> Result<Option<Session>, Error> {
        let row: Option<SessionRow> = self
            .db
            .query_row(
                r#"select "refresh_token"."did", "refresh_token"."expiresAt",
                          "refresh_token"."nextId", "refresh_token"."appPasswordName",
                          "app_password"."privileged"
                   from "refresh_token"
                   left join "app_password"
                     on "app_password"."did" = "refresh_token"."did"
                    and "app_password"."name" = "refresh_token"."appPasswordName"
                   where "refresh_token"."id" = ?1"#,
                params![id],
                |row| {
                    Ok(SessionRow {
                        did: row.get(0)?,
                        expires_at: row.get(1)?,
                        next_id: row.get(2)?,
                        name: row.get(3)?,
                        privileged: row.get(4)?,
                    })
                },
            )
            .optional()?;

        row.map(|row| {
            Ok(Session {
                id: id.to_owned(),
                did: row
                    .did
                    .parse()
                    .map_err(|_| Error::Malformed("a stored DID that is not one"))?,
                expires_at: row
                    .expires_at
                    .parse()
                    .map_err(|_| Error::Malformed("a stored timestamp that is not one"))?,
                next_id: row.next_id,
                app_password: row.name.map(|name| AppPassword {
                    name,
                    privileged: row.privileged == Some(1),
                }),
            })
        })
        .transpose()
    }

    /// Shortens a session to the grace period it has left and names what
    /// replaces it, so that a client retrying an exchange is handed the same
    /// session rather than a second one.
    ///
    /// Answers false when another exchange got there first under a different
    /// successor, which is the caller's signal to read the row again.
    ///
    /// # Errors
    ///
    /// If the write fails.
    pub fn hold_session(&self, id: &str, until: Timestamp, next: &str) -> Result<bool, Error> {
        let updated = self.db.execute(
            r#"update "refresh_token" set "expiresAt" = ?2, "nextId" = ?3
               where "id" = ?1 and ("nextId" is null or "nextId" = ?3)"#,
            params![id, stamp(until), next],
        )?;
        Ok(updated > 0)
    }

    /// Ends one session.
    ///
    /// # Errors
    ///
    /// If the write fails.
    pub fn revoke_session(&self, id: &str) -> Result<bool, Error> {
        let deleted = self.db.execute(
            r#"delete from "refresh_token" where "id" = ?1"#,
            params![id],
        )?;
        Ok(deleted > 0)
    }

    /// Ends every session an account has, which is what a password change is
    /// for.
    ///
    /// # Errors
    ///
    /// If the write fails.
    pub fn revoke_sessions(&self, did: &Did) -> Result<usize, Error> {
        Ok(self.db.execute(
            r#"delete from "refresh_token" where "did" = ?1"#,
            params![did.as_str()],
        )?)
    }

    /// Clears out what has already run out. Housekeeping rather than
    /// revocation: an expired token is refused whether or not its row is
    /// still there.
    ///
    /// # Errors
    ///
    /// If the write fails.
    pub fn expire_sessions(&self, did: &Did, now: Timestamp) -> Result<usize, Error> {
        Ok(self.db.execute(
            r#"delete from "refresh_token" where "did" = ?1 and "expiresAt" <= ?2"#,
            params![did.as_str(), stamp(now)],
        )?)
    }

    /// The account this email belongs to, whatever case it is asked in.
    ///
    /// # Errors
    ///
    /// If a row holds a DID or handle nothing here writes.
    pub fn by_email(&self, email: &str) -> Result<Option<Account>, Error> {
        self.query(
            r#"select "actor"."did", "actor"."handle", "account"."email", "account"."passwordScrypt"
               from "actor" join "account" on "account"."did" = "actor"."did"
               where lower("account"."email") = lower(?1)"#,
            email,
        )
    }

    /// Writes an app password, under the hash a session will be looked up by.
    ///
    /// # Errors
    ///
    /// If the account already has one by that name, or the write fails.
    pub fn create_app_password(
        &self,
        did: &Did,
        password: &AppPassword,
        hash: &str,
    ) -> Result<(), Error> {
        self.db.execute(
            r#"insert into "app_password"
               ("did", "name", "passwordScrypt", "createdAt", "privileged")
               values (?1, ?2, ?3, ?4, ?5)"#,
            params![
                did.as_str(),
                password.name,
                hash,
                stamp(Timestamp::now()),
                i64::from(password.privileged),
            ],
        )?;
        Ok(())
    }

    /// The app password with this hash, which is how one is checked: they are
    /// salted with the account, so the hash is the lookup.
    ///
    /// # Errors
    ///
    /// If the read fails.
    pub fn app_password(&self, did: &Did, hash: &str) -> Result<Option<AppPassword>, Error> {
        Ok(self
            .db
            .query_row(
                r#"select "name", "privileged" from "app_password"
                   where "did" = ?1 and "passwordScrypt" = ?2"#,
                params![did.as_str(), hash],
                |row| {
                    Ok(AppPassword {
                        name: row.get(0)?,
                        privileged: row.get::<_, i64>(1)? == 1,
                    })
                },
            )
            .optional()?)
    }

    /// Every app password an account holds, newest first.
    ///
    /// # Errors
    ///
    /// If a row holds a timestamp nothing here writes.
    pub fn app_passwords(&self, did: &Did) -> Result<Vec<(AppPassword, Timestamp)>, Error> {
        self.db
            .prepare(
                r#"select "name", "privileged", "createdAt" from "app_password"
                   where "did" = ?1 order by "createdAt" desc"#,
            )?
            .query_map(params![did.as_str()], |row| {
                Ok((
                    AppPassword {
                        name: row.get(0)?,
                        privileged: row.get::<_, i64>(1)? == 1,
                    },
                    row.get::<_, String>(2)?,
                ))
            })?
            .map(|row| {
                let (password, created_at) = row?;
                Ok((
                    password,
                    created_at
                        .parse()
                        .map_err(|_| Error::Malformed("a stored timestamp that is not one"))?,
                ))
            })
            .collect()
    }

    /// Takes an app password away, along with the sessions opened with it.
    ///
    /// # Errors
    ///
    /// If the write fails.
    pub fn revoke_app_password(&mut self, did: &Did, name: &str) -> Result<bool, Error> {
        let transaction = self.db.transaction()?;
        let deleted = transaction.execute(
            r#"delete from "app_password" where "did" = ?1 and "name" = ?2"#,
            params![did.as_str(), name],
        )?;
        transaction.execute(
            r#"delete from "refresh_token" where "did" = ?1 and "appPasswordName" = ?2"#,
            params![did.as_str(), name],
        )?;
        transaction.commit()?;
        Ok(deleted > 0)
    }

    /// Writes invite codes, all for one account and all with the same number
    /// of uses.
    ///
    /// The account is a string rather than a DID: a code the server itself
    /// hands out belongs to `admin`, which is nobody.
    ///
    /// # Errors
    ///
    /// If a code is already there, or the write fails.
    pub fn create_invites(
        &mut self,
        codes: &[String],
        for_account: &str,
        created_by: &str,
        uses: u32,
    ) -> Result<(), Error> {
        let now = stamp(Timestamp::now());
        let transaction = self.db.transaction()?;
        for code in codes {
            transaction.execute(
                r#"insert into "invite_code"
                   ("code", "availableUses", "disabled", "forAccount", "createdBy", "createdAt")
                   values (?1, ?2, 0, ?3, ?4, ?5)"#,
                params![code, uses, for_account, created_by, now],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// Whether a code can still be spent: it exists, was not disabled, has a
    /// use left, and belongs to an account that has not been taken down.
    ///
    /// # Errors
    ///
    /// If the read fails.
    pub fn invite_available(&self, code: &str) -> Result<bool, Error> {
        available(&self.db, code)
    }

    /// Spends one use of a code.
    ///
    /// # Errors
    ///
    /// If the account has already used that code, or the write fails.
    pub fn spend_invite(&self, code: &str, did: &Did) -> Result<(), Error> {
        self.db.execute(
            r#"insert into "invite_code_use" ("code", "usedBy", "usedAt") values (?1, ?2, ?3)"#,
            params![code, did.as_str(), stamp(Timestamp::now())],
        )?;
        Ok(())
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

/// Written both on its own and as part of a registration, so the statement has
/// one owner.
fn store_session(db: &Connection, session: &Session) -> Result<(), Error> {
    db.execute(
        r#"insert or ignore into "refresh_token" ("id", "did", "expiresAt", "appPasswordName")
           values (?1, ?2, ?3, ?4)"#,
        params![
            session.id,
            session.did.as_str(),
            stamp(session.expires_at),
            session.app_password.as_ref().map(|password| &password.name),
        ],
    )?;
    Ok(())
}

/// Whether a code can still be spent: it exists, was not disabled, has a use
/// left, and belongs to an account that has not been taken down.
fn available(db: &Connection, code: &str) -> Result<bool, Error> {
    Ok(db
        .query_row(
            r#"select 1 from "invite_code"
               left join "actor" on "actor"."did" = "invite_code"."forAccount"
               where "invite_code"."code" = ?1
                 and "invite_code"."disabled" = 0
                 and "actor"."takedownRef" is null
                 and "invite_code"."availableUses" >
                     (select count(*) from "invite_code_use" where "code" = ?1)"#,
            params![code],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

/// One row of the session join, before any of it is read as more than text.
struct SessionRow {
    did: String,
    expires_at: String,
    next_id: Option<String>,
    name: Option<String>,
    privileged: Option<i64>,
}

/// Milliseconds and a `Z`, which is what the other server writes and what
/// makes a text column sort as time.
fn stamp(at: Timestamp) -> String {
    format!("{at:.3}")
}
