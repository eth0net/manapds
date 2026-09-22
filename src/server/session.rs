//! Sessions: signing in, reading one back, exchanging it, and ending it.

use std::sync::Arc;

use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};

use crate::account::{self, Manager};
use crate::store;
use crate::xrpc::{
    self, Input,
    auth::{Access, Closing, Refresh},
};

/// What an account with no handle is called, so that the field is always a
/// handle even when nothing has been claimed.
const UNRESOLVED: &str = "handle.invalid";

/// What a client is told about the account it is signed in as.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Account {
    did: String,
    handle: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    email_confirmed: bool,
    /// Whether the repository can be read and written. Nothing here takes an
    /// account down yet, so it is always true.
    active: bool,
}

impl From<store::Account> for Account {
    fn from(account: store::Account) -> Self {
        Self {
            did: account.did.as_str().to_owned(),
            handle: account.handle.map_or_else(
                || UNRESOLVED.to_owned(),
                |handle| handle.as_str().to_owned(),
            ),
            email: Some(account.email),
            email_confirmed: false,
            active: true,
        }
    }
}

/// An account and the pair of tokens that reach it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Session {
    access_jwt: String,
    refresh_jwt: String,
    #[serde(flatten)]
    account: Account,
}

impl Session {
    fn new(credentials: account::Credentials, account: store::Account) -> Self {
        Self {
            access_jwt: credentials.access,
            refresh_jwt: credentials.refresh,
            account: account.into(),
        }
    }
}

/// What a client offers to sign in.
#[derive(Debug, Deserialize)]
pub(crate) struct SignIn {
    /// A handle, a DID, or an email address.
    identifier: String,
    /// The account's own password, or one of its app passwords.
    password: String,
}

/// `com.atproto.server.createSession`
///
/// # Errors
///
/// If the identifier and password do not name an account, or storage will not
/// answer.
pub(crate) async fn create(
    State(accounts): State<Arc<Manager>>,
    Input(input): Input<SignIn>,
) -> xrpc::Result<Json<Session>> {
    let login = accounts.login(&input.identifier, &input.password).await?;
    let credentials = accounts.open_session(&login.account.did, login.app_password.as_ref())?;
    Ok(Json(Session::new(credentials, login.account)))
}

/// `com.atproto.server.getSession`
///
/// # Errors
///
/// If the token names an account this server no longer holds, or storage will
/// not answer.
pub(crate) async fn get(
    State(accounts): State<Arc<Manager>>,
    access: Access,
) -> xrpc::Result<Json<Account>> {
    let account = accounts.account(&access.did)?.ok_or_else(missing)?;
    Ok(Json(account.into()))
}

/// `com.atproto.server.refreshSession`
///
/// # Errors
///
/// If the session has been revoked or has run out, the token names an account
/// this server no longer holds, or storage will not answer.
pub(crate) async fn refresh(
    State(accounts): State<Arc<Manager>>,
    refresh: Refresh,
) -> xrpc::Result<Json<Session>> {
    let account = accounts.account(&refresh.did)?.ok_or_else(missing)?;
    let credentials = accounts.refresh_session(&refresh.id)?.ok_or_else(|| {
        xrpc::Error::invalid_request("Token has been revoked").named("ExpiredToken")
    })?;
    Ok(Json(Session::new(credentials, account)))
}

/// `com.atproto.server.deleteSession`
///
/// # Errors
///
/// If storage will not answer. Ending a session that has already ended is not
/// one.
pub(crate) async fn delete(
    State(accounts): State<Arc<Manager>>,
    Closing(refresh): Closing,
) -> xrpc::Result<()> {
    accounts.revoke_session(&refresh.id)?;
    Ok(())
}

/// A token this server signed, naming an account it no longer holds.
fn missing() -> xrpc::Error {
    xrpc::Error::invalid_request("Could not find user info for account")
}
