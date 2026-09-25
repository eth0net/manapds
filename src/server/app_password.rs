//! App passwords: writing one, listing them, and taking one away.

use std::sync::Arc;

use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};

use crate::account::Manager;
use crate::store;
use crate::xrpc::{
    self, Input,
    auth::{Access, Full},
};

/// What a client asks for when it wants one.
#[derive(Debug, Deserialize)]
pub(crate) struct Wanted {
    /// What the account will call it, and what revoking it names.
    name: String,
    #[serde(default)]
    privileged: bool,
}

/// One app password, including the password itself.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Written {
    name: String,
    password: String,
    created_at: String,
    privileged: bool,
}

/// One app password as a listing shows it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Held {
    name: String,
    created_at: String,
    privileged: bool,
}

/// Every app password an account holds.
#[derive(Debug, Serialize)]
pub(crate) struct Passwords {
    passwords: Vec<Held>,
}

/// Which one to take away.
#[derive(Debug, Deserialize)]
pub(crate) struct Named {
    name: String,
}

/// `com.atproto.server.createAppPassword`
///
/// # Errors
///
/// If the account already holds one under that name, or storage will not
/// answer.
pub(crate) async fn create(
    State(accounts): State<Arc<Manager>>,
    Full(access): Full,
    Input(input): Input<Wanted>,
) -> xrpc::Result<Json<Written>> {
    let written = accounts
        .create_app_password(&access.did, input.name, input.privileged)
        .await?;
    Ok(Json(Written {
        name: written.name,
        password: written.password,
        created_at: store::stamp(written.created_at),
        privileged: written.privileged,
    }))
}

/// `com.atproto.server.listAppPasswords`
///
/// # Errors
///
/// If storage will not answer.
pub(crate) async fn list(
    State(accounts): State<Arc<Manager>>,
    access: Access,
) -> xrpc::Result<Json<Passwords>> {
    let passwords = accounts
        .app_passwords(&access.did)?
        .into_iter()
        .map(|(password, created_at)| Held {
            name: password.name,
            created_at: store::stamp(created_at),
            privileged: password.privileged,
        })
        .collect();
    Ok(Json(Passwords { passwords }))
}

/// `com.atproto.server.revokeAppPassword`
///
/// # Errors
///
/// If storage will not answer.
pub(crate) async fn revoke(
    State(accounts): State<Arc<Manager>>,
    access: Access,
    Input(input): Input<Named>,
) -> xrpc::Result<()> {
    accounts.revoke_app_password(&access.did, &input.name)?;
    Ok(())
}
