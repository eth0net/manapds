//! Signing up: the one method that mints an identity.

use std::sync::Arc;

use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};

use crate::account::{Manager, Signup};
use crate::xrpc::{self, Input};

/// What a client asks for when it signs up.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Create {
    /// The name it wants.
    handle: String,
    /// Where password resets and confirmations will go.
    email: String,
    /// What it will sign in with.
    password: String,
    /// The code it came in on, where the server asks for one.
    invite_code: Option<String>,
    /// A `did:key` that outranks this server's, so whoever holds it can take
    /// the account back.
    recovery_key: Option<String>,
    /// An identity created somewhere else, which is half of moving an account
    /// here and is not served yet.
    did: Option<String>,
    /// The operation that would register it.
    plc_op: Option<serde_json::Value>,
}

/// The account, and the session it is handed on the way out.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Created {
    did: String,
    handle: String,
    access_jwt: String,
    refresh_jwt: String,
}

/// `com.atproto.server.createAccount`
///
/// # Errors
///
/// If the handle, email, password or invite will not do, either is already
/// held, or storage or the directory will not answer.
pub(crate) async fn create(
    State(accounts): State<Arc<Manager>>,
    Input(input): Input<Create>,
) -> xrpc::Result<Json<Created>> {
    for (field, brought) in [
        ("did", input.did.is_some()),
        ("plcOp", input.plc_op.is_some()),
    ] {
        if brought {
            return Err(xrpc::Error::invalid_request(format!(
                "Unsupported input: \"{field}\""
            )));
        }
    }
    let recovery_key = input
        .recovery_key
        .as_deref()
        .map(str::parse)
        .transpose()
        .map_err(|_| {
            xrpc::Error::invalid_request("Invalid recovery key").named("IncompatibleDidDoc")
        })?;

    let created = accounts
        .create(&Signup {
            handle: input.handle,
            email: input.email,
            password: input.password,
            invite: input.invite_code,
            recovery_key,
        })
        .await?;

    // todo(resolver): the DID document goes back with this, once something
    // here can read one.
    Ok(Json(Created {
        did: created.did.as_str().to_owned(),
        handle: created.handle.as_str().to_owned(),
        access_jwt: created.credentials.access,
        refresh_jwt: created.credentials.refresh,
    }))
}
