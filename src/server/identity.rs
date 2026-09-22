//! Turning a name into the identity behind it.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Query, State},
};
use serde::{Deserialize, Serialize};

use crate::account::Manager;
use crate::xrpc;

#[derive(Debug, Deserialize)]
pub(crate) struct Resolve {
    handle: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct Resolved {
    did: String,
}

/// `com.atproto.identity.resolveHandle`
///
/// # Errors
///
/// If the handle is not one, nothing here answers to it, or storage will not
/// answer.
pub(crate) async fn resolve_handle(
    State(accounts): State<Arc<Manager>>,
    Query(query): Query<Resolve>,
) -> xrpc::Result<Json<Resolved>> {
    let handle = accounts
        .rules()
        .normalize(&query.handle)
        .map_err(|invalid| {
            xrpc::Error::invalid_request(invalid.to_string()).named(invalid.name())
        })?;

    // todo(resolver): a handle under somebody else's domain is theirs to
    // answer for, and reaching them needs DNS and an HTTP fetch.
    accounts
        .resolve(&handle)?
        .map(|did| {
            Json(Resolved {
                did: did.as_str().to_owned(),
            })
        })
        .ok_or_else(|| {
            xrpc::Error::invalid_request("Unable to resolve handle").named("HandleNotFound")
        })
}
