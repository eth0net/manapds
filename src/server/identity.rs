//! Turning a name into the identity behind it.

use std::sync::Arc;

use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};

use crate::account::Manager;
use crate::xrpc::{self, Params};

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
    Params(query): Params<Resolve>,
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
            let unresolved = xrpc::Error::invalid_request("Unable to resolve handle");
            // Only a name this server answers for is one it can say does not
            // exist. For anyone else's, not knowing is all this means.
            if accounts.rules().is_local(&handle) {
                unresolved.named("HandleNotFound")
            } else {
                unresolved
            }
        })
}
