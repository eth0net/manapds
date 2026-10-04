//! What another server reads to follow a repository here.

use std::sync::Arc;

use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};

use crate::account::Manager;
use crate::store;
use crate::syntax::Did;
use crate::xrpc::{self, Params};

/// Which repository to answer about.
#[derive(Debug, Deserialize)]
pub(crate) struct Wanted {
    did: String,
}

/// The commit a repository is on.
#[derive(Debug, Serialize)]
pub(crate) struct Latest {
    cid: String,
    rev: String,
}

/// Whether a repository is still hosted here, and where it has got to.
#[derive(Debug, Serialize)]
pub(crate) struct Status {
    did: String,
    /// Never false: nothing here deactivates or takes an account down, so the
    /// reason the lexicon pairs with that is never written either.
    active: bool,
    rev: String,
}

/// `com.atproto.sync.getLatestCommit`
///
/// # Errors
///
/// If nothing answers to the identifier, it holds no repository, or storage
/// will not answer.
pub(crate) async fn get_latest_commit(
    State(accounts): State<Arc<Manager>>,
    Params(query): Params<Wanted>,
) -> xrpc::Result<Json<Latest>> {
    let root = root(&accounts, &did(&query.did)?).await?;
    Ok(Json(Latest {
        cid: root.cid.to_string(),
        rev: root.rev.into_string(),
    }))
}

/// `com.atproto.sync.getRepoStatus`
///
/// # Errors
///
/// If nothing answers to the identifier, it holds no repository, or storage
/// will not answer.
pub(crate) async fn get_repo_status(
    State(accounts): State<Arc<Manager>>,
    Params(query): Params<Wanted>,
) -> xrpc::Result<Json<Status>> {
    let did = did(&query.did)?;
    let root = root(&accounts, &did).await?;
    Ok(Json(Status {
        did: did.into_string(),
        active: true,
        rev: root.rev.into_string(),
    }))
}

/// The identifier a caller named. The lexicon asks for a DID, so a handle is
/// not resolved here.
fn did(did: &str) -> xrpc::Result<Did> {
    did.parse()
        .map_err(|_| xrpc::Error::invalid_request("Invalid did"))
}

/// The root a method answers from, or the refusal owed for a repository this
/// server does not hold.
async fn root(accounts: &Manager, did: &Did) -> xrpc::Result<store::Root> {
    accounts.root(did).await?.ok_or_else(|| {
        xrpc::Error::invalid_request(format!("Could not find root for {did}")).named("RepoNotFound")
    })
}
