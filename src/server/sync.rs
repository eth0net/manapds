//! What another server reads to follow a repository here.

use std::sync::Arc;

use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};

use crate::account::Manager;
use crate::store;
use crate::syntax::Did;
use crate::xrpc::{self, Params};

/// How many repositories a page holds when the caller does not say.
const PAGE: u32 = 500;

/// The ceiling on that, however many are asked for.
const LONGEST_PAGE: u32 = 1000;

/// Which repository to answer about.
#[derive(Debug, Deserialize)]
pub(crate) struct Wanted {
    did: String,
}

/// Which page of the repositories here to answer with.
#[derive(Debug, Deserialize)]
pub(crate) struct Listing {
    limit: Option<u32>,
    cursor: Option<String>,
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

/// One repository on a page of them.
#[derive(Debug, Serialize)]
pub(crate) struct Held {
    did: String,
    head: String,
    rev: String,
    active: bool,
}

/// One page of them.
#[derive(Debug, Serialize)]
pub(crate) struct Page {
    #[serde(skip_serializing_if = "Option::is_none")]
    cursor: Option<String>,
    repos: Vec<Held>,
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

/// `com.atproto.sync.listRepos`
///
/// # Errors
///
/// If the cursor is not one this server handed out, or storage will not
/// answer.
pub(crate) async fn list_repos(
    State(accounts): State<Arc<Manager>>,
    Params(query): Params<Listing>,
) -> xrpc::Result<Json<Page>> {
    let limit = query.limit.unwrap_or(PAGE).clamp(1, LONGEST_PAGE);
    let from = query.cursor.as_deref().map(starting).transpose()?;
    let held = accounts.repos(limit, from).await?;

    let cursor = (u32::try_from(held.len()).unwrap_or(u32::MAX) == limit)
        .then(|| held.last().map(after))
        .flatten();
    Ok(Json(Page {
        cursor,
        repos: held.into_iter().map(shown).collect(),
    }))
}

/// Where a cursor says to pick up.
fn starting(cursor: &str) -> xrpc::Result<store::Cursor> {
    let malformed = || xrpc::Error::invalid_request("Malformed cursor");
    let (at, did) = cursor.split_once("::").ok_or_else(malformed)?;
    let created_at = at
        .parse()
        .ok()
        .and_then(|millis| jiff::Timestamp::from_millisecond(millis).ok())
        .ok_or_else(malformed)?;
    Ok(store::Cursor {
        created_at,
        did: did.to_owned(),
    })
}

/// The cursor that carries on after an account, written the way the reference
/// writes one so that either server reads the other's.
fn after(hosted: &store::Hosted) -> String {
    format!("{}::{}", hosted.created_at.as_millisecond(), hosted.did)
}

/// One repository, in the shape a page carries it.
fn shown(hosted: store::Hosted) -> Held {
    Held {
        did: hosted.did.into_string(),
        head: hosted.root.cid.to_string(),
        rev: hosted.root.rev.into_string(),
        active: true,
    }
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
