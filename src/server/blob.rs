//! Blobs: taking one in, and handing it back.

use std::sync::Arc;

use axum::{
    Json,
    body::Bytes,
    extract::State,
    http::{HeaderMap, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use crate::account::Manager;
use crate::store;
use crate::syntax::{AtIdentifier, Did};
use crate::xrpc::{self, Params, auth::Access};

/// What an upload is taken as when the caller says nothing.
const UNSAID: &str = "application/octet-stream";

/// Which blob to serve, and whose.
#[derive(Debug, Deserialize)]
pub(crate) struct Wanted {
    did: String,
    cid: String,
}

/// A blob as a record refers to one.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Reference {
    #[serde(rename = "$type")]
    kind: &'static str,
    #[serde(rename = "ref")]
    link: Link,
    mime_type: String,
    size: u64,
}

/// The CID inside one, in the shape JSON writes a link.
#[derive(Debug, Serialize)]
pub(crate) struct Link {
    #[serde(rename = "$link")]
    link: String,
}

/// What an upload answers with.
#[derive(Debug, Serialize)]
pub(crate) struct Uploaded {
    blob: Reference,
}

/// `com.atproto.repo.uploadBlob`
///
/// # Errors
///
/// If the account holds no repository, or storage will not answer.
pub(crate) async fn upload(
    State(accounts): State<Arc<Manager>>,
    access: Access,
    headers: HeaderMap,
    body: Bytes,
) -> xrpc::Result<Json<Uploaded>> {
    let mime = headers
        .get(header::CONTENT_TYPE)
        .and_then(|mime| mime.to_str().ok())
        .unwrap_or(UNSAID)
        .to_owned();
    let blob = accounts
        .upload_blob(&access.did, mime, body.to_vec())
        .await?;
    Ok(Json(Uploaded { blob: shown(&blob) }))
}

/// `com.atproto.sync.getBlob`
///
/// # Errors
///
/// If nothing answers to the identifier, it uploaded no such blob, or storage
/// will not answer.
pub(crate) async fn get(
    State(accounts): State<Arc<Manager>>,
    Params(query): Params<Wanted>,
) -> xrpc::Result<Response> {
    let did = held(&accounts, &query.did).await?;
    let cid = query
        .cid
        .parse()
        .map_err(|_| xrpc::Error::invalid_request("Invalid cid"))?;
    let (blob, bytes) = accounts
        .blob(&did, &cid)
        .await?
        .ok_or_else(|| xrpc::Error::invalid_request("Blob not found").named("BlobNotFound"))?;

    Ok((
        [
            (header::CONTENT_TYPE, blob.mime),
            // A blob is addressed by its bytes, so nothing it is served under
            // can ever be a different blob.
            (
                header::CACHE_CONTROL,
                "public, max-age=31536000, immutable".to_owned(),
            ),
        ],
        bytes,
    )
        .into_response())
}

/// The account an at-identifier names.
async fn held(accounts: &Manager, did: &str) -> xrpc::Result<Did> {
    let identifier: AtIdentifier = did
        .parse()
        .map_err(|_| xrpc::Error::invalid_request("Invalid did"))?;
    Ok(accounts
        .lookup(&identifier)
        .await?
        .ok_or_else(|| {
            xrpc::Error::invalid_request(format!("Could not find repo: {did}"))
                .named("RepoNotFound")
        })?
        .did)
}

/// One stored blob, in the shape a record would name it.
fn shown(blob: &store::Blob) -> Reference {
    Reference {
        kind: "blob",
        link: Link {
            link: blob.cid.to_string(),
        },
        mime_type: blob.mime.clone(),
        size: blob.size,
    }
}
