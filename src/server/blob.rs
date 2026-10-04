//! Blobs: taking one in, handing it back, and listing what records name.

use std::sync::Arc;

use axum::{
    Json,
    body::Bytes,
    extract::{State, rejection::BytesRejection},
    http::{HeaderMap, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use crate::account::Manager;
use crate::store;
use crate::syntax::{Did, Tid};
use crate::xrpc::{self, Params, auth::Access};

/// What an upload is taken as when the caller says nothing.
const UNSAID: &str = "application/octet-stream";

/// What a page holds when the caller does not ask for a size.
const PAGE: u32 = 500;

/// The most any page holds, however many are asked for.
const LONGEST_PAGE: u32 = 1000;

/// Which blob to serve, and whose.
#[derive(Debug, Deserialize)]
pub(crate) struct Wanted {
    did: String,
    cid: String,
}

/// Whose blobs to page through, and from where.
#[derive(Debug, Deserialize)]
pub(crate) struct Listing {
    did: String,
    since: Option<String>,
    limit: Option<u32>,
    cursor: Option<String>,
}

/// One page of the blobs an account's records name.
#[derive(Debug, Serialize)]
pub(crate) struct Page {
    #[serde(skip_serializing_if = "Option::is_none")]
    cursor: Option<String>,
    cids: Vec<String>,
}

/// Which page of the blobs nothing uploaded to ask for.
#[derive(Debug, Deserialize)]
pub(crate) struct Missing {
    limit: Option<u32>,
    cursor: Option<String>,
}

/// One page of the blobs a record names that nothing uploaded.
#[derive(Debug, Serialize)]
pub(crate) struct MissingPage {
    #[serde(skip_serializing_if = "Option::is_none")]
    cursor: Option<String>,
    blobs: Vec<RecordBlob>,
}

/// One of them, beside a record naming it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RecordBlob {
    cid: String,
    record_uri: String,
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
    body: Result<Bytes, BytesRejection>,
) -> xrpc::Result<Json<Uploaded>> {
    // The only route whose body is read whole, so the only one whose refusal
    // does not already come back in the XRPC shape.
    let body = body.map_err(|rejection| {
        xrpc::Error::new(xrpc::Status::PayloadTooLarge).saying(rejection.body_text())
    })?;
    let mime = headers
        .get(header::CONTENT_TYPE)
        .and_then(|mime| mime.to_str().ok())
        // A charset says nothing about what the bytes are, and what a record
        // holds has to match the type an appview's lexicon will accept.
        .map(|mime| mime.split(';').next().unwrap_or(mime).trim())
        .filter(|mime| !mime.is_empty())
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
    // The lexicon asks for a DID here rather than a handle, so nothing is
    // resolved: a blob is served by whoever holds it or by nobody.
    let did: Did = query
        .did
        .parse()
        .map_err(|_| xrpc::Error::invalid_request("Invalid did"))?;
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
            // Anyone's bytes under this server's origin, so a browser is told
            // three times over not to run them.
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_owned()),
            (header::CONTENT_DISPOSITION, "attachment".to_owned()),
            (
                header::CONTENT_SECURITY_POLICY,
                "default-src 'none'; sandbox".to_owned(),
            ),
        ],
        bytes,
    )
        .into_response())
}

/// `com.atproto.sync.listBlobs`
///
/// # Errors
///
/// If the identifier is not a DID or `since` is not a revision, nothing
/// answers to the identifier, or storage will not answer.
pub(crate) async fn list(
    State(accounts): State<Arc<Manager>>,
    Params(query): Params<Listing>,
) -> xrpc::Result<Json<Page>> {
    let did: Did = query
        .did
        .parse()
        .map_err(|_| xrpc::Error::invalid_request("Invalid did"))?;
    let since = query
        .since
        .map(|since| {
            since
                .parse::<Tid>()
                .map_err(|_| xrpc::Error::invalid_request("Invalid since"))
        })
        .transpose()?;
    let limit = query.limit.unwrap_or(PAGE).clamp(1, LONGEST_PAGE);
    let cids: Vec<String> = accounts
        .blobs(&did, since, limit, query.cursor)
        .await?
        .iter()
        .map(ToString::to_string)
        .collect();

    // A short page carries no cursor, which is what stops a client asking.
    let cursor = (u32::try_from(cids.len()).unwrap_or(u32::MAX) == limit)
        .then(|| cids.last().cloned())
        .flatten();
    Ok(Json(Page { cursor, cids }))
}

/// `com.atproto.repo.listMissingBlobs`
///
/// # Errors
///
/// If the caller holds no repository, or storage will not answer.
pub(crate) async fn list_missing(
    State(accounts): State<Arc<Manager>>,
    access: Access,
    Params(query): Params<Missing>,
) -> xrpc::Result<Json<MissingPage>> {
    let limit = query.limit.unwrap_or(PAGE).clamp(1, LONGEST_PAGE);
    let blobs: Vec<RecordBlob> = accounts
        .missing_blobs(&access.did, limit, query.cursor)
        .await?
        .into_iter()
        .map(|missing| RecordBlob {
            cid: missing.cid.to_string(),
            record_uri: missing.uri,
        })
        .collect();

    let cursor = (u32::try_from(blobs.len()).unwrap_or(u32::MAX) == limit)
        .then(|| blobs.last().map(|last| last.cid.clone()))
        .flatten();
    Ok(Json(MissingPage { cursor, blobs }))
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
