//! Event bodies: what a consumer is handed when something happens to a
//! repository.
//!
//! The log stores these without looking inside one, so the shapes live here
//! rather than next to it. Every field is the reference's, down to the two
//! that are deprecated and still required.

use serde::Serialize;

use crate::repo::{BlockMap, Cid, Error, Store, car, encode};
use crate::store::Event;
use crate::syntax::{Did, Handle, Tid};

/// An entry built and waiting for the log.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Body {
    /// Which kind of entry it is.
    pub event: Event,
    /// The dag-cbor a consumer decodes.
    pub bytes: Vec<u8>,
}

/// What one commit did to one record.
#[derive(Debug, Serialize)]
pub struct Op {
    /// `create`, `update` or `delete`.
    pub action: &'static str,
    /// The collection and the record key, joined by a slash.
    pub path: String,
    /// Where the record landed, or null where it was deleted.
    pub cid: Option<Cid>,
    /// What stood there before, left out entirely where nothing did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev: Option<Cid>,
}

/// A handle or DID document changed.
#[derive(Debug, Serialize)]
struct Identity<'a> {
    did: &'a Did,
    handle: &'a Handle,
}

/// An account became reachable or stopped being.
#[derive(Debug, Serialize)]
struct Account<'a> {
    did: &'a Did,
    active: bool,
}

/// A commit was written.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Append<'a> {
    repo: &'a Did,
    commit: Cid,
    rev: &'a Tid,
    since: Option<&'a Tid>,
    #[serde(with = "serde_bytes")]
    blocks: Vec<u8>,
    ops: &'a [Op],
    /// Left out entirely when there is no revision before this one.
    #[serde(skip_serializing_if = "Option::is_none")]
    prev_data: Option<Cid>,
    rebase: bool,
    too_big: bool,
    blobs: &'a [Cid],
}

/// Where a repository is now, for a consumer that fell behind.
#[derive(Debug, Serialize)]
struct Sync<'a> {
    did: &'a Did,
    rev: &'a Tid,
    #[serde(with = "serde_bytes")]
    blocks: Vec<u8>,
}

/// The four entries a new account puts in the log.
///
/// They are built together because they have to be written together: a
/// consumer that reads the commit before the account exists has no way to ask
/// for what it missed.
///
/// # Errors
///
/// If a body will not encode, or `blocks` is missing the commit.
pub fn account_created(
    did: &Did,
    handle: &Handle,
    commit: Cid,
    rev: &Tid,
    blocks: &BlockMap,
) -> Result<[Body; 4], Error> {
    let mut root = BlockMap::new();
    root.insert(commit, blocks.get(&commit)?.into_owned());

    Ok([
        Body {
            event: Event::Identity,
            bytes: encode(&Identity { did, handle })?,
        },
        Body {
            event: Event::Account,
            bytes: encode(&Account { did, active: true })?,
        },
        Body {
            event: Event::Append,
            bytes: encode(&Append {
                repo: did,
                commit,
                rev,
                since: None,
                blocks: car::write(commit, blocks)?,
                ops: &[],
                prev_data: None,
                rebase: false,
                too_big: false,
                blobs: &[],
            })?,
        },
        Body {
            event: Event::Sync,
            bytes: encode(&Sync {
                did,
                rev,
                blocks: car::write(commit, &root)?,
            })?,
        },
    ])
}
