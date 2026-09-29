//! Records: reading one, listing a collection, and describing a repository.

use std::sync::Arc;

use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::account::{self, Expect, Manager, Missing, Requested};
use crate::repo;
use crate::repo::Write;
use crate::store;
use crate::syntax::{AtIdentifier, Did, Handle, Nsid, RecordKey};
use crate::xrpc::limit::{self, Limits};
use crate::xrpc::{self, Input, Params, auth::Access};

/// What a page holds when the caller does not say.
const PAGE: u32 = 50;

/// The most any page holds, however many are asked for.
const LONGEST_PAGE: u32 = 100;

/// The most writes one call applies, which is the reference's own cap.
const WRITES: usize = 200;

/// A record to write to a key nothing holds.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Creating {
    repo: String,
    collection: String,
    rkey: Option<String>,
    record: Value,
    swap_commit: Option<String>,
}

/// What a caller believes is at a key.
///
/// The three cases are three answers: a field left out asks nothing of the
/// key, an explicit null asks for one holding nothing, and a CID asks for that
/// block. `Nothing` is declared before `Unasked` because both read a null and
/// the first match wins.
#[derive(Debug, Default, Deserialize)]
#[serde(untagged)]
pub(crate) enum Swap {
    /// The block that has to be there.
    Block(String),
    /// Nothing, which is what an explicit null asks for.
    Nothing,
    /// Not asked at all.
    #[default]
    Unasked,
}

/// A record to write whether or not the key holds one.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Putting {
    repo: String,
    collection: String,
    rkey: String,
    record: Value,
    #[serde(default)]
    swap_record: Swap,
    swap_commit: Option<String>,
}

/// A record to take out.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Deleting {
    repo: String,
    collection: String,
    rkey: String,
    #[serde(default)]
    swap_record: Swap,
    swap_commit: Option<String>,
}

/// A set of writes to apply under one commit.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Applying {
    repo: String,
    writes: Vec<Asked>,
    swap_commit: Option<String>,
}

/// One write in such a set, named by the lexicon it belongs to.
#[derive(Debug, Deserialize)]
#[serde(tag = "$type")]
pub(crate) enum Asked {
    #[serde(rename = "com.atproto.repo.applyWrites#create")]
    Create {
        collection: String,
        rkey: Option<String>,
        value: Value,
    },
    #[serde(rename = "com.atproto.repo.applyWrites#update")]
    Update {
        collection: String,
        rkey: String,
        value: Value,
    },
    #[serde(rename = "com.atproto.repo.applyWrites#delete")]
    Delete { collection: String, rkey: String },
}

/// Where a commit left the repository.
#[derive(Debug, Serialize)]
pub(crate) struct At {
    cid: String,
    rev: String,
}

/// What writing one record answers with.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Landed {
    uri: String,
    cid: String,
    commit: At,
}

/// What taking one out answers with. The commit is absent where there was
/// nothing at the key, since nothing was written.
#[derive(Debug, Serialize)]
pub(crate) struct Removed {
    #[serde(skip_serializing_if = "Option::is_none")]
    commit: Option<At>,
}

/// What a set of writes answers with.
#[derive(Debug, Serialize)]
pub(crate) struct Applied {
    #[serde(skip_serializing_if = "Option::is_none")]
    commit: Option<At>,
    results: Vec<Outcome>,
}

/// What one write in such a set did, named the way its lexicon names it.
#[derive(Debug, Serialize)]
#[serde(tag = "$type")]
pub(crate) enum Outcome {
    #[serde(rename = "com.atproto.repo.applyWrites#createResult")]
    Create { uri: String, cid: String },
    #[serde(rename = "com.atproto.repo.applyWrites#updateResult")]
    Update { uri: String, cid: String },
    #[serde(rename = "com.atproto.repo.applyWrites#deleteResult")]
    Delete {},
}

/// Which record to read.
#[derive(Debug, Deserialize)]
pub(crate) struct Wanted {
    repo: String,
    collection: String,
    rkey: String,
    /// The block it has to be in, for a caller that already knows.
    cid: Option<String>,
}

/// Which collection to page through.
#[derive(Debug, Deserialize)]
pub(crate) struct Listing {
    repo: String,
    collection: String,
    limit: Option<u32>,
    cursor: Option<String>,
    #[serde(default)]
    reverse: bool,
}

/// Which repository to describe.
#[derive(Debug, Deserialize)]
pub(crate) struct Described {
    repo: String,
}

/// One record as a client is shown it.
#[derive(Debug, Serialize)]
pub(crate) struct Held {
    uri: String,
    cid: String,
    value: Value,
}

/// One page of a collection.
#[derive(Debug, Serialize)]
pub(crate) struct Page {
    #[serde(skip_serializing_if = "Option::is_none")]
    cursor: Option<String>,
    records: Vec<Held>,
}

/// What a repository is and what is in it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Description {
    handle: String,
    did: String,
    did_doc: Value,
    collections: Vec<String>,
    /// Whether the document the directory holds names the handle this server
    /// does.
    handle_is_correct: bool,
}

/// `com.atproto.repo.createRecord`
///
/// # Errors
///
/// If the caller is not the repository it names, the key is taken, a swap
/// names a commit that is not the one there, or storage will not answer.
pub(crate) async fn create_record(
    State(accounts): State<Arc<Manager>>,
    State(limits): State<Option<Arc<Limits>>>,
    access: Access,
    Input(input): Input<Creating>,
) -> xrpc::Result<Json<Landed>> {
    let did = owned(&accounts, &access, &input.repo).await?;
    spend(limits.as_deref(), &did, limit::CREATE)?;
    let named = collection(&input.collection)?;
    let write = Write::Create {
        rkey: match &input.rkey {
            Some(rkey) => record_key(rkey)?,
            None => accounts.record_key(),
        },
        record: record(&named, input.record)?,
        collection: named,
    };
    landed(
        accounts
            .write(
                &did,
                vec![write.into()],
                swap(input.swap_commit.as_deref())?,
            )
            .await?,
    )
}

/// `com.atproto.repo.putRecord`
///
/// # Errors
///
/// If the caller is not the repository it names, a swap names something that
/// is not there, or storage will not answer.
pub(crate) async fn put_record(
    State(accounts): State<Arc<Manager>>,
    State(limits): State<Option<Arc<Limits>>>,
    access: Access,
    Input(input): Input<Putting>,
) -> xrpc::Result<Json<Landed>> {
    let did = owned(&accounts, &access, &input.repo).await?;
    spend(limits.as_deref(), &did, limit::PUT)?;
    let asked = Requested {
        write: {
            let named = collection(&input.collection)?;
            Write::Put {
                rkey: record_key(&input.rkey)?,
                record: record(&named, input.record)?,
                collection: named,
            }
        },
        expect: expected(&input.swap_record)?,
        missing: Missing::Refuse,
    };
    landed(
        accounts
            .write(&did, vec![asked], swap(input.swap_commit.as_deref())?)
            .await?,
    )
}

/// `com.atproto.repo.deleteRecord`
///
/// # Errors
///
/// If the caller is not the repository it names, a swap names something that
/// is not there, or storage will not answer.
pub(crate) async fn delete_record(
    State(accounts): State<Arc<Manager>>,
    State(limits): State<Option<Arc<Limits>>>,
    access: Access,
    Input(input): Input<Deleting>,
) -> xrpc::Result<Json<Removed>> {
    let did = owned(&accounts, &access, &input.repo).await?;
    spend(limits.as_deref(), &did, limit::DELETE)?;
    let asked = Requested {
        write: Write::Delete {
            collection: collection(&input.collection)?,
            rkey: record_key(&input.rkey)?,
        },
        // An explicit null is no check here rather than a demand for an empty
        // key, which is how the reference reads it on this method alone.
        expect: match input.swap_record {
            Swap::Nothing => Expect::Anything,
            asked => expected(&asked)?,
        },
        // A key holding nothing is what a delete was asking for, so it is
        // answered rather than refused, with no commit because none was made.
        missing: Missing::Skip,
    };
    let written = accounts
        .write(&did, vec![asked], swap(input.swap_commit.as_deref())?)
        .await?;
    Ok(Json(Removed {
        commit: written.map(|written| At {
            cid: written.commit.to_string(),
            rev: written.rev.as_str().to_owned(),
        }),
    }))
}

/// `com.atproto.repo.applyWrites`
///
/// # Errors
///
/// If the caller is not the repository it names, the call asks for more writes
/// than one commit takes, a key is taken or missing, or storage will not
/// answer.
pub(crate) async fn apply_writes(
    State(accounts): State<Arc<Manager>>,
    State(limits): State<Option<Arc<Limits>>>,
    access: Access,
    Input(input): Input<Applying>,
) -> xrpc::Result<Json<Applied>> {
    let did = owned(&accounts, &access, &input.repo).await?;
    if input.writes.len() > WRITES {
        return Err(xrpc::Error::invalid_request(format!(
            "Too many writes. Max: {WRITES}"
        )));
    }
    let points = input
        .writes
        .iter()
        .map(|asked| match asked {
            Asked::Create { .. } => limit::CREATE,
            Asked::Update { .. } => limit::PUT,
            Asked::Delete { .. } => limit::DELETE,
        })
        .sum();
    spend(limits.as_deref(), &did, points)?;

    let mut requested = Vec::with_capacity(input.writes.len());
    for asked in input.writes {
        requested.push(Requested::from(match asked {
            Asked::Create {
                collection: nsid,
                rkey,
                value,
            } => {
                let named = collection(&nsid)?;
                Write::Create {
                    rkey: match &rkey {
                        Some(rkey) => record_key(rkey)?,
                        None => accounts.record_key(),
                    },
                    record: record(&named, value)?,
                    collection: named,
                }
            }
            Asked::Update {
                collection: nsid,
                rkey,
                value,
            } => {
                let named = collection(&nsid)?;
                Write::Update {
                    rkey: record_key(&rkey)?,
                    record: record(&named, value)?,
                    collection: named,
                }
            }
            Asked::Delete {
                collection: nsid,
                rkey,
            } => Write::Delete {
                collection: collection(&nsid)?,
                rkey: record_key(&rkey)?,
            },
        }));
    }

    let kinds: Vec<&'static str> = requested
        .iter()
        .map(|asked| match asked.write {
            Write::Delete { .. } => "delete",
            Write::Update { .. } => "update",
            _ => "create",
        })
        .collect();
    let Some(written) = accounts
        .write(&did, requested, swap(input.swap_commit.as_deref())?)
        .await?
    else {
        // Nothing asked for, so nothing written and no commit to name.
        return Ok(Json(Applied {
            commit: None,
            results: Vec::new(),
        }));
    };

    Ok(Json(Applied {
        commit: Some(At {
            cid: written.commit.to_string(),
            rev: written.rev.as_str().to_owned(),
        }),
        results: written
            .results
            .into_iter()
            .zip(kinds)
            .map(|(result, kind)| match (kind, result.cid) {
                ("update", Some(cid)) => Outcome::Update {
                    uri: result.uri,
                    cid: cid.to_string(),
                },
                (_, Some(cid)) => Outcome::Create {
                    uri: result.uri,
                    cid: cid.to_string(),
                },
                (_, None) => Outcome::Delete {},
            })
            .collect(),
    }))
}

/// `com.atproto.repo.getRecord`
///
/// # Errors
///
/// If nothing answers to the repository, it holds no record at that key, or
/// storage will not answer.
pub(crate) async fn get_record(
    State(accounts): State<Arc<Manager>>,
    Params(query): Params<Wanted>,
) -> xrpc::Result<Json<Held>> {
    let did = repository(&accounts, &query.repo).await?;
    let (collection, rkey) = (collection(&query.collection)?, record_key(&query.rkey)?);
    let held = accounts
        .record(&did, &collection, &rkey)
        .await?
        .filter(|held| {
            query
                .cid
                .as_ref()
                .is_none_or(|cid| *cid == held.cid.to_string())
        })
        .ok_or_else(|| {
            xrpc::Error::invalid_request("Could not locate record").named("RecordNotFound")
        })?;
    Ok(Json(shown(held)?))
}

/// `com.atproto.repo.listRecords`
///
/// # Errors
///
/// If nothing answers to the repository, or storage will not answer.
pub(crate) async fn list_records(
    State(accounts): State<Arc<Manager>>,
    Params(query): Params<Listing>,
) -> xrpc::Result<Json<Page>> {
    let did = repository(&accounts, &query.repo).await?;
    let collection = collection(&query.collection)?;
    let limit = query.limit.unwrap_or(PAGE).clamp(1, LONGEST_PAGE);
    let held = accounts
        .records(&did, &collection, limit, query.cursor, query.reverse)
        .await?;

    // The cursor is the last key on the page, so the next one starts after it.
    // A short page has no next, and saying so is what stops a client asking.
    let cursor = (u32::try_from(held.len()).unwrap_or(u32::MAX) == limit)
        .then(|| held.last().map(|last| key_of(&last.uri).to_owned()))
        .flatten();
    Ok(Json(Page {
        cursor,
        records: held.into_iter().map(shown).collect::<Result<_, _>>()?,
    }))
}

/// `com.atproto.repo.describeRepo`
///
/// # Errors
///
/// If nothing answers to the repository, the directory will not say what it
/// holds for it, or storage will not answer.
pub(crate) async fn describe_repo(
    State(accounts): State<Arc<Manager>>,
    Params(query): Params<Described>,
) -> xrpc::Result<Json<Description>> {
    let account = found(&accounts, &query.repo).await?;
    let document = accounts.document(&account.did).await?;
    let handle = account
        .handle
        .map_or_else(|| account::handle::INVALID.to_owned(), Handle::into_string);
    let collections = accounts.collections(&account.did).await?;

    Ok(Json(Description {
        handle_is_correct: also_known_as(&document) == Some(handle.as_str()),
        handle,
        did: account.did.as_str().to_owned(),
        did_doc: document,
        collections: collections.into_iter().map(Nsid::into_string).collect(),
    }))
}

/// Counts a write against what the account may spend on its own repository.
fn spend(limits: Option<&Limits>, did: &Did, points: u32) -> xrpc::Result<()> {
    match limits.and_then(|limits| limits.writing(did, points)) {
        None => Ok(()),
        Some(reading) => Err(xrpc::Error::new(xrpc::Status::RateLimitExceeded).limited(reading)),
    }
}

/// The repository a caller named, which has to be the one it signed in as.
async fn owned(accounts: &Manager, access: &Access, repo: &str) -> xrpc::Result<Did> {
    let did = repository(accounts, repo).await?;
    if did != access.did {
        return Err(xrpc::Error::new(xrpc::Status::Forbidden)
            .saying("Not the repository this session reaches"));
    }
    Ok(did)
}

/// A record as it was sent, in the shape it is stored in.
///
/// A record names its own collection in `$type`, and one that leaves it out is
/// given it: the other server does the same, so the same input from the same
/// client lands under the same CID on either.
fn record(collection: &Nsid, value: Value) -> xrpc::Result<crate::repo::Ipld> {
    let mut value = value;
    match value.get("$type").and_then(Value::as_str) {
        Some(named) if named == collection.as_str() => {}
        Some(named) => {
            return Err(xrpc::Error::invalid_request(format!(
                "Invalid $type: expected {collection}, got {named}"
            )));
        }
        None => {
            let Value::Object(fields) = &mut value else {
                return Err(xrpc::Error::invalid_request(
                    "Invalid record: not an object",
                ));
            };
            fields.insert("$type".to_owned(), Value::String(collection.to_string()));
        }
    }
    repo::from_json(value)
        .map_err(|invalid| xrpc::Error::invalid_request(format!("Invalid record: {invalid}")))
}

/// The commit a caller believes the repository is on.
fn swap(cid: Option<&str>) -> xrpc::Result<Option<crate::repo::Cid>> {
    cid.map(|cid| {
        cid.parse()
            .map_err(|_| xrpc::Error::invalid_request("Invalid swapCommit").named("InvalidSwap"))
    })
    .transpose()
}

fn expected(swap: &Swap) -> xrpc::Result<Expect> {
    match swap {
        Swap::Unasked => Ok(Expect::Anything),
        Swap::Nothing => Ok(Expect::Nothing),
        Swap::Block(cid) => cid
            .parse()
            .map(Expect::Block)
            .map_err(|_| xrpc::Error::invalid_request("Invalid swapRecord").named("InvalidSwap")),
    }
}

/// What one record landing answers with.
fn landed(written: Option<account::Written>) -> xrpc::Result<Json<Landed>> {
    let written = written.ok_or_else(|| xrpc::Error::new(xrpc::Status::InternalServerError))?;
    let at = At {
        cid: written.commit.to_string(),
        rev: written.rev.as_str().to_owned(),
    };
    let one = written
        .results
        .into_iter()
        .next()
        .ok_or_else(|| xrpc::Error::new(xrpc::Status::InternalServerError))?;
    Ok(Json(Landed {
        uri: one.uri,
        cid: one.cid.unwrap_or_default().to_string(),
        commit: at,
    }))
}

/// The account an at-identifier names.
async fn found(accounts: &Manager, repo: &str) -> xrpc::Result<store::Account> {
    let identifier: AtIdentifier = repo
        .parse()
        .map_err(|_| xrpc::Error::invalid_request("Invalid repo"))?;
    accounts.lookup(&identifier).await?.ok_or_else(|| {
        xrpc::Error::invalid_request(format!("Could not find repo: {repo}")).named("RepoNotFound")
    })
}

/// The same, where only the identifier behind it is wanted.
async fn repository(accounts: &Manager, repo: &str) -> xrpc::Result<Did> {
    Ok(found(accounts, repo).await?.did)
}

fn collection(nsid: &str) -> xrpc::Result<Nsid> {
    nsid.parse()
        .map_err(|_| xrpc::Error::invalid_request("Invalid collection"))
}

fn record_key(rkey: &str) -> xrpc::Result<RecordKey> {
    rkey.parse()
        .map_err(|_| xrpc::Error::invalid_request("Invalid record key"))
}

/// One stored record, turned back into what a client sent.
fn shown(held: store::Record) -> Result<Held, account::Error> {
    Ok(Held {
        uri: held.uri,
        cid: held.cid.to_string(),
        value: repo::to_json(&repo::decode(&held.value)?)?,
    })
}

/// The record key an address ends in.
fn key_of(uri: &str) -> &str {
    uri.rsplit('/').next().unwrap_or(uri)
}

/// The handle a document says the account answers to, without the scheme the
/// directory writes it under.
fn also_known_as(document: &Value) -> Option<&str> {
    document
        .get("alsoKnownAs")?
        .as_array()?
        .iter()
        .find_map(|name| name.as_str()?.strip_prefix("at://"))
}
