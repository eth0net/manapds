//! Sync reads over the wire: what another server is told about the
//! repositories here.

mod common;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode},
};
use manapds::account;
use manapds::crypto::{Algorithm, Keypair};
use manapds::repo::{Ipld, Repo, Store as _, Write, car};
use manapds::syntax::{Did, Nsid, RecordKey, TidClock};
use manapds::xrpc::auth::Tokens;
use manapds::{server, store, store::keys};
use serde_json::Value;
use tempfile::TempDir;
use tower::ServiceExt;
use tower_http::normalize_path::NormalizePath;

fn alice() -> Did {
    "did:plc:4cjoyc3cgpal7gnrpzyjhnv3".parse().expect("a DID")
}

fn bob() -> Did {
    "did:plc:mav423b24thku7ezkx7yaray".parse().expect("a DID")
}

fn tokens() -> Tokens {
    Tokens::new(common::SECRET, "did:web:pds.example.com")
}

/// One record, in a collection nothing here has a lexicon for.
fn record(rkey: &str, text: &str) -> Write {
    Write::Create {
        collection: "com.example.record".parse::<Nsid>().expect("an NSID"),
        rkey: rkey.parse::<RecordKey>().expect("a record key"),
        record: Ipld::Map(BTreeMap::from([
            (
                "$type".to_owned(),
                Ipld::String("com.example.record".to_owned()),
            ),
            ("text".to_owned(), Ipld::String(text.to_owned())),
        ])),
    }
}

/// A server holding two accounts, each with a repository already on disk,
/// which is what signing both up would have left behind.
fn served() -> (NormalizePath<Router>, Arc<account::Manager>, TempDir) {
    let data = tempfile::tempdir().expect("a directory");
    let directory = store::Directory::new(data.path());
    let mut accounts = store::Accounts::memory().expect("a database");

    // Alice is written first, so she is the older account of the two and the
    // one a listing starts at.
    for (did, handle, email) in [
        (alice(), "alice.pds.example.com", "alice@example.com"),
        (bob(), "bob.pds.example.com", "bob@example.com"),
    ] {
        let root = repository(&directory, &did);
        accounts
            .create(&store::Registration {
                account: store::Account {
                    did,
                    handle: Some(handle.parse().expect("a handle")),
                    email: email.to_owned(),
                    password_scrypt: account::password::hash("correct horse battery staple"),
                },
                root,
                invite: None,
                session: None,
            })
            .expect("an account");
    }

    let config = Arc::new(common::config(
        "pds.example.com",
        data.path(),
        "http://127.0.0.1:1",
    ));
    let manager = Arc::new(account::Manager::new(
        Arc::clone(&config),
        accounts,
        store::Sequencer::memory().expect("a log"),
        tokens(),
    ));
    let context = server::Context::new(config, Arc::clone(&manager), tokens());
    (server::router(context), manager, data)
}

/// One account's key and first commit.
fn repository(directory: &store::Directory, did: &Did) -> store::Root {
    let key = Keypair::generate(Algorithm::Secp256k1);
    keys::write(&directory.actor_key(did), &key).expect("a key");
    let (repo, blocks) = Repo::create(did.clone(), &key, &mut TidClock::new()).expect("a repo");
    let root = store::Root {
        cid: repo.cid(),
        rev: repo.rev().clone(),
    };
    store::Actor::open(&directory.actor_store(did), did.clone())
        .expect("a store")
        .commit(None, &root, &blocks, &[], &blobs())
        .expect("a commit");
    root
}

/// One query, answered. None of these needs credentials.
async fn get(router: &NormalizePath<Router>, path: &str) -> (StatusCode, Value) {
    let (status, _, body) = fetch(router, path).await;
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

/// The same, where the answer is bytes rather than JSON, beside the type it
/// arrived under.
async fn fetch(router: &NormalizePath<Router>, path: &str) -> (StatusCode, String, Vec<u8>) {
    let mut request = Request::builder()
        .method("GET")
        .uri(path)
        .body(Body::empty())
        .expect("a request");
    let peer: SocketAddr = "203.0.113.1:9000".parse().expect("an address");
    request.extensions_mut().insert(ConnectInfo(peer));

    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("the router answers");
    let status = response.status();
    let mime = response
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let body = axum::body::to_bytes(response.into_body(), 256 * 1024)
        .await
        .expect("a body");
    (status, mime, body.to_vec())
}

/// A blob store for a commit that writes no blobs, which touches no file.
fn blobs() -> manapds::store::Blobs {
    manapds::store::Directory::new("/nonexistent/manapds").blobs()
}

#[tokio::test]
async fn every_repository_here_is_listed_oldest_account_first() {
    let (router, manager, _data) = served();
    let written = manager
        .write(
            &alice(),
            vec![record("3jqfcqzm4fc2j", "first").into()],
            None,
        )
        .await
        .expect("a commit")
        .expect("a write");

    let (status, body) = get(&router, "/xrpc/com.atproto.sync.listRepos?limit=1").await;
    assert_eq!(status, StatusCode::OK);
    let repos = body["repos"].as_array().expect("repos");
    assert_eq!(repos.len(), 1);
    assert_eq!(repos[0]["did"], alice().as_str());
    assert_eq!(repos[0]["head"], written.commit.to_string());
    assert_eq!(repos[0]["rev"], written.rev.as_str());
    assert_eq!(repos[0]["active"], true);
    assert_eq!(repos[0]["status"], Value::Null);

    let cursor = body["cursor"].as_str().expect("a cursor").to_owned();
    let (status, body) = get(
        &router,
        &format!("/xrpc/com.atproto.sync.listRepos?limit=1&cursor={cursor}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let repos = body["repos"].as_array().expect("repos");
    assert_eq!(repos.len(), 1);
    assert_eq!(repos[0]["did"], bob().as_str());

    // The page that empties the listing carries no cursor, which is how a
    // caller knows it has every repository.
    let cursor = body["cursor"].as_str().expect("a cursor").to_owned();
    let (status, body) = get(
        &router,
        &format!("/xrpc/com.atproto.sync.listRepos?limit=1&cursor={cursor}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["repos"].as_array().expect("repos").len(), 0);
    assert_eq!(body["cursor"], Value::Null);

    // Both of them fit on a page nobody sized, and that page is the end of
    // the listing too.
    let (status, body) = get(&router, "/xrpc/com.atproto.sync.listRepos").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["repos"].as_array().expect("repos").len(), 2);
    assert_eq!(body["cursor"], Value::Null);
}

#[tokio::test]
async fn a_cursor_this_server_never_wrote_is_refused() {
    let (router, _manager, _data) = served();

    for cursor in ["nonsense", "nonsense::did:plc:4cjoyc3cgpal7gnrpzyjhnv3"] {
        let (status, body) = get(
            &router,
            &format!("/xrpc/com.atproto.sync.listRepos?cursor={cursor}"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{cursor}");
        assert_eq!(body["message"], "Malformed cursor");
    }
}

#[tokio::test]
async fn the_latest_commit_is_the_one_the_last_write_left() {
    let (router, manager, _data) = served();
    let written = manager
        .write(
            &alice(),
            vec![record("3jqfcqzm4fc2j", "first").into()],
            None,
        )
        .await
        .expect("a commit")
        .expect("a write");

    let (status, body) = get(
        &router,
        &format!("/xrpc/com.atproto.sync.getLatestCommit?did={}", alice()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["cid"], written.commit.to_string());
    assert_eq!(body["rev"], written.rev.as_str());

    // Bob's repository is still where signing up left it, so the two answer
    // differently.
    let (status, other) = get(
        &router,
        &format!("/xrpc/com.atproto.sync.getLatestCommit?did={}", bob()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ne!(other["cid"], body["cid"]);
}

#[tokio::test]
async fn a_repository_here_is_active_and_at_its_latest_revision() {
    let (router, manager, _data) = served();
    let written = manager
        .write(
            &alice(),
            vec![record("3jqfcqzm4fc2j", "first").into()],
            None,
        )
        .await
        .expect("a commit")
        .expect("a write");

    let (status, body) = get(
        &router,
        &format!("/xrpc/com.atproto.sync.getRepoStatus?did={}", alice()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["did"], alice().as_str());
    assert_eq!(body["active"], true);
    assert_eq!(body["rev"], written.rev.as_str());
    // Nothing is taken down or deactivated here, so no reason is ever given.
    assert_eq!(body["status"], Value::Null);

    let (status, body) = get(
        &router,
        "/xrpc/com.atproto.sync.getRepoStatus?did=did:plc:mav423b24thku7ezkx7yarax",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "RepoNotFound");
}

#[tokio::test]
async fn a_repository_nobody_here_holds_is_refused() {
    let (router, _manager, _data) = served();

    let (status, body) = get(
        &router,
        "/xrpc/com.atproto.sync.getLatestCommit?did=did:plc:mav423b24thku7ezkx7yarax",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "RepoNotFound");

    // A handle is not resolved on this method, so it is not a DID and nothing
    // more.
    let (status, body) = get(
        &router,
        "/xrpc/com.atproto.sync.getLatestCommit?did=alice.pds.example.com",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test]
async fn a_repository_comes_back_as_a_car_rooted_at_its_commit() {
    let (router, manager, _data) = served();
    let written = manager
        .write(
            &alice(),
            vec![record("3jqfcqzm4fc2j", "first").into()],
            None,
        )
        .await
        .expect("a commit")
        .expect("a write");

    let (status, mime, body) = fetch(
        &router,
        &format!("/xrpc/com.atproto.sync.getRepo?did={}", alice()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(mime, "application/vnd.ipld.car");

    let (root, blocks) = car::read(&body).expect("a car file");
    assert_eq!(root, written.commit);
    let record = written.results[0].cid.expect("a record");
    assert!(blocks.contains(&record).expect("a lookup"));

    // Bob's repository is still where signing up left it, so the two files
    // hang from different roots.
    let signed_up = manager
        .root(&bob())
        .await
        .expect("a root")
        .expect("a repository");
    let (_, _, other) = fetch(
        &router,
        &format!("/xrpc/com.atproto.sync.getRepo?did={}", bob()),
    )
    .await;
    assert_eq!(car::read(&other).expect("a car file").0, signed_up.cid);
}

#[tokio::test]
async fn a_download_since_a_revision_carries_only_what_came_after() {
    let (router, manager, _data) = served();
    let first = manager
        .write(
            &alice(),
            vec![record("3jqfcqzm4fc2j", "first").into()],
            None,
        )
        .await
        .expect("a commit")
        .expect("a write");
    let second = manager
        .write(
            &alice(),
            vec![record("3jqfcqzm4fc2k", "second").into()],
            None,
        )
        .await
        .expect("a commit")
        .expect("a write");

    let (status, _, body) = fetch(
        &router,
        &format!(
            "/xrpc/com.atproto.sync.getRepo?did={}&since={}",
            alice(),
            first.rev
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // The root is the commit the repository is on either way, so a caller
    // knows what the blocks it was handed add up to.
    let (root, blocks) = car::read(&body).expect("a car file");
    assert_eq!(root, second.commit);
    assert!(
        blocks
            .contains(&second.results[0].cid.expect("a record"))
            .expect("a lookup")
    );
    assert!(
        !blocks
            .contains(&first.results[0].cid.expect("a record"))
            .expect("a lookup")
    );
    assert!(!blocks.contains(&first.commit).expect("a lookup"));
}

/// The repository Alice is left holding, and the three records in it.
async fn three_records(manager: &account::Manager) -> account::Written {
    manager
        .write(
            &alice(),
            vec![
                record("3jqfcqzm4fc2j", "first").into(),
                record("3jqfcqzm4fc2k", "second").into(),
                record("3jqfcqzm4fc2l", "third").into(),
            ],
            None,
        )
        .await
        .expect("a commit")
        .expect("a write")
}

/// Where those records live.
fn kept(rkey: &str) -> (Nsid, RecordKey) {
    (
        "com.example.record".parse().expect("an NSID"),
        rkey.parse().expect("a record key"),
    )
}

#[tokio::test]
async fn a_record_comes_back_with_the_blocks_that_prove_it() {
    let (router, manager, _data) = served();
    let written = three_records(&manager).await;
    let wanted = written.results[1].cid.expect("a record");

    let (status, mime, body) = fetch(
        &router,
        &format!(
            "/xrpc/com.atproto.sync.getRecord?did={}&collection=com.example.record&rkey=3jqfcqzm4fc2k",
            alice()
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(mime, "application/vnd.ipld.car");

    // A proof rather than a copy: the tree walks from the commit to the
    // record on these blocks alone, and the records beside it are not here.
    let (root, blocks) = car::read(&body).expect("a car file");
    assert_eq!(root, written.commit);
    let (collection, rkey) = kept("3jqfcqzm4fc2k");
    let mut repo = Repo::load(&blocks, root).expect("a repository");
    assert_eq!(
        repo.get(&blocks, &collection, &rkey).expect("a lookup"),
        Some(wanted)
    );
    assert!(
        !blocks
            .contains(&written.results[0].cid.expect("a record"))
            .expect("a lookup")
    );
}

#[tokio::test]
async fn a_key_nothing_is_at_comes_back_as_the_walk_that_shows_it() {
    let (router, manager, _data) = served();
    let written = three_records(&manager).await;

    let (status, _, body) = fetch(
        &router,
        &format!(
            "/xrpc/com.atproto.sync.getRecord?did={}&collection=com.example.record&rkey=3jqfcqzm4fc2z",
            alice()
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (root, blocks) = car::read(&body).expect("a car file");
    assert_eq!(root, written.commit);
    let (collection, rkey) = kept("3jqfcqzm4fc2z");
    let mut repo = Repo::load(&blocks, root).expect("a repository");
    assert_eq!(
        repo.get(&blocks, &collection, &rkey).expect("a lookup"),
        None
    );
}

#[tokio::test]
async fn a_proof_for_a_repository_nobody_here_holds_is_refused() {
    let (router, _manager, _data) = served();

    let (status, body) = get(
        &router,
        "/xrpc/com.atproto.sync.getRecord?did=did:plc:mav423b24thku7ezkx7yarax&collection=com.example.record&rkey=3jqfcqzm4fc2j",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "RepoNotFound");

    let (status, body) = get(
        &router,
        &format!(
            "/xrpc/com.atproto.sync.getRecord?did={}&collection=not-an-nsid&rkey=3jqfcqzm4fc2j",
            alice()
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Invalid collection");
}

#[tokio::test]
async fn the_blocks_a_caller_names_come_back_and_nothing_else_does() {
    let (router, manager, _data) = served();
    let written = manager
        .write(
            &alice(),
            vec![record("3jqfcqzm4fc2j", "first").into()],
            None,
        )
        .await
        .expect("a commit")
        .expect("a write");
    let record = written.results[0].cid.expect("a record");

    let (status, mime, body) = fetch(
        &router,
        &format!(
            "/xrpc/com.atproto.sync.getBlocks?did={}&cids={}&cids={}",
            alice(),
            written.commit,
            record
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(mime, "application/vnd.ipld.car");

    // A slice of a repository hangs from nothing, so the file names no root
    // and the whole of it is the two blocks asked for.
    let blocks = car::read_blocks(&body).expect("a car file");
    assert_eq!(blocks.len(), 2);
    assert!(blocks.contains(&written.commit).expect("a lookup"));
    assert!(blocks.contains(&record).expect("a lookup"));
    assert_eq!(
        car::read(&body),
        Err(manapds::repo::Error::MalformedCar("not exactly one root"))
    );
}

#[tokio::test]
async fn a_cid_the_repository_holds_nothing_under_is_refused() {
    let (router, manager, _data) = served();
    let written = manager
        .write(
            &alice(),
            vec![record("3jqfcqzm4fc2j", "first").into()],
            None,
        )
        .await
        .expect("a commit")
        .expect("a write");
    // Bob's repository is a different one, so his commit is a CID Alice's
    // holds nothing under.
    let elsewhere = manager
        .root(&bob())
        .await
        .expect("a root")
        .expect("a repository")
        .cid;

    let (status, body) = get(
        &router,
        &format!(
            "/xrpc/com.atproto.sync.getBlocks?did={}&cids={}&cids={}",
            alice(),
            written.commit,
            elsewhere
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "InvalidRequest");
    assert_eq!(body["message"], format!("Could not find cids: {elsewhere}"));

    // Naming none of them, and naming one that is not a CID at all.
    let (status, body) = get(
        &router,
        &format!("/xrpc/com.atproto.sync.getBlocks?did={}", alice()),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], r#"Params must have the property "cids""#);

    let (status, body) = get(
        &router,
        &format!(
            "/xrpc/com.atproto.sync.getBlocks?did={}&cids=nonsense",
            alice()
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Invalid cid");
}

#[tokio::test]
async fn a_download_of_a_repository_nobody_here_holds_is_refused() {
    let (router, _manager, _data) = served();

    let (status, body) = get(
        &router,
        "/xrpc/com.atproto.sync.getRepo?did=did:plc:mav423b24thku7ezkx7yarax",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "RepoNotFound");

    // A revision is a TID and nothing else, so a `since` that is not one is
    // refused rather than read as the start of time.
    let (status, body) = get(
        &router,
        &format!(
            "/xrpc/com.atproto.sync.getRepo?did={}&since=nonsense",
            alice()
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Invalid since");
}
