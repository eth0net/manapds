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
use manapds::repo::{Ipld, Repo, Write};
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
    let body = axum::body::to_bytes(response.into_body(), 256 * 1024)
        .await
        .expect("a body");
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

/// A blob store for a commit that writes no blobs, which touches no file.
fn blobs() -> manapds::store::Blobs {
    manapds::store::Directory::new("/nonexistent/manapds").blobs()
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
