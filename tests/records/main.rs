//! Records over the wire: what a client is shown, and in what order.
//!
//! One binary, a module per subject, and the fixtures every subject builds on.

mod backlinks;
mod blobs;
mod listing;
mod writing;

#[path = "../common/mod.rs"]
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
use manapds::store;
use manapds::syntax::{Did, Nsid, RecordKey, TidClock};
use manapds::xrpc::auth::{Scope, Tokens};
use manapds::xrpc::limit::{self, Limits};
use manapds::{server, store::keys};
use serde_json::Value;
use tempfile::TempDir;
use tower::ServiceExt;
use tower_http::normalize_path::NormalizePath;

/// A blob store for a commit that writes no blobs, which touches no file. A
fn somebody_else() -> Did {
    "did:plc:mav423b24thku7ezkx7yaray".parse().expect("a DID")
}

/// test that does hands in one of its own.
fn blobs() -> store::Blobs {
    store::Directory::new("/nonexistent/manapds").blobs()
}

fn account() -> Did {
    "did:plc:4cjoyc3cgpal7gnrpzyjhnv3".parse().expect("a DID")
}

fn tokens() -> Tokens {
    Tokens::new(common::SECRET, "did:web:pds.example.com")
}

/// A server holding one account whose repository is already on disk, which is
/// what signing up would have left behind.
fn served() -> (NormalizePath<Router>, Arc<account::Manager>, TempDir) {
    let (router, manager, data, _) = standing(false);
    (router, manager, data)
}

/// The same, with the budgets on and the context they are held in, so a test
/// can spend one without making five thousand requests.
fn budgeted() -> (NormalizePath<Router>, Arc<Limits>, TempDir) {
    let (router, _, data, limits) = standing(true);
    (router, limits.expect("budgets"), data)
}

fn standing(
    rate_limits: bool,
) -> (
    NormalizePath<Router>,
    Arc<account::Manager>,
    TempDir,
    Option<Arc<Limits>>,
) {
    let data = tempfile::tempdir().expect("a directory");
    let directory = store::Directory::new(data.path());
    let did = account();

    let key = Keypair::generate(Algorithm::Secp256k1);
    keys::write(&directory.actor_key(&did), &key).expect("a key");
    let (repo, blocks) = Repo::create(did.clone(), &key, &mut TidClock::new()).expect("a repo");
    let root = store::Root {
        cid: repo.cid(),
        rev: repo.rev().clone(),
    };
    store::Actor::open(&directory.actor_store(&did), did.clone())
        .expect("a store")
        .commit(
            None,
            &root,
            store::Blocks {
                written: &blocks,
                dropped: &[],
            },
            &[],
            &blobs(),
        )
        .expect("a commit");

    let mut accounts = store::Accounts::memory().expect("a database");
    accounts
        .create(&store::Registration {
            account: store::Account {
                did: did.clone(),
                handle: Some("alice.pds.example.com".parse().expect("a handle")),
                email: "alice@example.com".to_owned(),
                password_scrypt: account::password::hash("correct horse battery staple"),
            },
            root: root.clone(),
            invite: None,
            session: None,
        })
        .expect("an account");
    // Somebody else on the same server, so a caller naming a repository that
    // is not its own reaches the check rather than stopping at the lookup.
    accounts
        .create(&store::Registration {
            account: store::Account {
                did: somebody_else(),
                handle: Some("bob.pds.example.com".parse().expect("a handle")),
                email: "bob@example.com".to_owned(),
                password_scrypt: account::password::hash("correct horse battery staple"),
            },
            root,
            invite: None,
            session: None,
        })
        .expect("another account");

    let mut config = common::config("pds.example.com", data.path(), "http://127.0.0.1:1");
    config.rate_limits = rate_limits;
    let config = Arc::new(config);
    let manager = Arc::new(account::Manager::new(
        Arc::clone(&config),
        accounts,
        store::Sequencer::memory().expect("a log"),
        tokens(),
    ));
    let context = server::Context::new(config, Arc::clone(&manager), tokens());
    let limits = context.limits.clone();
    (server::router(context), manager, data, limits)
}

/// One procedure, answered, signed in as the account.
async fn post(router: &NormalizePath<Router>, path: &str, body: Value) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .header(
            "authorization",
            format!("Bearer {}", tokens().access(&account(), Scope::Access)),
        )
        .body(Body::from(body.to_string()))
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

/// One query, answered.
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

/// One blob, uploaded, as the answer a record would carry.
async fn uploaded(router: &NormalizePath<Router>, bytes: Vec<u8>) -> Value {
    let mut request = Request::builder()
        .method("POST")
        .uri("/xrpc/com.atproto.repo.uploadBlob")
        .header("content-type", "image/png")
        .header(
            "authorization",
            format!("Bearer {}", tokens().access(&account(), Scope::Access)),
        )
        .body(Body::from(bytes))
        .expect("a request");
    request.extensions_mut().insert(ConnectInfo(
        "203.0.113.1:9000"
            .parse::<SocketAddr>()
            .expect("an address"),
    ));
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("the router answers");
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("a body");
    let uploaded: Value = serde_json::from_slice(&body).expect("json");
    uploaded["blob"].clone()
}

async fn holding(router: &NormalizePath<Router>, rkey: &str, blob: &Value) -> (StatusCode, Value) {
    post(
        router,
        "/xrpc/com.atproto.repo.createRecord",
        serde_json::json!({
            "repo": account().as_str(),
            "collection": "com.example.record",
            "rkey": rkey,
            "record": { "$type": "com.example.record", "image": blob },
        }),
    )
    .await
}

/// The CID a blob reference names.
fn link(blob: &Value) -> String {
    blob["ref"]["$link"].as_str().expect("a link").to_owned()
}
