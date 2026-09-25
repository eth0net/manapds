//! Records over the wire: what a client is shown, and in what order.

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
use manapds::xrpc::auth::Tokens;
use manapds::{server, store::keys};
use serde_json::Value;
use tempfile::TempDir;
use tower::ServiceExt;
use tower_http::normalize_path::NormalizePath;

fn account() -> Did {
    "did:plc:4cjoyc3cgpal7gnrpzyjhnv3".parse().expect("a DID")
}

fn tokens() -> Tokens {
    Tokens::new(common::SECRET, "did:web:pds.example.com")
}

/// A record in a collection this server holds no lexicon for.
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

/// A server holding one account whose repository is already on disk, which is
/// what signing up would have left behind.
fn served() -> (NormalizePath<Router>, Arc<account::Manager>, TempDir) {
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
        .commit(&root, &blocks, &[])
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
            root,
            invite: None,
            session: None,
        })
        .expect("an account");

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

#[tokio::test]
async fn a_record_is_read_back_by_its_key() {
    let (router, manager, _data) = served();
    manager
        .write(&account(), vec![record("3jqfcqzm4fc2j", "first")], None)
        .await
        .expect("a commit");

    let (status, body) = get(
        &router,
        "/xrpc/com.atproto.repo.getRecord\
         ?repo=alice.pds.example.com&collection=com.example.record&rkey=3jqfcqzm4fc2j",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["uri"],
        format!("at://{}/com.example.record/3jqfcqzm4fc2j", account())
    );
    assert_eq!(body["value"]["text"], "first");

    // Asking for the block it is not in is asking for a record nobody holds.
    let (status, body) = get(
        &router,
        "/xrpc/com.atproto.repo.getRecord\
         ?repo=alice.pds.example.com&collection=com.example.record&rkey=3jqfcqzm4fc2j\
         &cid=bafyreidfcltdzyzp4dmvoeohhrhi6z2lhsbhgorpuoqqzvpxrbfuspqsoq",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "RecordNotFound");

    // And so is asking a repository nobody holds.
    let (status, body) = get(
        &router,
        "/xrpc/com.atproto.repo.getRecord\
         ?repo=nobody.pds.example.com&collection=com.example.record&rkey=3jqfcqzm4fc2j",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "RepoNotFound");
}

#[tokio::test]
async fn a_collection_is_paged_newest_first_and_stops_saying_so() {
    let (router, manager, _data) = served();
    manager
        .write(
            &account(),
            vec![
                record("3jqfcqzm4fa2j", "first"),
                record("3jqfcqzm4fb2j", "second"),
                record("3jqfcqzm4fc2j", "third"),
            ],
            None,
        )
        .await
        .expect("a commit");

    let (status, body) = get(
        &router,
        "/xrpc/com.atproto.repo.listRecords\
         ?repo=alice.pds.example.com&collection=com.example.record&limit=2",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["records"]
            .as_array()
            .expect("records")
            .iter()
            .map(|held| held["value"]["text"].as_str().expect("text"))
            .collect::<Vec<_>>(),
        ["third", "second"]
    );
    assert_eq!(body["cursor"], "3jqfcqzm4fb2j");

    // The page that empties the collection carries no cursor, which is how a
    // client knows to stop asking.
    let (status, body) = get(
        &router,
        "/xrpc/com.atproto.repo.listRecords\
         ?repo=alice.pds.example.com&collection=com.example.record&limit=2\
         &cursor=3jqfcqzm4fb2j",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["records"].as_array().expect("records").len(), 1);
    assert_eq!(body["cursor"], Value::Null);
}
