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
use manapds::xrpc::auth::{Scope, Tokens};
use manapds::xrpc::limit::{self, Limits};
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
        .commit(None, &root, &blocks, &[])
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

#[tokio::test]
async fn a_record_is_read_back_by_its_key() {
    let (router, manager, _data) = served();
    manager
        .write(
            &account(),
            vec![record("3jqfcqzm4fc2j", "first").into()],
            None,
        )
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
                record("3jqfcqzm4fa2j", "first").into(),
                record("3jqfcqzm4fb2j", "second").into(),
                record("3jqfcqzm4fc2j", "third").into(),
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

#[tokio::test]
async fn a_record_is_written_read_replaced_and_taken_out() {
    let (router, _manager, _data) = served();
    let did = account();

    let (status, written) = post(
        &router,
        "/xrpc/com.atproto.repo.createRecord",
        serde_json::json!({
            "repo": did.as_str(),
            "collection": "com.example.record",
            "rkey": "3jqfcqzm4fc2j",
            "record": { "$type": "com.example.record", "text": "first" },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{written}");
    assert_eq!(
        written["uri"],
        format!("at://{did}/com.example.record/3jqfcqzm4fc2j")
    );
    let first = written["cid"].as_str().expect("a cid").to_owned();

    // Writing the same key again is a put, and the swap has to name what is
    // there rather than what the caller first wrote.
    let (status, refused) = post(
        &router,
        "/xrpc/com.atproto.repo.putRecord",
        serde_json::json!({
            "repo": did.as_str(),
            "collection": "com.example.record",
            "rkey": "3jqfcqzm4fc2j",
            "record": { "$type": "com.example.record", "text": "second" },
            "swapRecord": null,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    assert_eq!(refused["error"], "InvalidSwap");

    let (status, replaced) = post(
        &router,
        "/xrpc/com.atproto.repo.putRecord",
        serde_json::json!({
            "repo": did.as_str(),
            "collection": "com.example.record",
            "rkey": "3jqfcqzm4fc2j",
            "record": { "$type": "com.example.record", "text": "second" },
            "swapRecord": first,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{replaced}");
    assert_ne!(replaced["cid"], first);

    let (status, body) = get(
        &router,
        "/xrpc/com.atproto.repo.getRecord\
         ?repo=alice.pds.example.com&collection=com.example.record&rkey=3jqfcqzm4fc2j",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["value"]["text"], "second");

    let (status, removed) = post(
        &router,
        "/xrpc/com.atproto.repo.deleteRecord",
        serde_json::json!({
            "repo": did.as_str(),
            "collection": "com.example.record",
            "rkey": "3jqfcqzm4fc2j",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{removed}");
    assert!(removed["commit"]["rev"].is_string());

    let (status, _) = get(
        &router,
        "/xrpc/com.atproto.repo.getRecord\
         ?repo=alice.pds.example.com&collection=com.example.record&rkey=3jqfcqzm4fc2j",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_set_of_writes_lands_under_one_commit_and_answers_in_order() {
    let (router, _manager, _data) = served();
    let did = account();

    let (status, applied) = post(
        &router,
        "/xrpc/com.atproto.repo.applyWrites",
        serde_json::json!({
            "repo": did.as_str(),
            "writes": [
                {
                    "$type": "com.atproto.repo.applyWrites#create",
                    "collection": "com.example.record",
                    "rkey": "3jqfcqzm4fa2j",
                    "value": { "$type": "com.example.record", "text": "first" },
                },
                {
                    "$type": "com.atproto.repo.applyWrites#create",
                    "collection": "com.example.record",
                    "rkey": "3jqfcqzm4fb2j",
                    "value": { "$type": "com.example.record", "text": "second" },
                },
            ],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{applied}");
    let results = applied["results"].as_array().expect("results");
    assert_eq!(results.len(), 2);
    assert_eq!(
        results[0]["$type"],
        "com.atproto.repo.applyWrites#createResult"
    );

    // Both went in under one revision, which is the point of the method.
    let (_, page) = get(
        &router,
        "/xrpc/com.atproto.repo.listRecords\
         ?repo=alice.pds.example.com&collection=com.example.record",
    )
    .await;
    assert_eq!(page["records"].as_array().expect("records").len(), 2);

    // A delete beside an update answers with the shape each one is owed.
    let (status, applied) = post(
        &router,
        "/xrpc/com.atproto.repo.applyWrites",
        serde_json::json!({
            "repo": did.as_str(),
            "writes": [
                {
                    "$type": "com.atproto.repo.applyWrites#update",
                    "collection": "com.example.record",
                    "rkey": "3jqfcqzm4fa2j",
                    "value": { "$type": "com.example.record", "text": "again" },
                },
                {
                    "$type": "com.atproto.repo.applyWrites#delete",
                    "collection": "com.example.record",
                    "rkey": "3jqfcqzm4fb2j",
                },
            ],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{applied}");
    let results = applied["results"].as_array().expect("results");
    assert_eq!(
        results[0]["$type"],
        "com.atproto.repo.applyWrites#updateResult"
    );
    assert_eq!(
        results[1]["$type"],
        "com.atproto.repo.applyWrites#deleteResult"
    );
    assert!(results[1].get("uri").is_none());
}

#[tokio::test]
async fn a_caller_may_only_write_to_the_repository_it_signed_in_as() {
    let (router, _manager, _data) = served();

    let (status, refused) = post(
        &router,
        "/xrpc/com.atproto.repo.createRecord",
        serde_json::json!({
            "repo": "did:plc:mav423b24thku7ezkx7yaray",
            "collection": "com.example.record",
            "record": { "$type": "com.example.record", "text": "not mine" },
        }),
    )
    .await;
    // Nothing on this server answers to it, so it never reaches the check.
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    assert_eq!(refused["error"], "RepoNotFound");
}

#[tokio::test]
async fn a_blob_is_taken_in_and_handed_back_as_it_was_sent() {
    let (router, _manager, _data) = served();
    let did = account();

    let mut request = Request::builder()
        .method("POST")
        .uri("/xrpc/com.atproto.repo.uploadBlob")
        .header("content-type", "image/png")
        .header(
            "authorization",
            format!("Bearer {}", tokens().access(&did, Scope::Access)),
        )
        .body(Body::from(vec![1u8, 2, 3, 4]))
        .expect("a request");
    let peer: SocketAddr = "203.0.113.1:9000".parse().expect("an address");
    request.extensions_mut().insert(ConnectInfo(peer));
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

    // The answer is the shape a record refers to a blob by, rather than a
    // bare CID: a client writes it straight into the record it is making.
    assert_eq!(uploaded["blob"]["$type"], "blob");
    assert_eq!(uploaded["blob"]["mimeType"], "image/png");
    assert_eq!(uploaded["blob"]["size"], 4);
    let cid = uploaded["blob"]["ref"]["$link"]
        .as_str()
        .expect("a link")
        .to_owned();

    let mut request = Request::builder()
        .method("GET")
        .uri(format!(
            "/xrpc/com.atproto.sync.getBlob?did={did}&cid={cid}"
        ))
        .body(Body::empty())
        .expect("a request");
    request.extensions_mut().insert(ConnectInfo(peer));
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("the router answers");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .expect("a type")
            .to_str()
            .expect("text"),
        "image/png"
    );
    let served = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("a body");
    assert_eq!(served.to_vec(), vec![1u8, 2, 3, 4]);
}

#[tokio::test]
async fn an_account_past_its_write_budget_is_told_when_to_come_back() {
    let (router, limits, _data) = budgeted();
    let did = account();

    // Spent here rather than over five thousand requests, against the same
    // budget the handler reaches.
    while limits.writing(&did, limit::CREATE).is_none() {}

    let mut request = Request::builder()
        .method("POST")
        .uri("/xrpc/com.atproto.repo.createRecord")
        .header("content-type", "application/json")
        .header(
            "authorization",
            format!("Bearer {}", tokens().access(&did, Scope::Access)),
        )
        .body(Body::from(
            serde_json::json!({
                "repo": did.as_str(),
                "collection": "com.example.record",
                "record": { "$type": "com.example.record", "text": "one too many" },
            })
            .to_string(),
        ))
        .expect("a request");
    let peer: SocketAddr = "203.0.113.1:9000".parse().expect("an address");
    request.extensions_mut().insert(ConnectInfo(peer));

    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("the router answers");
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    // Refused with the one header that tells a client what to do about it.
    assert!(response.headers().contains_key("retry-after"));
}

#[tokio::test(flavor = "multi_thread")]
async fn writes_from_two_callers_at_once_all_land() {
    let (_router, manager, _data) = served();
    let did = account();

    // Whether these overlap is up to the scheduler, so this says that nothing
    // is lost when they do rather than making them. The store's own test is
    // where a commit built on a moved root is refused.
    for round in 0..10 {
        let (one, other) = (Arc::clone(&manager), Arc::clone(&manager));
        let (left, right) = (did.clone(), did.clone());
        let first = tokio::spawn(async move {
            one.write(
                &left,
                vec![record(&format!("3jqfcqzm4f{round}2j"), "mine").into()],
                None,
            )
            .await
        });
        let second = tokio::spawn(async move {
            other
                .write(
                    &right,
                    vec![record(&format!("3jqfcqzm4g{round}2j"), "theirs").into()],
                    None,
                )
                .await
        });
        first.await.expect("a task").expect("one lands");
        second.await.expect("a task").expect("the other lands");
    }

    let held = manager
        .records(
            &did,
            &"com.example.record".parse().expect("an NSID"),
            100,
            None,
            false,
        )
        .await
        .expect("reads");
    assert_eq!(held.len(), 20);
}
