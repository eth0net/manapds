//! Sessions and the app passwords that open them, over a router, as a client
//! reaches them.

mod common;

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use manapds::account::{self, password};
use manapds::crypto::{Algorithm, Keypair};
use manapds::repo::Repo;
use manapds::server;
use manapds::store;
use manapds::syntax::{Did, TidClock};
use manapds::xrpc::auth::Tokens;
use serde_json::{Value, json};
use tower::ServiceExt;
use tower_http::normalize_path::NormalizePath;

fn account() -> Did {
    "did:plc:mav423b24thku7ezkx7yaray".parse().expect("a DID")
}

fn tokens() -> Tokens {
    Tokens::new(common::SECRET, "did:web:pds.test")
}

/// A server holding one account, reachable over its own router.
fn server() -> NormalizePath<Router> {
    let mut accounts = store::Accounts::memory().expect("a database");
    accounts
        .create(&store::Registration {
            account: store::Account {
                did: account(),
                handle: Some("alice.pds.test".parse().expect("a handle")),
                email: "alice@example.com".to_owned(),
                password_scrypt: password::hash("correct horse battery staple"),
            },
            root: root(),
            invite: None,
            session: None,
        })
        .expect("an account");

    let config = Arc::new(common::config("pds.test", "data", "http://127.0.0.1:1"));
    let manager = account::Manager::new(
        Arc::clone(&config),
        accounts,
        store::Sequencer::memory().expect("a log"),
        tokens(),
    )
    .answering_in(std::time::Duration::ZERO);
    server::router(server::Context::new(config, Arc::new(manager), tokens()))
}

fn root() -> store::Root {
    let key = Keypair::generate(Algorithm::Secp256k1);
    let (repo, _) = Repo::create(account(), &key, &mut TidClock::new()).expect("a repository");
    store::Root {
        cid: repo.cid(),
        rev: repo.rev().clone(),
    }
}

/// Calls a method, with a bearer token if one is given, and reads the answer.
async fn call(
    router: &NormalizePath<Router>,
    method: &str,
    nsid: &str,
    bearer: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(format!("/xrpc/{nsid}"));
    if let Some(token) = bearer {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let request = match body {
        Some(body) => request
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string())),
        None => request.body(Body::empty()),
    }
    .expect("a request");

    let response = router.clone().oneshot(request).await.expect("a response");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("a body");
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

async fn sign_in(router: &NormalizePath<Router>) -> Value {
    let (status, body) = call(
        router,
        "POST",
        "com.atproto.server.createSession",
        None,
        Some(json!({
            "identifier": "alice.pds.test",
            "password": "correct horse battery staple",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

#[tokio::test]
async fn signing_in_hands_back_a_pair_of_tokens_and_the_account() {
    let router = server();
    let body = sign_in(&router).await;

    assert_eq!(body["did"], account().as_str());
    assert_eq!(body["handle"], "alice.pds.test");
    assert_eq!(body["email"], "alice@example.com");
    assert_eq!(body["active"], true);
    assert!(body["accessJwt"].is_string());
    assert!(body["refreshJwt"].is_string());
}

#[tokio::test]
async fn a_wrong_password_is_refused_without_saying_which_half_was_wrong() {
    let router = server();

    for (identifier, password) in [
        ("alice.pds.test", "not the password"),
        ("nobody.pds.test", "correct horse battery staple"),
    ] {
        let (status, body) = call(
            &router,
            "POST",
            "com.atproto.server.createSession",
            None,
            Some(json!({ "identifier": identifier, "password": password })),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{identifier}");
        assert_eq!(body["error"], "AuthenticationRequired");
        assert_eq!(body["message"], "Invalid identifier or password");
    }
}

#[tokio::test]
async fn a_body_that_will_not_read_is_refused_the_way_everything_else_is() {
    let router = server();

    let (status, body) = call(
        &router,
        "POST",
        "com.atproto.server.createSession",
        None,
        Some(json!({ "identifier": "alice.pds.test" })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "InvalidRequest");
    assert!(
        body["message"]
            .as_str()
            .expect("a message")
            .contains("password"),
        "{body}"
    );
}

#[tokio::test]
async fn a_body_longer_than_anything_this_takes_says_that_and_not_something_else() {
    let router = server();

    let (status, body) = call(
        &router,
        "POST",
        "com.atproto.server.createSession",
        None,
        Some(json!({ "identifier": "a".repeat(4 * 1024 * 1024), "password": "x" })),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{body}");
    assert_eq!(body["error"], "PayloadTooLarge");
}

#[tokio::test]
async fn a_session_reads_itself_back_and_only_with_its_own_token() {
    let router = server();
    let session = sign_in(&router).await;
    let access = session["accessJwt"].as_str().expect("a token");

    let (status, body) = call(
        &router,
        "GET",
        "com.atproto.server.getSession",
        Some(access),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["did"], account().as_str());
    assert_eq!(body["handle"], "alice.pds.test");
    // The tokens are not handed out again by a method that only reads.
    assert!(body["accessJwt"].is_null());

    // A refresh token is not an access token, whatever it is spent on.
    let refresh = session["refreshJwt"].as_str().expect("a token");
    let (status, _) = call(
        &router,
        "GET",
        "com.atproto.server.getSession",
        Some(refresh),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, body) = call(&router, "GET", "com.atproto.server.getSession", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "AuthMissing");
}

#[tokio::test]
async fn a_session_is_exchanged_for_the_next_one() {
    let router = server();
    let session = sign_in(&router).await;
    let refresh = session["refreshJwt"].as_str().expect("a token");

    let (status, body) = call(
        &router,
        "POST",
        "com.atproto.server.refreshSession",
        Some(refresh),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_ne!(body["refreshJwt"], session["refreshJwt"]);
    assert_eq!(body["did"], account().as_str());

    // And an access token will not do in its place.
    let access = session["accessJwt"].as_str().expect("a token");
    let (status, _) = call(
        &router,
        "POST",
        "com.atproto.server.refreshSession",
        Some(access),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn ending_a_session_stops_it_being_exchanged_again() {
    let router = server();
    let session = sign_in(&router).await;
    let refresh = session["refreshJwt"].as_str().expect("a token");

    let (status, _) = call(
        &router,
        "POST",
        "com.atproto.server.deleteSession",
        Some(refresh),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = call(
        &router,
        "POST",
        "com.atproto.server.refreshSession",
        Some(refresh),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "ExpiredToken");
}

/// Writes an app password and hands back what the account was told.
async fn write_app_password(router: &NormalizePath<Router>, access: &str, name: &str) -> Value {
    let (status, body) = call(
        router,
        "POST",
        "com.atproto.server.createAppPassword",
        Some(access),
        Some(json!({ "name": name })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

#[tokio::test]
async fn an_app_password_is_written_listed_and_signed_in_with() {
    let router = server();
    let session = sign_in(&router).await;
    let access = session["accessJwt"].as_str().expect("a token");

    let written = write_app_password(&router, access, "phone").await;
    assert_eq!(written["name"], "phone");
    assert_eq!(written["privileged"], false);
    // Four groups of four, which is what a client shows somebody to type.
    let password = written["password"].as_str().expect("a password");
    assert_eq!(password.len(), 19);
    assert!(password.split('-').all(|group| group.len() == 4));

    let (status, listed) = call(
        &router,
        "GET",
        "com.atproto.server.listAppPasswords",
        Some(access),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{listed}");
    assert_eq!(listed["passwords"][0]["name"], "phone");
    assert_eq!(listed["passwords"][0]["createdAt"], written["createdAt"]);
    // Said once: a listing names them and hands none of them back.
    assert!(listed["passwords"][0]["password"].is_null());

    let (status, opened) = call(
        &router,
        "POST",
        "com.atproto.server.createSession",
        None,
        Some(json!({ "identifier": "alice.pds.test", "password": password })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{opened}");
}

#[tokio::test]
async fn a_revoked_app_password_opens_nothing_and_is_listed_no_longer() {
    let router = server();
    let session = sign_in(&router).await;
    let access = session["accessJwt"].as_str().expect("a token");
    let written = write_app_password(&router, access, "phone").await;
    let password = written["password"].as_str().expect("a password");

    let (status, body) = call(
        &router,
        "POST",
        "com.atproto.server.revokeAppPassword",
        Some(access),
        Some(json!({ "name": "phone" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (_, listed) = call(
        &router,
        "GET",
        "com.atproto.server.listAppPasswords",
        Some(access),
        None,
    )
    .await;
    assert_eq!(listed["passwords"].as_array().expect("a list").len(), 0);

    let (status, refused) = call(
        &router,
        "POST",
        "com.atproto.server.createSession",
        None,
        Some(json!({ "identifier": "alice.pds.test", "password": password })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{refused}");
}

#[tokio::test]
async fn an_app_password_will_not_write_another_one() {
    let router = server();
    let session = sign_in(&router).await;
    let access = session["accessJwt"].as_str().expect("a token");
    let written = write_app_password(&router, access, "phone").await;

    let (_, opened) = call(
        &router,
        "POST",
        "com.atproto.server.createSession",
        None,
        Some(json!({
            "identifier": "alice.pds.test",
            "password": written["password"].as_str().expect("a password"),
        })),
    )
    .await;
    let lesser = opened["accessJwt"].as_str().expect("a token");

    let (status, refused) = call(
        &router,
        "POST",
        "com.atproto.server.createAppPassword",
        Some(lesser),
        Some(json!({ "name": "laptop" })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    assert_eq!(refused["error"], "InvalidToken");
    // Listing them is another matter: upstream lets an app password see the
    // names, and only writing one is held back.
    let (status, listed) = call(
        &router,
        "GET",
        "com.atproto.server.listAppPasswords",
        Some(lesser),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{listed}");
}

#[tokio::test]
async fn a_name_the_account_already_uses_is_refused() {
    let router = server();
    let session = sign_in(&router).await;
    let access = session["accessJwt"].as_str().expect("a token");
    write_app_password(&router, access, "phone").await;

    let (status, refused) = call(
        &router,
        "POST",
        "com.atproto.server.createAppPassword",
        Some(access),
        Some(json!({ "name": "phone" })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    assert_eq!(refused["error"], "InvalidRequest");
}
