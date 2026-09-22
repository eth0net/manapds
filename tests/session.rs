//! The session methods, over a router, as a client reaches them.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use manapds::account::{self, password};
use manapds::config::{Config, Secret};
use manapds::crypto::{Algorithm, Keypair};
use manapds::repo::Repo;
use manapds::server;
use manapds::store;
use manapds::syntax::{Did, TidClock};
use manapds::xrpc::auth::Tokens;
use serde_json::{Value, json};
use tower::ServiceExt;
use tower_http::normalize_path::NormalizePath;

const SECRET: &str = "a secret long enough to not be guessed";

fn account() -> Did {
    "did:plc:mav423b24thku7ezkx7yaray".parse().expect("a DID")
}

fn tokens() -> Tokens {
    Tokens::new(SECRET, "did:web:pds.test")
}

fn config() -> Config {
    Config {
        hostname: "pds.test".to_owned(),
        port: 443,
        service_did: "did:web:pds.test".to_owned(),
        data_directory: "data".into(),
        jwt_secret: Secret::new(SECRET),
        admin_password: Secret::new("admin"),
        plc_rotation_key: Keypair::generate(Algorithm::Secp256k1),
        plc_url: "http://127.0.0.1:1".to_owned(),
        recovery_key: None,
        handle_domains: vec![".pds.test".to_owned()],
        invite_required: false,
        blob_upload_limit: 5 * 1024 * 1024,
        privacy_policy_url: None,
        terms_of_service_url: None,
        contact_email: None,
        rate_limits: false,
        rate_limit_bypass_key: None,
        rate_limit_bypass_ips: Vec::new(),
    }
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

    let config = Arc::new(config());
    let manager = account::Manager::new(Arc::clone(&config), accounts, tokens());
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
