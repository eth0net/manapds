//! Signing up and resolving a handle, over a router, as a client reaches them.

mod common;

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, Uri, header};
use manapds::account;
use manapds::server;
use manapds::store;
use manapds::xrpc::auth::Tokens;
use serde_json::{Value, json};
use tempfile::TempDir;
use tower::ServiceExt;
use tower_http::normalize_path::NormalizePath;

/// What a directory was sent, so that a test can tell whether it was told.
type Seen = Arc<Mutex<Vec<String>>>;

async fn plc() -> (String, Seen) {
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&seen);
    let router = Router::new().fallback(move |uri: Uri, _: String| {
        let recorded = Arc::clone(&recorded);
        async move {
            recorded
                .lock()
                .expect("nothing panicked while holding it")
                .push(uri.path().to_owned());
            ""
        }
    });
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("a port");
    let url = format!(
        "http://127.0.0.1:{}",
        listener.local_addr().expect("an address").port()
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    (url, seen)
}

/// A server nobody has signed up to, and the directory it registers at.
async fn server(invite_required: bool) -> (NormalizePath<Router>, TempDir, Seen) {
    let (url, seen) = plc().await;
    let data = tempfile::tempdir().expect("a directory");
    let mut config = common::config("pds.test", data.path(), &url);
    config.invite_required = invite_required;
    let config = Arc::new(config);
    let tokens = Tokens::new(common::SECRET, "did:web:pds.test");
    let accounts = store::Accounts::memory().expect("a database");
    let manager = account::Manager::new(Arc::clone(&config), accounts, tokens.clone())
        .answering_in(std::time::Duration::ZERO);
    let context = server::Context::new(config, Arc::new(manager), tokens);
    (server::router(context), data, seen)
}

async fn call(
    router: &NormalizePath<Router>,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let request = Request::builder()
        .method(method)
        .uri(format!("/xrpc/{path}"));
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
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn signup(handle: &str) -> Value {
    json!({
        "handle": handle,
        "email": "alice@example.com",
        "password": "correct horse battery staple",
    })
}

#[tokio::test]
async fn signing_up_hands_back_an_identity_and_a_session() {
    let (router, _data, seen) = server(false).await;

    let (status, body) = call(
        &router,
        "POST",
        "com.atproto.server.createAccount",
        Some(signup("alice.pds.test")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["handle"], "alice.pds.test");
    let did = body["did"].as_str().expect("a DID");
    assert!(did.starts_with("did:plc:"), "{did}");
    assert!(body["accessJwt"].is_string());
    assert!(body["refreshJwt"].is_string());

    // The directory was told, under the identifier the operation minted.
    assert_eq!(
        *seen.lock().expect("nothing panicked"),
        vec![format!("/{did}")]
    );

    // And the name now answers to it.
    let (status, body) = call(
        &router,
        "GET",
        "com.atproto.identity.resolveHandle?handle=Alice.PDS.test",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["did"], did);
}

#[tokio::test]
async fn a_name_this_server_will_not_hand_out_is_refused_by_its_lexicon_name() {
    let (router, _data, seen) = server(false).await;

    for (handle, error) in [
        ("ab.pds.test", "InvalidHandle"),
        ("admin.pds.test", "HandleNotAvailable"),
        ("alice.example.com", "UnsupportedDomain"),
    ] {
        let (status, body) = call(
            &router,
            "POST",
            "com.atproto.server.createAccount",
            Some(signup(handle)),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{handle}");
        assert_eq!(body["error"], error, "{handle}");
    }
    assert!(seen.lock().expect("nothing panicked").is_empty());
}

#[tokio::test]
async fn a_server_that_asks_for_an_invite_says_so_by_name() {
    let (router, _data, _seen) = server(true).await;

    let (status, body) = call(
        &router,
        "POST",
        "com.atproto.server.createAccount",
        Some(signup("alice.pds.test")),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "InvalidInviteCode");
}

#[tokio::test]
async fn an_account_brought_from_somewhere_else_is_not_served_yet() {
    let (router, _data, _seen) = server(false).await;

    let mut input = signup("alice.pds.test");
    input["did"] = json!("did:plc:mav423b24thku7ezkx7yaray");
    let (status, body) = call(
        &router,
        "POST",
        "com.atproto.server.createAccount",
        Some(input),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "Unsupported input: \"did\"");
}

#[tokio::test]
async fn a_handle_nothing_here_holds_is_not_resolved_for_a_client() {
    let (router, _data, _seen) = server(false).await;

    for (query, error) in [
        ("handle=nobody.pds.test", "HandleNotFound"),
        // Somebody else's domain, which this server has no way to ask about.
        ("handle=alice.example.com", "HandleNotFound"),
        ("handle=not%20a%20handle", "InvalidHandle"),
    ] {
        let (status, body) = call(
            &router,
            "GET",
            &format!("com.atproto.identity.resolveHandle?{query}"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{query}");
        assert_eq!(body["error"], error, "{query}");
    }
}

/// The header `pdsadmin` sends, which is HTTP Basic under one fixed name.
fn as_admin(password: &str) -> String {
    use base64::{Engine, engine::general_purpose::STANDARD};
    format!("Basic {}", STANDARD.encode(format!("admin:{password}")))
}

async fn call_as(
    router: &NormalizePath<Router>,
    path: &str,
    authorization: &str,
    body: Value,
) -> (StatusCode, Value) {
    let request = Request::builder()
        .method("POST")
        .uri(format!("/xrpc/{path}"))
        .header(header::AUTHORIZATION, authorization)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .expect("a request");

    let response = router.clone().oneshot(request).await.expect("a response");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("a body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn an_administrator_writes_a_code_and_an_account_comes_in_on_it() {
    let (router, _data, _seen) = server(true).await;

    let (status, body) = call_as(
        &router,
        "com.atproto.server.createInviteCode",
        &as_admin(common::ADMIN),
        json!({ "useCount": 1 }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let code = body["code"].as_str().expect("a code").to_owned();
    assert!(code.starts_with("pds-test-"), "{code}");

    let mut input = signup("alice.pds.test");
    input["inviteCode"] = json!(code);
    let (status, body) = call(
        &router,
        "POST",
        "com.atproto.server.createAccount",
        Some(input),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn nobody_without_the_admin_password_writes_a_code() {
    let (router, _data, _seen) = server(true).await;

    for authorization in [
        as_admin("not the password"),
        // A Basic credential that is not base64, which reaches the same "no
        // credentials" answer as sending none.
        "Basic not-base64!".to_owned(),
        "Bearer admin".to_owned(),
        // The right password under a name that is not the administrator's.
        {
            use base64::{Engine, engine::general_purpose::STANDARD};
            format!(
                "Basic {}",
                STANDARD.encode(format!("alice:{}", common::ADMIN))
            )
        },
    ] {
        let (status, _) = call_as(
            &router,
            "com.atproto.server.createInviteCode",
            &authorization,
            json!({ "useCount": 1 }),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{authorization}");
    }
}

#[tokio::test]
async fn codes_are_written_in_bulk_for_the_accounts_named() {
    let (router, _data, _seen) = server(true).await;

    let (status, body) = call_as(
        &router,
        "com.atproto.server.createInviteCodes",
        &as_admin(common::ADMIN),
        json!({ "codeCount": 2, "useCount": 5, "forAccounts": ["did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["codes"][0]["account"],
        "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"
    );
    assert_eq!(
        body["codes"][0]["codes"].as_array().expect("codes").len(),
        2
    );
}

#[tokio::test]
async fn an_account_signs_in_with_what_it_signed_up_with() {
    let (router, _data, _seen) = server(false).await;

    let (status, created) = call(
        &router,
        "POST",
        "com.atproto.server.createAccount",
        Some(signup("alice.pds.test")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{created}");

    for identifier in ["alice.pds.test", "alice@example.com"] {
        let (status, body) = call(
            &router,
            "POST",
            "com.atproto.server.createSession",
            Some(json!({
                "identifier": identifier,
                "password": "correct horse battery staple",
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{identifier}: {body}");
        assert_eq!(body["did"], created["did"], "{identifier}");
        // A second session rather than the one signing up left with.
        assert_ne!(body["refreshJwt"], created["refreshJwt"], "{identifier}");
    }
}
