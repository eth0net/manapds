//! Signing up and resolving a handle, over a router, as a client reaches them.

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, Uri, header};
use manapds::account;
use manapds::config::{Config, Secret};
use manapds::crypto::{Algorithm, Keypair};
use manapds::server;
use manapds::store;
use manapds::xrpc::auth::Tokens;
use serde_json::{Value, json};
use tempfile::TempDir;
use tower::ServiceExt;
use tower_http::normalize_path::NormalizePath;

const SECRET: &str = "a secret long enough to not be guessed";

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
    let config = Arc::new(Config {
        hostname: "pds.test".to_owned(),
        port: 443,
        service_did: "did:web:pds.test".to_owned(),
        data_directory: data.path().to_path_buf(),
        jwt_secret: Secret::new(SECRET),
        admin_password: Secret::new("admin"),
        plc_rotation_key: Keypair::generate(Algorithm::Secp256k1),
        plc_url: url,
        recovery_key: None,
        handle_domains: vec![".pds.test".to_owned()],
        invite_required,
        blob_upload_limit: 5 * 1024 * 1024,
        privacy_policy_url: None,
        terms_of_service_url: None,
        contact_email: None,
        rate_limits: false,
        rate_limit_bypass_key: None,
        rate_limit_bypass_ips: Vec::new(),
    });
    let tokens = Tokens::new(SECRET, "did:web:pds.test");
    let accounts = store::Accounts::memory().expect("a database");
    let manager = account::Manager::new(Arc::clone(&config), accounts, tokens.clone());
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
