//! The router: what a request reaches, what it is turned away with, and the
//! budget it spends getting there.
//!
//! What each of those is built from is tested beside itself; everything here
//! needs a router and a database standing behind it.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::FromRequestParts;
use axum::{
    Router,
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode, header},
};
use manapds::account;
use manapds::config::{Config, Secret};
use manapds::server;
use manapds::store;
use manapds::syntax::Did;
use manapds::xrpc::auth::{Access, Full, Scope, Tokens};
use manapds::xrpc::{Error, Status};
use tower::ServiceExt;
use tower_http::normalize_path::NormalizePath;

fn account() -> Did {
    "did:plc:4cjoyc3cgpal7gnrpzyjhnv3".parse().expect("a DID")
}

fn config() -> Config {
    common::config("pds.example.com", "data", "http://127.0.0.1:1")
}

fn tokens() -> Tokens {
    Tokens::new(common::SECRET, "did:web:pds.example.com")
}

/// The context a router is built from, around a database held in memory.
fn context() -> server::Context {
    context_from(config())
}

fn context_from(config: Config) -> server::Context {
    let config = Arc::new(config);
    let accounts = store::Accounts::memory().expect("a database");
    let manager = account::Manager::new(
        Arc::clone(&config),
        accounts,
        store::Sequencer::memory().expect("a log"),
        tokens(),
    )
    // Nothing here is timed, and the pad is what makes signing in slow.
    .answering_in(std::time::Duration::ZERO);
    server::Context::new(config, Arc::new(manager), tokens())
}

/// Sends one request through the router, as if from `peer`.
async fn call(
    router: &NormalizePath<Router>,
    method: &str,
    path: &str,
    peer: &str,
) -> (StatusCode, String) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .body(Body::empty())
        .expect("a request");
    let peer: SocketAddr = peer.parse().expect("an address");
    request.extensions_mut().insert(ConnectInfo(peer));

    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("the router answers");
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("a body");
    (status, String::from_utf8(body.to_vec()).expect("text"))
}

#[tokio::test]
async fn a_method_this_server_does_not_serve_says_so() {
    let router = server::router(context());
    let (status, body) = call(
        &router,
        "GET",
        "/xrpc/com.atproto.sync.subscribeRepos",
        "1.2.3.4:9",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    assert!(body.contains("MethodNotImplemented"), "{body}");
}

#[tokio::test]
async fn a_path_that_is_not_a_lexicon_is_refused_before_that() {
    let router = server::router(context());
    let (status, body) = call(&router, "GET", "/xrpc/not-an-nsid", "1.2.3.4:9").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("invalid xrpc path"), "{body}");
}

#[tokio::test]
async fn a_query_asked_for_as_a_procedure_names_the_verb_it_wanted() {
    let router = server::router(context());
    let (status, body) = call(
        &router,
        "POST",
        "/xrpc/com.atproto.server.describeServer",
        "1.2.3.4:9",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("expected GET"), "{body}");
}

#[tokio::test]
async fn a_method_asked_for_with_a_trailing_slash_is_still_served() {
    let router = server::router(context());
    let (status, body) = call(
        &router,
        "GET",
        "/xrpc/com.atproto.server.describeServer/",
        "1.2.3.4:9",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("availableUserDomains"), "{body}");
}

#[tokio::test]
async fn a_path_outside_xrpc_is_left_alone() {
    let router = server::router(context());
    let (status, _) = call(&router, "GET", "/nothing/here", "1.2.3.4:9").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, body) = call(&router, "GET", "/robots.txt", "1.2.3.4:9").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("User-agent: *"), "{body}");
}

/// Runs an extractor over a request carrying this header.
async fn extract<T>(header: Option<&str>) -> Result<T, Error>
where
    T: FromRequestParts<manapds::server::Context, Rejection = Error>,
{
    let mut request = Request::builder().uri("/xrpc/com.atproto.repo.createRecord");
    if let Some(header) = header {
        request = request.header(axum::http::header::AUTHORIZATION, header);
    }
    let (mut parts, ()) = request.body(()).expect("a request").into_parts();
    T::from_request_parts(&mut parts, &context()).await
}

#[tokio::test]
async fn a_handler_is_handed_the_account_its_caller_signed_in_as() {
    let token = tokens().access(&account(), Scope::Access);
    let access: Access = extract(Some(&format!("Bearer {token}")))
        .await
        .expect("the session verifies");
    assert_eq!(access.did, account());

    let error = extract::<Access>(None)
        .await
        .expect_err("nothing was offered");
    assert_eq!(error.status(), Status::AuthenticationRequired);
    assert_eq!(error.name(), "AuthMissing");
    assert_eq!(error.message(), "Authentication Required");

    let error = extract::<Access>(Some("Bearer not-a-token"))
        .await
        .expect_err("that is not one of ours");
    assert_eq!(error.name(), "InvalidToken");
}

#[tokio::test]
async fn a_method_that_asks_for_a_full_session_will_not_take_an_app_password() {
    let tokens = tokens();
    for scope in [Scope::AppPassword, Scope::PrivilegedAppPassword] {
        let header = format!("Bearer {}", tokens.access(&account(), scope));
        extract::<Access>(Some(&header))
            .await
            .expect("an app password signs in");
        let error = extract::<Full>(Some(&header))
            .await
            .expect_err("and gets no further");
        assert_eq!(error.message(), "Bad token scope");
    }

    let header = format!("Bearer {}", tokens.access(&account(), Scope::Access));
    let Full(access) = extract(Some(&header)).await.expect("a password does");
    assert_eq!(access.did, account());
}

#[tokio::test]
async fn a_caller_that_spends_its_budget_is_told_what_it_has_left() {
    let mut config = config();
    config.rate_limits = true;
    let router = server::router(context_from(config));

    let request = Request::builder()
        .uri("/xrpc/com.atproto.server.describeServer")
        .body(Body::empty())
        .expect("a request");
    let mut request = request;
    request.extensions_mut().insert(ConnectInfo(
        "1.2.3.4:9".parse::<SocketAddr>().expect("an address"),
    ));

    let response = router.oneshot(request).await.expect("an answer");
    assert_eq!(response.status(), StatusCode::OK);
    let header = |name: &str| {
        response
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    };
    assert_eq!(header("ratelimit-limit").as_deref(), Some("3000"));
    assert_eq!(header("ratelimit-remaining").as_deref(), Some("2999"));
    assert_eq!(header("ratelimit-policy").as_deref(), Some("3000;w=300"));
}

#[tokio::test]
async fn the_budget_is_off_unless_it_is_asked_for() {
    let router = server::router(context());
    let request = Request::builder()
        .uri("/xrpc/com.atproto.server.describeServer")
        .header(header::ACCEPT, "application/json")
        .body(Body::empty())
        .expect("a request");
    let response = router.oneshot(request).await.expect("an answer");
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get("ratelimit-limit").is_none());
}

#[tokio::test]
async fn a_caller_holding_the_bypass_key_is_not_counted() {
    let mut config = config();
    config.rate_limits = true;
    config.rate_limit_bypass_key = Some(Secret::new("let me through"));
    let router = server::router(context_from(config));

    let mut request = Request::builder()
        .uri("/xrpc/com.atproto.server.describeServer")
        .header("x-ratelimit-bypass", "let me through")
        .body(Body::empty())
        .expect("a request");
    request.extensions_mut().insert(ConnectInfo(
        "1.2.3.4:9".parse::<SocketAddr>().expect("an address"),
    ));

    let response = router.oneshot(request).await.expect("an answer");
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get("ratelimit-limit").is_none());
}

#[tokio::test]
async fn a_browser_is_told_it_may_call_from_anywhere() {
    let request = Request::builder()
        .method("OPTIONS")
        .uri("/xrpc/com.atproto.server.describeServer")
        .header("origin", "https://client.example.com")
        .header("access-control-request-method", "GET")
        .body(Body::empty())
        .expect("a request");

    let response = server::router(context())
        .oneshot(request)
        .await
        .expect("an answer");
    let allowed = |name: &str| {
        response
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    };
    assert_eq!(allowed("access-control-allow-origin").as_deref(), Some("*"));
    assert_eq!(allowed("access-control-max-age").as_deref(), Some("86400"));
}

#[tokio::test]
async fn an_answer_that_depended_on_the_caller_says_so() {
    // A route of the test's own, since nothing served yet reads credentials.
    let router = Router::new()
        .route(
            "/xrpc/com.example.mine",
            axum::routing::get(|_: Access| async { "yours" }),
        )
        .route(
            "/xrpc/com.example.anyones",
            axum::routing::get(|| async { "everyone's" }),
        )
        .with_state(context())
        .layer(axum::middleware::from_fn(manapds::xrpc::auth::private));

    let call = async |path: &str, header: Option<String>| {
        let mut request = Request::builder().uri(path);
        if let Some(header) = header {
            request = request.header(axum::http::header::AUTHORIZATION, header);
        }
        router
            .clone()
            .oneshot(request.body(Body::empty()).expect("a request"))
            .await
            .expect("an answer")
    };

    let token = tokens().access(&account(), Scope::Access);
    let mine = call("/xrpc/com.example.mine", Some(format!("Bearer {token}"))).await;
    assert_eq!(mine.status(), StatusCode::OK);
    assert_eq!(
        mine.headers().get(axum::http::header::CACHE_CONTROL),
        Some(&axum::http::HeaderValue::from_static("private"))
    );
    assert_eq!(
        mine.headers().get(axum::http::header::VARY),
        Some(&axum::http::HeaderValue::from_static("Authorization"))
    );

    // Refusing to answer still depended on the credential offered.
    let refused = call("/xrpc/com.example.mine", None).await;
    assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
    assert!(refused.headers().contains_key(axum::http::header::VARY));

    // A public answer is the same for everyone and may be shared as such.
    let anyones = call("/xrpc/com.example.anyones", None).await;
    assert_eq!(anyones.status(), StatusCode::OK);
    assert!(!anyones.headers().contains_key(axum::http::header::VARY));
    assert!(
        !anyones
            .headers()
            .contains_key(axum::http::header::CACHE_CONTROL)
    );
}

#[tokio::test]
async fn a_caller_past_its_budget_is_refused_and_told_when_to_return() {
    let mut config = config();
    config.rate_limits = true;
    let router = server::router(context_from(config));

    let call = async || {
        let mut request = Request::builder()
            .uri("/xrpc/com.atproto.server.describeServer")
            .body(Body::empty())
            .expect("a request");
        request.extensions_mut().insert(ConnectInfo(
            "1.2.3.4:9".parse::<SocketAddr>().expect("an address"),
        ));
        router.clone().oneshot(request).await.expect("an answer")
    };

    // The global budget is 3000 points per five minutes, one point a call.
    for _ in 0..3000 {
        assert_eq!(call().await.status(), StatusCode::OK);
    }

    let refused = call().await;
    assert_eq!(refused.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(refused.headers().contains_key("retry-after"));
    assert_eq!(
        refused
            .headers()
            .get("ratelimit-remaining")
            .and_then(|value| value.to_str().ok()),
        Some("0")
    );

    let body = axum::body::to_bytes(refused.into_body(), 64 * 1024)
        .await
        .expect("a body");
    let body = String::from_utf8(body.to_vec()).expect("text");
    assert!(body.contains("RateLimitExceeded"), "{body}");

    // Another caller still has its own.
    let mut request = Request::builder()
        .uri("/xrpc/com.atproto.server.describeServer")
        .body(Body::empty())
        .expect("a request");
    request.extensions_mut().insert(ConnectInfo(
        "5.6.7.8:9".parse::<SocketAddr>().expect("an address"),
    ));
    let other = router.clone().oneshot(request).await.expect("an answer");
    assert_eq!(other.status(), StatusCode::OK);
}

#[tokio::test]
async fn the_one_path_with_its_own_budget_spends_that_and_not_the_shared_one() {
    let mut config = config();
    config.rate_limits = true;
    let router = server::router(context_from(config));

    let mut request = Request::builder()
        .uri("/xrpc/com.atproto.sync.getRepo")
        .body(Body::empty())
        .expect("a request");
    request.extensions_mut().insert(ConnectInfo(
        "1.2.3.4:9".parse::<SocketAddr>().expect("an address"),
    ));

    let response = router.oneshot(request).await.expect("an answer");
    assert_eq!(
        response
            .headers()
            .get("ratelimit-limit")
            .and_then(|value| value.to_str().ok()),
        Some("6000")
    );
}

#[tokio::test]
async fn signing_in_spends_a_budget_the_account_it_names_holds() {
    let mut config = config();
    config.rate_limits = true;
    let router = server::router(context_from(config));

    let sign_in = async |identifier: &str, peer: &str| {
        let mut request = Request::builder()
            .method("POST")
            .uri("/xrpc/com.atproto.server.createSession")
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"identifier":"{identifier}","password":"hunter2"}}"#
            )))
            .expect("a request");
        request
            .extensions_mut()
            .insert(ConnectInfo(peer.parse::<SocketAddr>().expect("an address")));
        router
            .clone()
            .oneshot(request)
            .await
            .expect("an answer")
            .status()
    };

    // Thirty tries per five minutes, whatever the answer was.
    for _ in 0..30 {
        assert_eq!(
            sign_in("alice.pds.example.com", "1.2.3.4:9").await,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        sign_in("alice.pds.example.com", "1.2.3.4:9").await,
        StatusCode::TOO_MANY_REQUESTS
    );
    // Spelling the same account another way is not a budget of its own.
    assert_eq!(
        sign_in("ALICE.pds.example.com", "1.2.3.4:9").await,
        StatusCode::TOO_MANY_REQUESTS
    );

    // Another account from the same line still has its own, and so does the
    // same account from somewhere else.
    assert_eq!(
        sign_in("bob.pds.example.com", "1.2.3.4:9").await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        sign_in("alice.pds.example.com", "5.6.7.8:9").await,
        StatusCode::UNAUTHORIZED
    );

    // A name past what any account could answer to is held by what it starts
    // with, so a caller cannot mint a key of its own by writing a longer one.
    let long = "z".repeat(4000);
    for _ in 0..30 {
        assert_eq!(sign_in(&long, "9.9.9.9:9").await, StatusCode::UNAUTHORIZED);
    }
    assert_eq!(
        sign_in(&format!("{long}{long}"), "9.9.9.9:9").await,
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn a_sign_in_too_large_to_read_still_reaches_the_method() {
    let mut config = config();
    config.rate_limits = true;
    let router = server::router(context_from(config));

    let mut request = Request::builder()
        .method("POST")
        .uri("/xrpc/com.atproto.server.createSession")
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"identifier":"{}","password":"hunter2"}}"#,
            "a".repeat(64 * 1024)
        )))
        .expect("a request");
    request.extensions_mut().insert(ConnectInfo(
        "1.2.3.4:9".parse::<SocketAddr>().expect("an address"),
    ));

    // Counted under no name and handed on whole, so the method answers for
    // itself.
    let answer = router.oneshot(request).await.expect("an answer");
    assert_eq!(answer.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_sign_in_that_will_not_say_how_long_it_is_still_reaches_the_method() {
    let mut config = config();
    config.rate_limits = true;
    let router = server::router(context_from(config));

    let body = format!(
        r#"{{"identifier":"{}","password":"hunter2"}}"#,
        "a".repeat(64 * 1024)
    );
    let mut request = Request::builder()
        .method("POST")
        .uri("/xrpc/com.atproto.server.createSession")
        .header("content-type", "application/json")
        // A stream says nothing about its length, which is what a chunked
        // body looks like from here.
        .body(Body::from_stream(futures_util::stream::once(async move {
            Ok::<_, std::convert::Infallible>(body)
        })))
        .expect("a request");
    request.extensions_mut().insert(ConnectInfo(
        "1.2.3.4:9".parse::<SocketAddr>().expect("an address"),
    ));

    let answer = router.oneshot(request).await.expect("an answer");
    assert_eq!(answer.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn signing_up_spends_a_budget_of_its_own() {
    let mut config = config();
    config.rate_limits = true;
    // Refused before anything is written, which is the cheapest hundred
    // signups a test can make.
    config.invite_required = true;
    let router = server::router(context_from(config));

    let sign_up = async |peer: &str| {
        let mut request = Request::builder()
            .method("POST")
            .uri("/xrpc/com.atproto.server.createAccount")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"handle":"alice.pds.example.com","email":"alice@example.com","password":"hunter2"}"#,
            ))
            .expect("a request");
        request
            .extensions_mut()
            .insert(ConnectInfo(peer.parse::<SocketAddr>().expect("an address")));
        router
            .clone()
            .oneshot(request)
            .await
            .expect("an answer")
            .status()
    };

    for _ in 0..100 {
        assert_eq!(sign_up("1.2.3.4:9").await, StatusCode::BAD_REQUEST);
    }
    assert_eq!(sign_up("1.2.3.4:9").await, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(sign_up("5.6.7.8:9").await, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn describe_server_answers_the_fields_its_lexicon_declares() {
    let mut config = config();
    config.contact_email = Some("hello@pds.example.com".to_owned());
    config.invite_required = true;
    let router = server::router(context_from(config));

    let (status, body) = call(
        &router,
        "GET",
        "/xrpc/com.atproto.server.describeServer",
        "1.2.3.4:9",
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let answer: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(answer["did"], "did:web:pds.example.com");
    assert_eq!(answer["availableUserDomains"][0], ".pds.example.com");
    assert_eq!(answer["inviteCodeRequired"], true);
    assert_eq!(answer["blobUploadLimit"], 5 * 1024 * 1024);
    assert_eq!(answer["contact"]["email"], "hello@pds.example.com");

    // What is unset is absent rather than null, which is what the lexicon's
    // optional fields mean.
    assert!(answer["links"].get("privacyPolicy").is_none(), "{body}");
    assert!(answer["links"].get("termsOfService").is_none(), "{body}");
}
