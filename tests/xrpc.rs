//! The request surface: what a method answers with, who it answers, and how
//! much of it one caller gets.

use std::net::SocketAddr;

use axum::extract::FromRequestParts;
use axum::{
    Router,
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode, header},
};
use manapds::config::{Config, Secret};
use manapds::server;
use manapds::syntax::Did;
use manapds::xrpc::auth::{Access, Authorization, Credential, Scope, Tokens};
use manapds::xrpc::limit::{self, Limiter};
use manapds::xrpc::{Error, Status};
use tower::ServiceExt;

fn account() -> Did {
    "did:plc:4cjoyc3cgpal7gnrpzyjhnv3".parse().expect("a DID")
}

fn tokens() -> Tokens {
    Tokens::new("a secret", "did:web:pds.example.com")
}

fn config() -> Config {
    Config {
        hostname: "pds.example.com".to_owned(),
        port: 0,
        service_did: "did:web:pds.example.com".to_owned(),
        data_directory: "data".into(),
        jwt_secret: Secret::new("a secret"),
        handle_domains: vec![".pds.example.com".to_owned()],
        invite_required: true,
        blob_upload_limit: 5 * 1024 * 1024,
        privacy_policy_url: None,
        terms_of_service_url: None,
        contact_email: None,
        rate_limits: false,
        rate_limit_bypass_key: None,
        rate_limit_bypass_ips: Vec::new(),
    }
}

/// Sends one request through the router, as if from `peer`.
async fn call(router: &Router, method: &str, path: &str, peer: &str) -> (StatusCode, String) {
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

#[test]
fn an_error_falls_back_to_the_name_of_its_status() {
    let error = Error::new(Status::MethodNotImplemented);
    assert_eq!(error.name(), "MethodNotImplemented");
    assert_eq!(error.message(), "Method Not Implemented");
}

#[test]
fn a_lexicon_name_is_what_the_client_branches_on() {
    let error = Error::invalid_request("Token has expired").named("ExpiredToken");
    assert_eq!(error.status(), Status::InvalidRequest);
    assert_eq!(error.name(), "ExpiredToken");
    assert_eq!(error.message(), "Token has expired");
}

#[test]
fn a_fault_on_this_side_is_never_described() {
    let error = Error::internal("the database is on fire");
    assert_eq!(error.name(), "InternalServerError");
    assert_eq!(error.message(), "Internal Server Error");
}

#[tokio::test]
async fn a_method_this_server_does_not_serve_says_so() {
    let router = server::router(config());
    let (status, body) = call(
        &router,
        "GET",
        "/xrpc/com.atproto.sync.getBlob",
        "1.2.3.4:9",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    assert!(body.contains("MethodNotImplemented"), "{body}");
}

#[tokio::test]
async fn a_path_that_is_not_a_lexicon_is_refused_before_that() {
    let router = server::router(config());
    let (status, body) = call(&router, "GET", "/xrpc/not-an-nsid", "1.2.3.4:9").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("invalid xrpc path"), "{body}");
}

#[tokio::test]
async fn a_query_asked_for_as_a_procedure_names_the_verb_it_wanted() {
    let router = server::router(config());
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
async fn a_path_outside_xrpc_is_left_alone() {
    let router = server::router(config());
    let (status, _) = call(&router, "GET", "/nothing/here", "1.2.3.4:9").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, body) = call(&router, "GET", "/robots.txt", "1.2.3.4:9").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("User-agent: *"), "{body}");
}

#[test]
fn an_access_token_comes_back_as_the_session_that_minted_it() {
    let tokens = tokens();
    let token = tokens.access(&account(), Scope::Access);
    let access = tokens
        .verify_access(&token, &Scope::STANDARD)
        .expect("the token verifies");
    assert_eq!(access.did, account());
    assert_eq!(access.scope, Scope::Access);
}

#[test]
fn a_refresh_token_carries_the_id_the_session_is_stored_under() {
    let tokens = tokens();
    let token = tokens.refresh(&account(), "a-stored-session");
    let refresh = tokens
        .verify_refresh(&token, false)
        .expect("the token verifies");
    assert_eq!(refresh.did, account());
    assert_eq!(refresh.id, "a-stored-session");
}

#[test]
fn neither_kind_of_token_can_be_spent_as_the_other() {
    let tokens = tokens();
    let access = tokens.access(&account(), Scope::Access);
    let refresh = tokens.refresh(&account(), "a-stored-session");
    assert!(tokens.verify_refresh(&access, false).is_err());
    assert!(tokens.verify_access(&refresh, &Scope::STANDARD).is_err());
}

#[test]
fn a_token_another_secret_signed_is_not_one_of_ours() {
    let token =
        Tokens::new("another secret", "did:web:pds.example.com").access(&account(), Scope::Access);
    let error = tokens()
        .verify_access(&token, &Scope::STANDARD)
        .expect_err("the signature is not ours");
    assert_eq!(error.name(), "InvalidToken");
}

#[test]
fn a_token_minted_for_another_service_is_not_accepted_here() {
    let token =
        Tokens::new("a secret", "did:web:elsewhere.example.com").access(&account(), Scope::Access);
    let error = tokens()
        .verify_access(&token, &Scope::STANDARD)
        .expect_err("the audience is not us");
    assert_eq!(error.name(), "InvalidToken");
}

#[test]
fn an_app_password_does_not_reach_what_a_full_session_does() {
    let tokens = tokens();
    let token = tokens.access(&account(), Scope::AppPassword);
    assert!(tokens.verify_access(&token, &Scope::STANDARD).is_ok());
    let error = tokens
        .verify_access(&token, &Scope::PRIVILEGED)
        .expect_err("an app password is not privileged");
    assert_eq!(error.message(), "Bad token scope");
}

#[test]
fn a_tampered_token_does_not_verify() {
    let tokens = tokens();
    let token = tokens.access(&account(), Scope::Access);
    let (body, signature) = token.rsplit_once('.').expect("three parts");
    let forged = format!("{body}x.{signature}");
    assert!(tokens.verify_access(&forged, &Scope::STANDARD).is_err());
}

/// Runs the `Access` extractor over a request carrying this header.
async fn extract(header: Option<&str>) -> Result<manapds::xrpc::auth::Access, Error> {
    let mut request = Request::builder().uri("/xrpc/com.atproto.repo.createRecord");
    if let Some(header) = header {
        request = request.header(axum::http::header::AUTHORIZATION, header);
    }
    let (mut parts, ()) = request.body(()).expect("a request").into_parts();
    manapds::xrpc::auth::Access::from_request_parts(&mut parts, &server::Context::new(config()))
        .await
}

#[tokio::test]
async fn a_handler_is_handed_the_account_its_caller_signed_in_as() {
    let token = tokens().access(&account(), Scope::Access);
    let access = extract(Some(&format!("Bearer {token}")))
        .await
        .expect("the session verifies");
    assert_eq!(access.did, account());

    let error = extract(None).await.expect_err("nothing was offered");
    assert_eq!(error.status(), Status::AuthenticationRequired);
    assert_eq!(error.name(), "AuthMissing");
    assert_eq!(error.message(), "Authentication Required");

    let error = extract(Some("Bearer not-a-token"))
        .await
        .expect_err("that is not one of ours");
    assert_eq!(error.name(), "InvalidToken");
}

#[test]
fn the_authorization_header_is_read_as_the_scheme_it_names() {
    assert_eq!(
        Authorization::parse(None).expect("nothing"),
        Authorization(None)
    );
    assert_eq!(
        Authorization::parse(Some("bearer a-token"))
            .expect("a bearer token")
            .bearer(),
        Some("a-token")
    );
    assert_eq!(
        Authorization::parse(Some("Basic YWRtaW46aHVudGVyOjI=")).expect("a password"),
        Authorization(Some(Credential::Basic {
            username: "admin".to_owned(),
            password: "hunter:2".to_owned(),
        }))
    );
    assert_eq!(
        Authorization::parse(Some("Digest nope"))
            .expect_err("nothing here speaks digest")
            .message(),
        "Unsupported authorization type: Digest"
    );
    assert!(Authorization::parse(Some("Bearer")).is_err());
}

#[test]
fn a_budget_runs_out_and_says_when_it_is_back() {
    let limiter = Limiter::new(2, std::time::Duration::from_mins(5));
    assert!(!limiter.consume("1.2.3.4", 1).exceeded);
    let reading = limiter.consume("1.2.3.4", 1);
    assert!(!reading.exceeded);
    assert_eq!(reading.remaining, 0);
    let reading = limiter.consume("1.2.3.4", 1);
    assert!(reading.exceeded);
    assert!(reading.resets_in <= std::time::Duration::from_mins(5));
    // Another caller has its own.
    assert!(!limiter.consume("5.6.7.8", 1).exceeded);
}

#[tokio::test]
async fn a_caller_that_spends_its_budget_is_told_what_it_has_left() {
    let mut config = config();
    config.rate_limits = true;
    let router = server::router(config);

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
    let router = server::router(config());
    let request = Request::builder()
        .uri("/xrpc/com.atproto.server.describeServer")
        .header(header::ACCEPT, "application/json")
        .body(Body::empty())
        .expect("a request");
    let response = router.oneshot(request).await.expect("an answer");
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get("ratelimit-limit").is_none());
}

#[test]
fn a_token_past_its_expiry_says_which_of_the_two_it_is() {
    let tokens = tokens();
    let token = tokens.access_for(
        &account(),
        Scope::Access,
        jiff::SignedDuration::from_secs(-1),
    );
    let error = tokens
        .verify_access(&token, &Scope::STANDARD)
        .expect_err("an hour too late");
    assert_eq!(error.name(), "ExpiredToken");
    assert_eq!(error.message(), "Token has expired");
}

#[test]
fn a_caller_cannot_name_someone_else_to_spend_the_budget() {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("x-forwarded-for", "9.9.9.9".parse().expect("a header"));

    let behind_a_proxy: SocketAddr = "127.0.0.1:9".parse().expect("an address");
    assert_eq!(
        limit::caller(behind_a_proxy.ip(), &headers).to_string(),
        "9.9.9.9"
    );

    let straight_off_the_internet: SocketAddr = "8.8.8.8:9".parse().expect("an address");
    assert_eq!(
        limit::caller(straight_off_the_internet.ip(), &headers).to_string(),
        "8.8.8.8"
    );
}

#[test]
fn a_chain_of_proxies_is_walked_back_to_the_first_one_outside() {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        "x-forwarded-for",
        "1.1.1.1, 9.9.9.9, 10.0.0.7".parse().expect("a header"),
    );
    let peer: SocketAddr = "127.0.0.1:9".parse().expect("an address");
    assert_eq!(limit::caller(peer.ip(), &headers).to_string(), "9.9.9.9");
}

#[tokio::test]
async fn a_caller_holding_the_bypass_key_is_not_counted() {
    let mut config = config();
    config.rate_limits = true;
    config.rate_limit_bypass_key = Some(Secret::new("let me through"));
    let router = server::router(config);

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

    let response = server::router(config())
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
        .with_state(server::Context::new(config()))
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
