//! The request surface: what a method answers with, who it answers, and how
//! much of it one caller gets.

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
use manapds::xrpc::auth::{Access, Authorization, Credential, Expired, Full, Scope, Tokens};
use manapds::xrpc::limit::{self, Limiter};
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
    let router = server::router(context());
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
        .verify_refresh(&token, Expired::Refuse)
        .expect("the token verifies");
    assert_eq!(refresh.did, account());
    assert_eq!(refresh.id, "a-stored-session");
}

#[test]
fn neither_kind_of_token_can_be_spent_as_the_other() {
    let tokens = tokens();
    let access = tokens.access(&account(), Scope::Access);
    let refresh = tokens.refresh(&account(), "a-stored-session");
    assert!(tokens.verify_refresh(&access, Expired::Refuse).is_err());
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
fn a_refresh_token_past_its_expiry_can_still_end_its_session() {
    let tokens = tokens();
    let token = tokens.refresh(&account(), "a-stored-session");

    // Nothing here mints an expired refresh token, so this pins the choice
    // rather than the clock: refusing is what exchanging one does.
    assert!(tokens.verify_refresh(&token, Expired::Refuse).is_ok());
    assert!(tokens.verify_refresh(&token, Expired::Allow).is_ok());

    let stale = forge(
        "refresh+jwt",
        &serde_json::json!({
            "scope": "com.atproto.refresh",
            "sub": account().as_str(),
            "aud": "did:web:pds.example.com",
            "jti": "a-stored-session",
            "iat": 1_600_000_000,
            "exp": 1_600_000_001,
        }),
    );
    assert_eq!(
        tokens
            .verify_refresh(&stale, Expired::Refuse)
            .expect_err("too late to exchange")
            .name(),
        "ExpiredToken"
    );
    assert_eq!(
        tokens
            .verify_refresh(&stale, Expired::Allow)
            .expect("late is still this session")
            .id,
        "a-stored-session"
    );
}

#[test]
fn a_tampered_token_does_not_verify() {
    let tokens = tokens();
    let token = tokens.access(&account(), Scope::Access);
    let (body, signature) = token.rsplit_once('.').expect("three parts");
    let forged = format!("{body}x.{signature}");
    assert!(tokens.verify_access(&forged, &Scope::STANDARD).is_err());
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
fn a_proxy_is_believed_however_its_address_is_spelled() {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("x-forwarded-for", "9.9.9.9".parse().expect("a header"));

    // The same loopback, written the way a dual-stack socket reports it.
    let mapped: SocketAddr = "[::ffff:127.0.0.1]:9".parse().expect("an address");
    assert_eq!(limit::caller(mapped.ip(), &headers).to_string(), "9.9.9.9");

    // Carrier-grade NAT, which is what a hosting front-end arrives from.
    let cgnat: SocketAddr = "100.64.0.1:9".parse().expect("an address");
    assert_eq!(limit::caller(cgnat.ip(), &headers).to_string(), "9.9.9.9");

    // And one caller reaching us both ways is still one caller.
    let straight: SocketAddr = "[::ffff:8.8.8.8]:9".parse().expect("an address");
    assert_eq!(
        limit::caller(straight.ip(), &axum::http::HeaderMap::new()).to_string(),
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

/// Mints a token this server would not, so the checks on the way back in can
/// be reached from outside it.
fn forge(typ: &str, claims: &serde_json::Value) -> String {
    use base64::Engine as _;
    use hmac::Mac as _;

    let encoder = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header = encoder.encode(serde_json::json!({"alg": "HS256", "typ": typ}).to_string());
    let signed = format!("{header}.{}", encoder.encode(claims.to_string()));

    let mut mac =
        <hmac::Hmac<sha2::Sha256> as hmac::KeyInit>::new_from_slice(common::SECRET.as_bytes())
            .expect("a key of any length");
    mac.update(signed.as_bytes());
    format!("{signed}.{}", encoder.encode(mac.finalize().into_bytes()))
}

/// The claims of a session this server would have issued.
fn session() -> serde_json::Value {
    serde_json::json!({
        "scope": "com.atproto.access",
        "sub": account().as_str(),
        "aud": "did:web:pds.example.com",
        "iat": 1_700_000_000,
        "exp": 4_100_000_000i64,
    })
}

#[test]
fn a_token_proving_something_else_is_not_a_session() {
    let tokens = tokens();
    for claim in ["lxm", "cnf"] {
        let mut claims = session();
        claims[claim] = serde_json::json!("com.atproto.repo.createRecord");
        let error = tokens
            .verify_access(&forge("at+jwt", &claims), &Scope::STANDARD)
            .expect_err("service auth is not a session");
        assert_eq!(error.message(), "Malformed token", "{claim}");
    }

    // The same claims without either are a session, so the refusal above is
    // the claim and not the forging.
    assert!(
        tokens
            .verify_access(&forge("at+jwt", &session()), &Scope::STANDARD)
            .is_ok()
    );
}

#[test]
fn a_scope_this_server_never_issued_is_a_scope_problem() {
    let mut claims = session();
    claims["scope"] = serde_json::json!("com.atproto.somethingElse");
    let error = tokens()
        .verify_access(&forge("at+jwt", &claims), &Scope::STANDARD)
        .expect_err("no such scope");
    assert_eq!(error.message(), "Bad token scope");
}

#[test]
fn a_token_for_another_service_reads_as_one_we_cannot_verify() {
    let mut claims = session();
    claims["aud"] = serde_json::json!("did:web:elsewhere.example.com");
    let error = tokens()
        .verify_access(&forge("at+jwt", &claims), &Scope::STANDARD)
        .expect_err("not our audience");
    assert_eq!(error.message(), "Token could not be verified");
}

#[test]
fn a_basic_header_that_will_not_decode_is_no_credential_at_all() {
    // Upstream falls through to "nothing was offered" rather than answering a
    // different status, so an admin endpoint gives one answer either way.
    assert_eq!(
        Authorization::parse(Some("Basic not-base64!!")).expect("no credential"),
        Authorization(None)
    );
    assert_eq!(
        Authorization::parse(Some("Basic bm9jb2xvbg==")).expect("no credential"),
        Authorization(None)
    );
}

#[test]
fn a_budget_comes_back_when_its_window_has_passed() {
    let limiter = Limiter::new(1, std::time::Duration::from_millis(40));
    assert!(!limiter.consume("1.2.3.4", 1).exceeded);
    assert!(limiter.consume("1.2.3.4", 1).exceeded);

    std::thread::sleep(std::time::Duration::from_millis(60));
    let reading = limiter.consume("1.2.3.4", 1);
    assert!(!reading.exceeded, "the window refilled");
    assert_eq!(reading.spent, 1, "and it started again from nothing");
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
async fn the_one_path_with_its_own_budget_is_not_counted_here() {
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
    assert!(response.headers().get("ratelimit-limit").is_none());
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

#[test]
fn every_status_is_named_the_way_the_lexicons_name_it() {
    // Transcribed from ResponseType and ResponseTypeStrings in
    // packages/xrpc/src/types.ts. Clients branch on the middle column.
    let table = [
        (
            Status::InvalidRequest,
            400,
            "InvalidRequest",
            "Invalid Request",
        ),
        (
            Status::AuthenticationRequired,
            401,
            "AuthenticationRequired",
            "Authentication Required",
        ),
        (Status::Forbidden, 403, "Forbidden", "Forbidden"),
        (
            Status::XrpcNotSupported,
            404,
            "XRPCNotSupported",
            "XRPC Not Supported",
        ),
        (
            Status::NotAcceptable,
            406,
            "NotAcceptable",
            "Not Acceptable",
        ),
        (
            Status::PayloadTooLarge,
            413,
            "PayloadTooLarge",
            "Payload Too Large",
        ),
        (
            Status::UnsupportedMediaType,
            415,
            "UnsupportedMediaType",
            "Unsupported Media Type",
        ),
        (
            Status::RateLimitExceeded,
            429,
            "RateLimitExceeded",
            "Rate Limit Exceeded",
        ),
        (
            Status::InternalServerError,
            500,
            "InternalServerError",
            "Internal Server Error",
        ),
        (
            Status::MethodNotImplemented,
            501,
            "MethodNotImplemented",
            "Method Not Implemented",
        ),
        (
            Status::UpstreamFailure,
            502,
            "UpstreamFailure",
            "Upstream Failure",
        ),
        (
            Status::NotEnoughResources,
            503,
            "NotEnoughResources",
            "Not Enough Resources",
        ),
        (
            Status::UpstreamTimeout,
            504,
            "UpstreamTimeout",
            "Upstream Timeout",
        ),
    ];

    for (status, code, name, description) in table {
        assert_eq!(status.code().as_u16(), code, "{name}");
        assert_eq!(status.name(), name);
        assert_eq!(status.description(), description, "{name}");
    }
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

#[test]
fn one_line_spends_one_budget_however_many_addresses_it_holds() {
    let rotated = |address: &str| limit::budget(address.parse().expect("an address"));

    // A residential line or a VPS is given a /64, so an address it has not
    // used yet is not a caller we have not seen.
    assert_eq!(
        rotated("2001:db8:1:2::1"),
        rotated("2001:db8:1:2:dead:beef::")
    );
    assert_ne!(rotated("2001:db8:1:2::1"), rotated("2001:db8:1:3::1"));

    // IPv4 is scarce enough that neighbors are not the same customer.
    assert_ne!(rotated("9.9.9.9"), rotated("9.9.9.10"));
    assert_eq!(rotated("9.9.9.9"), "9.9.9.9");
}

#[test]
fn a_budget_holding_every_key_it_will_counts_nobody_new() {
    let limiter = Limiter::new(1, std::time::Duration::from_mins(5));
    for key in 0..100_000 {
        assert!(!limiter.consume(&key.to_string(), 1).exceeded);
    }

    // The table is full, so an arrival nothing has seen goes uncounted rather
    // than costing memory the process cannot get back.
    let reading = limiter.consume("one too many", 1);
    assert_eq!(reading.spent, 0);
    assert!(!reading.exceeded);

    // A key already in there is still held to its budget.
    assert!(limiter.consume("0", 1).exceeded);
}
