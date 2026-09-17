//! The request surface: what a method answers with, who it answers, and how
//! much of it one caller gets.

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use manapds::config::Config;
use manapds::server;
use manapds::xrpc::{Error, Status};
use tower::ServiceExt;

fn config() -> Config {
    Config {
        hostname: "pds.example.com".to_owned(),
        port: 0,
        service_did: "did:web:pds.example.com".to_owned(),
        data_directory: "data".into(),
        handle_domains: vec![".pds.example.com".to_owned()],
        invite_required: true,
        blob_upload_limit: 5 * 1024 * 1024,
        privacy_policy_url: None,
        terms_of_service_url: None,
        contact_email: None,
    }
}

/// Sends one request through the router and reads the answer back.
async fn call(router: &Router, method: &str, path: &str) -> (StatusCode, String) {
    let request = Request::builder()
        .method(method)
        .uri(path)
        .body(Body::empty())
        .expect("a request");

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
    let (status, body) = call(&router, "GET", "/xrpc/com.atproto.sync.getBlob").await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    assert!(body.contains("MethodNotImplemented"), "{body}");
}

#[tokio::test]
async fn a_path_that_is_not_a_lexicon_is_refused_before_that() {
    let router = server::router(config());
    let (status, body) = call(&router, "GET", "/xrpc/not-an-nsid").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("invalid xrpc path"), "{body}");
}

#[tokio::test]
async fn a_query_asked_for_as_a_procedure_names_the_verb_it_wanted() {
    let router = server::router(config());
    let (status, body) = call(&router, "POST", "/xrpc/com.atproto.server.describeServer").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("expected GET"), "{body}");
}

#[tokio::test]
async fn a_path_outside_xrpc_is_left_alone() {
    let router = server::router(config());
    let (status, _) = call(&router, "GET", "/nothing/here").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, body) = call(&router, "GET", "/robots.txt").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("User-agent: *"), "{body}");
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
