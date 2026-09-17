//! Routing: holding a method to the verb its lexicon declares, and naming
//! what this server does not serve.

use axum::{
    handler::Handler,
    http::{Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::{MethodRouter, get, post},
};

use crate::syntax::Nsid;

use super::{Error, Status};

/// Serves a lexicon query, and refuses the same path under any other verb.
pub fn query<H, T, S>(handler: H) -> MethodRouter<S>
where
    H: Handler<T, S>,
    T: 'static,
    S: Clone + Send + Sync + 'static,
{
    get(handler).fallback(|method: Method| async move { mismatch(&method, "GET") })
}

/// Serves a lexicon procedure, and refuses the same path under any other verb.
pub fn procedure<H, T, S>(handler: H) -> MethodRouter<S>
where
    H: Handler<T, S>,
    T: 'static,
    S: Clone + Send + Sync + 'static,
{
    post(handler).fallback(|method: Method| async move { mismatch(&method, "POST") })
}

/// Answers a path no route claimed, which under `/xrpc/` is a lexicon this
/// server does not serve. See `docs/architecture.md` for why that is not a 404.
pub async fn fallback(uri: Uri) -> Response {
    let Some(path) = uri.path().strip_prefix("/xrpc/") else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if path.trim_end_matches('/').parse::<Nsid>().is_err() {
        return Error::invalid_request("invalid xrpc path").into_response();
    }
    Error::new(Status::MethodNotImplemented).into_response()
}

fn mismatch(method: &Method, expected: &str) -> Error {
    Error::invalid_request(format!(
        "Incorrect HTTP method ({method}) expected {expected}"
    ))
}
