//! The XRPC error shape.

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

/// An XRPC failure. The `error` name is what a client branches on, so it is a
/// string from the lexicon rather than anything derived from the message.
#[derive(Debug, Serialize)]
pub struct Error {
    #[serde(skip)]
    pub status: StatusCode,
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        (self.status, Json(&self)).into_response()
    }
}
