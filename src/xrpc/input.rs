//! A method's body, read the way XRPC says a body that will not read is
//! refused.

use axum::{
    Json,
    extract::{FromRequest, Request, rejection::JsonRejection},
};
use serde::de::DeserializeOwned;

use super::{Error, Status};

/// What a procedure was sent.
///
/// Axum's own rejection answers in plain text, which a client that only reads
/// the XRPC error shape cannot tell from anything else going wrong.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Input<T>(pub T);

impl<T: DeserializeOwned, S: Send + Sync> FromRequest<S> for Input<T> {
    type Rejection = Error;

    async fn from_request(request: Request, state: &S) -> Result<Self, Error> {
        match Json::<T>::from_request(request, state).await {
            Ok(Json(value)) => Ok(Self(value)),
            Err(JsonRejection::MissingJsonContentType(_)) => {
                Err(Error::new(Status::UnsupportedMediaType).saying("Expected application/json"))
            }
            Err(rejection) => Err(Error::invalid_request(rejection.body_text())),
        }
    }
}
