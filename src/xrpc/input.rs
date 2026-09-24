//! What a method was sent, read the way XRPC says something that will not read
//! is refused.

use axum::extract::{FromRequest, FromRequestParts, Query, Request, rejection::JsonRejection};
use axum::{Json, http::StatusCode, http::request::Parts};
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
            // Asked of the rejection rather than matched, since which variant
            // carries a body that ran long is axum's to change.
            Err(rejection) if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE => {
                Err(Error::new(Status::PayloadTooLarge).saying(rejection.body_text()))
            }
            Err(rejection) => Err(Error::invalid_request(rejection.body_text())),
        }
    }
}

/// What a query was asked with.
///
/// Axum refuses a missing parameter the way it refuses a body, so this answers
/// it the way [`Input`] does.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Params<T>(pub T);

impl<T: DeserializeOwned, S: Send + Sync> FromRequestParts<S> for Params<T> {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Error> {
        Query::<T>::from_request_parts(parts, state)
            .await
            .map(|Query(value)| Self(value))
            .map_err(|rejection| Error::invalid_request(rejection.body_text()))
    }
}
