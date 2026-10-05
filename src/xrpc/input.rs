//! A method's body and its query, refused in the XRPC error shape when they
//! will not parse.

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
/// Axum's own rejection is plain text, so this answers it in the shape
/// [`Input`] uses.
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

/// A query as the pairs it arrived as.
///
/// A lexicon array is sent as its name repeated, and [`Params`] reads a field
/// at one value, so a method taking one asks for this beside it.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Listed(Vec<(String, String)>);

impl Listed {
    /// Every value sent under a name, in the order they arrived.
    #[must_use]
    pub fn all(&self, name: &str) -> Vec<&str> {
        self.0
            .iter()
            .filter(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
            .collect()
    }
}

impl<S: Send + Sync> FromRequestParts<S> for Listed {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Error> {
        Query::<Vec<(String, String)>>::from_request_parts(parts, state)
            .await
            .map(|Query(pairs)| Self(pairs))
            .map_err(|rejection| Error::invalid_request(rejection.body_text()))
    }
}
