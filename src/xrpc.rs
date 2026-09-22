//! The request surface: the error shape every method answers with, the routing
//! helpers that hold a method to its verb, the credentials a request carries,
//! and the budgets it spends.

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

pub mod auth;
mod input;
pub mod limit;
mod route;

pub use input::Input;
pub use route::{fallback, procedure, query};

/// The result an XRPC method hands back.
pub type Result<T> = std::result::Result<T, Error>;

/// The statuses XRPC gives names to.
///
/// Clients branch on the name rather than the number, and the names are not
/// HTTP's — 404 is `XRPCNotSupported`, and a method that exists but is not
/// served answers 501 instead.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    /// The request was understood and refused. 400.
    InvalidRequest,
    /// No usable credentials. 401.
    AuthenticationRequired,
    /// Credentials that do not reach this. 403.
    Forbidden,
    /// Not an XRPC path at all. 404.
    XrpcNotSupported,
    /// Nothing can be produced in a format the client will take. 406.
    NotAcceptable,
    /// A body larger than the method accepts. 413.
    PayloadTooLarge,
    /// A body in a format the method does not read. 415.
    UnsupportedMediaType,
    /// A budget the caller has spent. 429.
    RateLimitExceeded,
    /// A fault on this side, which is never described to the client. 500.
    InternalServerError,
    /// A method this server does not serve. 501.
    MethodNotImplemented,
    /// A server this one depends on failed. 502.
    UpstreamFailure,
    /// This server is out of something it needs. 503.
    NotEnoughResources,
    /// A server this one depends on did not answer. 504.
    UpstreamTimeout,
}

impl Status {
    /// The HTTP status carrying it.
    #[must_use]
    pub fn code(self) -> StatusCode {
        match self {
            Self::InvalidRequest => StatusCode::BAD_REQUEST,
            Self::AuthenticationRequired => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::XrpcNotSupported => StatusCode::NOT_FOUND,
            Self::NotAcceptable => StatusCode::NOT_ACCEPTABLE,
            Self::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::UnsupportedMediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Self::RateLimitExceeded => StatusCode::TOO_MANY_REQUESTS,
            Self::InternalServerError => StatusCode::INTERNAL_SERVER_ERROR,
            Self::MethodNotImplemented => StatusCode::NOT_IMPLEMENTED,
            Self::UpstreamFailure => StatusCode::BAD_GATEWAY,
            Self::NotEnoughResources => StatusCode::SERVICE_UNAVAILABLE,
            Self::UpstreamTimeout => StatusCode::GATEWAY_TIMEOUT,
        }
    }

    /// What goes in `error` when a lexicon names nothing more specific.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::InvalidRequest => "InvalidRequest",
            Self::AuthenticationRequired => "AuthenticationRequired",
            Self::Forbidden => "Forbidden",
            Self::XrpcNotSupported => "XRPCNotSupported",
            Self::NotAcceptable => "NotAcceptable",
            Self::PayloadTooLarge => "PayloadTooLarge",
            Self::UnsupportedMediaType => "UnsupportedMediaType",
            Self::RateLimitExceeded => "RateLimitExceeded",
            Self::InternalServerError => "InternalServerError",
            Self::MethodNotImplemented => "MethodNotImplemented",
            Self::UpstreamFailure => "UpstreamFailure",
            Self::NotEnoughResources => "NotEnoughResources",
            Self::UpstreamTimeout => "UpstreamTimeout",
        }
    }

    /// What goes in `message` when nothing else says more.
    #[must_use]
    pub fn description(self) -> &'static str {
        match self {
            Self::InvalidRequest => "Invalid Request",
            Self::AuthenticationRequired => "Authentication Required",
            Self::Forbidden => "Forbidden",
            Self::XrpcNotSupported => "XRPC Not Supported",
            Self::NotAcceptable => "Not Acceptable",
            Self::PayloadTooLarge => "Payload Too Large",
            Self::UnsupportedMediaType => "Unsupported Media Type",
            Self::RateLimitExceeded => "Rate Limit Exceeded",
            Self::InternalServerError => "Internal Server Error",
            Self::MethodNotImplemented => "Method Not Implemented",
            Self::UpstreamFailure => "Upstream Failure",
            Self::NotEnoughResources => "Not Enough Resources",
            Self::UpstreamTimeout => "Upstream Timeout",
        }
    }
}

/// A failed method call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Error {
    status: Status,
    name: Option<String>,
    message: Option<String>,
}

impl Error {
    /// An error carrying nothing but its status.
    #[must_use]
    pub fn new(status: Status) -> Self {
        Self {
            status,
            name: None,
            message: None,
        }
    }

    /// The request was understood and refused.
    #[must_use]
    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self::new(Status::InvalidRequest).saying(message)
    }

    /// No usable credentials were offered.
    #[must_use]
    pub fn auth_required(message: impl Into<String>) -> Self {
        Self::new(Status::AuthenticationRequired).saying(message)
    }

    /// A fault on this side. The message is logged rather than answered with,
    /// so it can say what actually happened.
    #[must_use]
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(Status::InternalServerError).saying(message)
    }

    /// The name a lexicon gives this failure, which is what a client branches
    /// on.
    #[must_use]
    pub fn named(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// What to tell the caller, where the status alone does not.
    #[must_use]
    pub fn saying(mut self, message: impl Into<String>) -> Self {
        self.message = Some(message.into());
        self
    }

    /// Which failure this is.
    #[must_use]
    pub fn status(&self) -> Status {
        self.status
    }

    /// What the client sees in `error`.
    #[must_use]
    pub fn name(&self) -> &str {
        self.name.as_deref().unwrap_or_else(|| self.status.name())
    }

    /// What the client sees in `message`, which for a fault on this side is
    /// the status and never the cause.
    #[must_use]
    pub fn message(&self) -> &str {
        if self.status == Status::InternalServerError {
            return self.status.description();
        }
        self.message
            .as_deref()
            .unwrap_or_else(|| self.status.description())
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = self.message.as_deref().unwrap_or(self.status.description());
        write!(formatter, "{}: {message}", self.name())
    }
}

impl std::error::Error for Error {}

/// What the body of a failed call is, and all it ever is.
#[derive(Debug, Serialize)]
struct Payload<'a> {
    error: &'a str,
    message: &'a str,
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        if self.status == Status::InternalServerError {
            tracing::error!(error = %self, "internal server error");
        }
        let payload = Payload {
            error: self.name(),
            message: self.message(),
        };
        (self.status.code(), Json(payload)).into_response()
    }
}
