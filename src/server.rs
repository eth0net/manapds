//! Routing, what every handler is handed, and the methods small enough to
//! sit beside it.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{FromRef, State},
    middleware,
    routing::get,
};
use serde::Serialize;
use tower_http::{
    cors::{Any, CorsLayer},
    normalize_path::NormalizePath,
    trace::TraceLayer,
};

mod session;

use crate::account;
use crate::config::Config;
use crate::store;
use crate::xrpc::{self, auth::Tokens, limit::Limits};

/// Everything a handler can ask the router for.
#[derive(Clone, Debug)]
pub struct Context {
    /// How this server was started.
    pub config: Arc<Config>,
    /// The accounts on it, and the sessions open against them.
    pub accounts: Arc<account::Manager>,
    /// The secret every session token is signed under.
    pub tokens: Tokens,
}

impl Context {
    /// Opens the databases under the configured data directory.
    ///
    /// # Errors
    ///
    /// If the directory cannot be made, or a database cannot be opened or has
    /// been migrated past what this server reads.
    pub fn open(config: Config) -> Result<Self, store::Error> {
        let config = Arc::new(config);
        let directory = store::Directory::new(config.data_directory.clone());
        let accounts = store::Accounts::open(&directory.accounts())?;
        let tokens = Tokens::new(config.jwt_secret.reveal(), config.service_did.clone());
        Ok(Self::new(
            Arc::clone(&config),
            Arc::new(account::Manager::new(config, accounts, tokens.clone())),
            tokens,
        ))
    }

    /// The same, around an account layer somebody else opened, which is what a
    /// test wants.
    #[must_use]
    pub fn new(config: Arc<Config>, accounts: Arc<account::Manager>, tokens: Tokens) -> Self {
        Self {
            config,
            accounts,
            tokens,
        }
    }
}

impl FromRef<Context> for Tokens {
    fn from_ref(context: &Context) -> Self {
        context.tokens.clone()
    }
}

impl FromRef<Context> for Arc<Config> {
    fn from_ref(context: &Context) -> Self {
        Arc::clone(&context.config)
    }
}

impl FromRef<Context> for Arc<account::Manager> {
    fn from_ref(context: &Context) -> Self {
        Arc::clone(&context.accounts)
    }
}

impl From<account::Error> for xrpc::Error {
    fn from(error: account::Error) -> Self {
        use account::Error;
        let status = match error {
            Error::Credentials => xrpc::Status::AuthenticationRequired,
            Error::Plc(_) | Error::Repo(_) | Error::Storage(_) => {
                return Self::internal(error.to_string());
            }
            _ => xrpc::Status::InvalidRequest,
        };
        Self::new(status)
            .named(error.name())
            .saying(error.to_string())
    }
}

/// Builds the whole request surface. Takes what it needs rather than opening
/// it, so a test can drive the server without touching the environment or the
/// disk.
///
/// A trailing slash is trimmed before anything routes, because upstream serves
/// `/xrpc/<nsid>/` and a client that sends one should not be told the method
/// does not exist.
#[must_use]
pub fn router(context: Context) -> NormalizePath<Router> {
    NormalizePath::trim_trailing_slash(routes(context))
}

fn routes(context: Context) -> Router {
    let limits = Limits::new(&context.config).map(Arc::new);
    let router = Router::new()
        .route("/", get(root))
        .route("/robots.txt", get(robots))
        .route("/xrpc/_health", get(health))
        .route(
            "/xrpc/com.atproto.server.describeServer",
            xrpc::query(describe_server),
        )
        .route(
            "/xrpc/com.atproto.server.createSession",
            xrpc::procedure(session::create),
        )
        .route(
            "/xrpc/com.atproto.server.getSession",
            xrpc::query(session::get),
        )
        .route(
            "/xrpc/com.atproto.server.refreshSession",
            xrpc::procedure(session::refresh),
        )
        .route(
            "/xrpc/com.atproto.server.deleteSession",
            xrpc::procedure(session::delete),
        )
        .fallback(xrpc::fallback)
        .with_state(context)
        .layer(middleware::from_fn(xrpc::auth::private));

    // CORS goes outside the budget so that a browser is told why it was
    // refused rather than being told nothing at all.
    match limits {
        Some(limits) => router.layer(middleware::from_fn_with_state(limits, xrpc::limit::global)),
        None => router,
    }
    .layer(cors())
    .layer(TraceLayer::new_for_http())
}

/// Anything may call this server, since every method either needs credentials
/// or is public to begin with.
fn cors() -> CorsLayer {
    CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any)
        .expose_headers(Any)
        .max_age(std::time::Duration::from_hours(24))
}

async fn root() -> &'static str {
    "This is an AT Protocol Personal Data Server.\n\nMost of it is under /xrpc/.\n"
}

async fn robots() -> &'static str {
    "# Crawling the public API is allowed\nUser-agent: *\nAllow: /\n"
}

#[derive(Debug, Serialize)]
struct Health {
    version: &'static str,
}

async fn health() -> Json<Health> {
    Json(Health {
        version: env!("CARGO_PKG_VERSION"),
    })
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DescribeServer {
    did: String,
    available_user_domains: Vec<String>,
    invite_code_required: bool,
    blob_upload_limit: u64,
    links: Links,
    contact: Contact,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Links {
    #[serde(skip_serializing_if = "Option::is_none")]
    privacy_policy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    terms_of_service: Option<String>,
}

#[derive(Debug, Serialize)]
struct Contact {
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
}

async fn describe_server(State(config): State<Arc<Config>>) -> Json<DescribeServer> {
    Json(DescribeServer {
        did: config.service_did.clone(),
        available_user_domains: config.handle_domains.clone(),
        invite_code_required: config.invite_required,
        blob_upload_limit: config.blob_upload_limit,
        links: Links {
            privacy_policy: config.privacy_policy_url.clone(),
            terms_of_service: config.terms_of_service_url.clone(),
        },
        contact: Contact {
            email: config.contact_email.clone(),
        },
    })
}
