//! Routing, and the handlers that need no storage yet.

use std::sync::Arc;

use axum::{Json, Router, extract::State, routing::get};
use serde::Serialize;
use tower_http::trace::TraceLayer;

use crate::config::Config;

/// Builds the router. Takes the configuration rather than reading it, so a
/// test can drive the whole surface without touching the environment.
pub fn router(config: Config) -> Router {
    Router::new()
        .route("/xrpc/_health", get(health))
        .route(
            "/xrpc/com.atproto.server.describeServer",
            get(describe_server),
        )
        .layer(TraceLayer::new_for_http())
        .with_state(Arc::new(config))
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
