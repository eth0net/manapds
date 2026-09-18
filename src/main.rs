use std::net::{Ipv4Addr, SocketAddr};

use axum::ServiceExt;
use manapds::{config::Config, server};
use tokio::{net::TcpListener, signal};
use tracing_subscriber::{EnvFilter, fmt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let config = Config::from_env()?;
    let address = SocketAddr::from((Ipv4Addr::UNSPECIFIED, config.port));
    let listener = TcpListener::bind(address).await?;
    let hostname = config.hostname.clone();

    tracing::info!(%address, %hostname, "listening");
    // The connecting address is carried into the request so that rate limits
    // have someone to count against.
    let service = ServiceExt::<axum::extract::Request>::into_make_service_with_connect_info::<
        SocketAddr,
    >(server::router(config));
    axum::serve(listener, service)
        .with_graceful_shutdown(async {
            let _ = signal::ctrl_c().await;
        })
        .await?;

    Ok(())
}
