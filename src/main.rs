use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr};
use std::process::ExitCode;

use axum::ServiceExt;
use clap::{Parser, Subcommand};
use manapds::{
    config::{Config, Secret},
    crypto::{self, Algorithm, Keypair},
    server,
};
use tokio::{net::TcpListener, signal};
use tracing_subscriber::{EnvFilter, fmt};

/// An atproto personal data server.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Serve, reading the configuration from the environment.
    Serve,
    /// Write a secret fit for `PDS_JWT_SECRET`.
    Secret,
    /// Write a key fit for `PDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX`.
    ///
    /// Every account this server creates is anchored to it, and no copy of it
    /// is kept anywhere else.
    RotationKey,
}

fn main() -> ExitCode {
    let outcome = match Cli::parse().command {
        Command::Serve => serve(),
        Command::Secret => {
            println!("{}", Secret::generate().reveal());
            Ok(())
        }
        Command::RotationKey => {
            println!(
                "{}",
                crypto::hex(&Keypair::generate(Algorithm::Secp256k1).to_bytes())
            );
            Ok(())
        }
    };

    // Returning the error instead would print it through `Debug`, which turns
    // the sentence naming the fix back into the struct behind it.
    if let Err(error) = outcome {
        eprintln!("manapds: {error}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

#[tokio::main]
async fn serve() -> Result<(), Box<dyn Error>> {
    fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let config = Config::from_env()?;
    let address = SocketAddr::from((Ipv4Addr::UNSPECIFIED, config.port));
    let hostname = config.hostname.clone();
    let context = server::Context::open(config)?;
    let listener = TcpListener::bind(address).await?;

    tracing::info!(%address, %hostname, "listening");
    // The connecting address is carried into the request so that rate limits
    // have someone to count against.
    let service = ServiceExt::<axum::extract::Request>::into_make_service_with_connect_info::<
        SocketAddr,
    >(server::router(context));
    axum::serve(listener, service)
        .with_graceful_shutdown(async {
            let _ = signal::ctrl_c().await;
        })
        .await?;

    Ok(())
}
