//! Server configuration, read from the environment.

use std::{env, net::IpAddr, num::ParseIntError, path::PathBuf};

use thiserror::Error;

/// The shortest secret this server will start under.
///
/// 128 bits written as base64 is 24 characters and as hex is 32, so the floor
/// is the shorter spelling. Length is all that can be checked: a long phrase
/// someone thought of still falls to a word list.
const SECRET_LENGTH: usize = 24;

/// A configured value that has no business reaching a log.
#[derive(Clone, Eq, PartialEq)]
pub struct Secret(String);

impl Secret {
    /// Holds a value, so that printing the thing around it cannot spill it.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The value itself, at the one point that has to have it.
    #[must_use]
    pub fn reveal(&self) -> &str {
        &self.0
    }

    /// A fresh one, at the length the reference installer writes.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0u8; 16];
        rand::fill(&mut bytes);
        Self(crate::crypto::hex(&bytes))
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("<secret>")
    }
}

/// Everything the server needs to start.
#[derive(Debug, Clone)]
pub struct Config {
    /// The public hostname. Identifies the server to clients and to the
    /// network, and is the default for much of the rest of this struct.
    pub hostname: String,
    pub port: u16,
    pub service_did: String,
    pub data_directory: PathBuf,
    /// What every session token is signed under. Losing it signs every client
    /// out; changing it on a running server does the same.
    pub jwt_secret: Secret,
    /// Suffixes an account may take a handle under, each with its leading dot.
    pub handle_domains: Vec<String>,
    pub invite_required: bool,
    pub blob_upload_limit: u64,
    pub privacy_policy_url: Option<String>,
    pub terms_of_service_url: Option<String>,
    pub contact_email: Option<String>,
    /// Whether to hold callers to a budget at all, which the reference leaves
    /// off.
    pub rate_limits: bool,
    /// A key a caller sends to be let past those budgets.
    pub rate_limit_bypass_key: Option<Secret>,
    /// Addresses let past them without a key.
    pub rate_limit_bypass_ips: Vec<IpAddr>,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("{0} is not a number: {1}")]
    NotANumber(&'static str, #[source] ParseIntError),
    #[error("{0} is not true or false")]
    NotABoolean(&'static str),
    #[error("{0} has to be set")]
    Missing(&'static str),
    #[error("{0} has to be at least {1} characters, and random: `manapds secret` writes one")]
    TooShort(&'static str, usize),
}

impl Config {
    /// Reads the environment, filling in defaults for a local server.
    ///
    /// Unknown `PDS_*` variables are ignored rather than rejected, so a
    /// configuration file written for the reference server starts this one.
    ///
    /// # Errors
    ///
    /// If a variable that has to be a number or a boolean isn't one, or
    /// `PDS_JWT_SECRET` is unset.
    pub fn from_env() -> Result<Self, ConfigError> {
        let hostname = string("PDS_HOSTNAME").unwrap_or_else(|| "localhost".to_owned());

        Ok(Self {
            service_did: string("PDS_SERVICE_DID").unwrap_or_else(|| format!("did:web:{hostname}")),
            handle_domains: list("PDS_SERVICE_HANDLE_DOMAINS")
                .unwrap_or_else(|| vec![format!(".{hostname}")]),
            port: number("PDS_PORT")?.unwrap_or(2583),
            data_directory: string("PDS_DATA_DIRECTORY")
                .map_or_else(|| PathBuf::from("data"), PathBuf::from),
            jwt_secret: secret("PDS_JWT_SECRET")?,
            invite_required: boolean("PDS_INVITE_REQUIRED")?.unwrap_or(true),
            blob_upload_limit: number("PDS_BLOB_UPLOAD_LIMIT")?.unwrap_or(5 * 1024 * 1024),
            privacy_policy_url: string("PDS_PRIVACY_POLICY_URL"),
            terms_of_service_url: string("PDS_TERMS_OF_SERVICE_URL"),
            contact_email: string("PDS_CONTACT_EMAIL_ADDRESS"),
            rate_limits: boolean("PDS_RATE_LIMITS_ENABLED")?.unwrap_or(false),
            rate_limit_bypass_key: string("PDS_RATE_LIMIT_BYPASS_KEY").map(Secret::new),
            // The reference takes CIDR here and keeps only the address, so a
            // range written out is read as the one address it starts at.
            rate_limit_bypass_ips: list("PDS_RATE_LIMIT_BYPASS_IPS")
                .unwrap_or_default()
                .iter()
                .filter_map(|value| value.split('/').next()?.trim().parse().ok())
                .collect(),
            hostname,
        })
    }
}

/// An empty variable counts as unset, since that is how a `.env` file with a
/// key and no value reads.
fn string(key: &str) -> Option<String> {
    env::var(key).ok().filter(|value| !value.is_empty())
}

/// A secret short enough to be found by trying is refused at startup, since
/// every session on the server is signed under this one and a holder of any
/// token can look for it offline.
fn secret(key: &'static str) -> Result<Secret, ConfigError> {
    let value = string(key).ok_or(ConfigError::Missing(key))?;
    if value.chars().count() < SECRET_LENGTH {
        return Err(ConfigError::TooShort(key, SECRET_LENGTH));
    }
    Ok(Secret::new(value))
}

fn list(key: &str) -> Option<Vec<String>> {
    string(key).map(|value| {
        value
            .split(',')
            .map(|part| part.trim().to_owned())
            .collect()
    })
}

/// Upstream reads an unrecognized value as unset and falls back to the
/// default. Here it is an error: a misspelled flag that quietly means the
/// opposite of what was written is worse than a server that will not start.
fn boolean(key: &'static str) -> Result<Option<bool>, ConfigError> {
    match string(key).as_deref() {
        None => Ok(None),
        Some("true" | "1") => Ok(Some(true)),
        Some("false" | "0") => Ok(Some(false)),
        Some(_) => Err(ConfigError::NotABoolean(key)),
    }
}

fn number<T: std::str::FromStr<Err = ParseIntError>>(
    key: &'static str,
) -> Result<Option<T>, ConfigError> {
    string(key)
        .map(|value| {
            value
                .parse()
                .map_err(|error| ConfigError::NotANumber(key, error))
        })
        .transpose()
}
