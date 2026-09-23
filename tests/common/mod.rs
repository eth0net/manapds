//! What a test binary needs to stand a server up.
//!
//! The shape is shared and the values are not, so a new field in `Config` is
//! written here once rather than in every binary that builds one.

use std::path::Path;

use manapds::config::{Config, Secret};
use manapds::crypto::{Algorithm, Keypair};

/// What every test signs its tokens under, past the floor a real one has to
/// clear.
pub(crate) const SECRET: &str = "a secret long enough to not be guessed";

/// What every test's administrator authenticates with.
pub(crate) const ADMIN: &str = "admin";

/// A server under `hostname`, writing under `data` and registering at `plc`.
///
/// Everything else is what a server told nothing would use, and a test that
/// cares about one of them writes over it.
pub(crate) fn config(hostname: &str, data: impl AsRef<Path>, plc: &str) -> Config {
    Config {
        service_did: format!("did:web:{hostname}"),
        handle_domains: vec![format!(".{hostname}")],
        reserved_handles: Vec::new(),
        hostname: hostname.to_owned(),
        port: 443,
        data_directory: data.as_ref().to_path_buf(),
        jwt_secret: Secret::new(SECRET),
        admin_password: Secret::new(ADMIN),
        plc_rotation_key: Keypair::generate(Algorithm::Secp256k1),
        plc_url: plc.to_owned(),
        recovery_key: None,
        invite_required: false,
        blob_upload_limit: 5 * 1024 * 1024,
        privacy_policy_url: None,
        terms_of_service_url: None,
        contact_email: None,
        rate_limits: false,
        rate_limit_bypass_key: None,
        rate_limit_bypass_ips: Vec::new(),
    }
}
