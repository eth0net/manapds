//! An account's signing key, kept as raw bytes in a file beside its database.
//!
//! Always secp256k1: that is what the reference generates and what the PLC
//! directory expects back.

use std::path::Path;

use crate::crypto::{Algorithm, Keypair};

use super::Error;

/// Reads a signing key.
///
/// # Errors
///
/// If the file is not there, or does not hold a key on the curve.
pub fn read(path: &Path) -> Result<Keypair, Error> {
    Ok(Keypair::from_bytes(
        Algorithm::Secp256k1,
        &std::fs::read(path)?,
    )?)
}

/// Writes a signing key, readable only by the user running the server.
///
/// # Errors
///
/// If the directory cannot be made or the file cannot be written.
pub fn write(path: &Path, keypair: &Keypair) -> Result<(), Error> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, keypair.to_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}
