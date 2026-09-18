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

/// Writes a signing key that nobody else could read even for an instant, and
/// refuses to write over one already there. See `docs/porting.md` for why the
/// strictness is worth a permissions error.
///
/// # Errors
///
/// If the directory cannot be made, a key is already at that path, or the
/// write fails.
pub fn write(path: &Path, keypair: &Keypair) -> Result<(), Error> {
    use std::io::Write;

    if let Some(parent) = path.parent() {
        super::directory(parent)?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(&keypair.to_bytes())?;
    Ok(())
}
