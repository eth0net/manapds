//! Blobs: the images and files records point at, kept as files rather than
//! rows because a blob is immutable and already addressed by its contents.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use ipld_core::cid::{Cid, multihash::Multihash};
use sha2::{Digest, Sha256};

use crate::syntax::Did;

use super::Error;

/// raw, in the multicodec table. A blob is bytes and nothing else, so it is
/// addressed under that codec rather than dag-cbor's.
const RAW: u64 = 0x55;

/// sha2-256, in the multihash table.
const SHA2_256: u64 = 0x12;

/// The CID a blob is stored under.
#[must_use]
#[expect(clippy::missing_panics_doc, reason = "a sha-256 digest is 32 bytes")]
pub fn cid_for(bytes: &[u8]) -> Cid {
    let hash = Multihash::wrap(SHA2_256, &Sha256::digest(bytes)).expect("a 32-byte digest fits");
    Cid::new_v1(RAW, hash)
}

/// Where blobs live, under the directory the reference calls `blocks`.
#[derive(Clone, Debug)]
pub struct Blobs(PathBuf);

impl Blobs {
    /// Names a directory without touching it.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self(root.into())
    }

    /// Where a stored blob is.
    #[must_use]
    pub fn path(&self, did: &Did, cid: &Cid) -> PathBuf {
        self.stored(did).join(cid.to_string())
    }

    /// Where an account's blobs are served from.
    fn stored(&self, did: &Did) -> PathBuf {
        self.0.join(did.as_str())
    }

    /// Where its uploads wait. Spelled as upstream spells it, which is a typo
    /// that has outlived every chance to fix it.
    fn uploads(&self, did: &Did) -> PathBuf {
        self.0.join("tempt").join(did.as_str())
    }

    /// Where a blob sits while it is being taken down. A file here is not
    /// served and not deleted.
    #[must_use]
    pub fn quarantine_path(&self, did: &Did, cid: &Cid) -> PathBuf {
        self.0
            .join("quarantine")
            .join(did.as_str())
            .join(cid.to_string())
    }

    /// Where a blob sits before its CID is known.
    #[must_use]
    pub fn temp_path(&self, did: &Did, key: &str) -> PathBuf {
        self.uploads(did).join(key)
    }

    /// Takes the uploads under an account that no key in `held` names and
    /// that nothing has written since `cutoff`, and says which went.
    ///
    /// # Errors
    ///
    /// If the directory cannot be read, or a file will not delete.
    pub fn sweep_uploads(
        &self,
        did: &Did,
        held: &HashSet<String>,
        cutoff: jiff::Timestamp,
    ) -> Result<Vec<String>, Error> {
        sweep(&self.uploads(did), held, cutoff)
    }

    /// Stores a blob nothing has claimed yet, under a key of its own rather
    /// than under its CID; `docs/architecture.md` has why.
    ///
    /// # Errors
    ///
    /// If the CID is not the one over these bytes, or the write fails.
    pub fn put(&self, did: &Did, key: &str, cid: &Cid, bytes: &[u8]) -> Result<(), Error> {
        if cid_for(bytes) != *cid {
            return Err(Error::WrongCid(*cid));
        }
        write(&self.temp_path(did, key), bytes)
    }

    /// Puts a blob where it is served from, leaving what it was uploaded as.
    ///
    /// Answers whether this call is what put it there, which says whose it is
    /// to take back: doing it twice is doing it once, and the second caller
    /// must not undo the first.
    ///
    /// # Errors
    ///
    /// If the upload is not there, or will not link.
    pub fn claim(&self, did: &Did, key: &str, cid: &Cid) -> Result<bool, Error> {
        let path = self.path(did, cid);
        if let Some(parent) = path.parent() {
            super::directory(parent)?;
        }
        match std::fs::hard_link(self.temp_path(did, key), &path) {
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
            result => {
                result?;
                Ok(true)
            }
        }
    }

    /// Drops what a blob was uploaded as, once it is served from its own name.
    ///
    /// # Errors
    ///
    /// If it is there and will not delete.
    pub fn delete_upload(&self, did: &Did, key: &str) -> Result<(), Error> {
        match std::fs::remove_file(self.temp_path(did, key)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            result => Ok(result?),
        }
    }

    /// Reads a blob back.
    ///
    /// # Errors
    ///
    /// If it is not there, or cannot be read.
    pub fn get(&self, did: &Did, cid: &Cid) -> Result<Vec<u8>, Error> {
        Ok(std::fs::read(self.path(did, cid))?)
    }

    /// Whether a blob is stored and servable.
    #[must_use]
    pub fn has(&self, did: &Did, cid: &Cid) -> bool {
        self.path(did, cid).is_file()
    }

    /// Moves a blob out of reach without losing it.
    ///
    /// # Errors
    ///
    /// If it is not there, or cannot be moved.
    pub fn quarantine(&self, did: &Did, cid: &Cid) -> Result<(), Error> {
        rename(&self.path(did, cid), &self.quarantine_path(did, cid))
    }

    /// Puts a quarantined blob back.
    ///
    /// # Errors
    ///
    /// If it is not in quarantine, or cannot be moved.
    pub fn unquarantine(&self, did: &Did, cid: &Cid) -> Result<(), Error> {
        rename(&self.quarantine_path(did, cid), &self.path(did, cid))
    }

    /// Deletes a blob, and says nothing if it was already gone.
    ///
    /// # Errors
    ///
    /// If it is there and will not delete.
    pub fn delete(&self, did: &Did, cid: &Cid) -> Result<(), Error> {
        match std::fs::remove_file(self.path(did, cid)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            result => Ok(result?),
        }
    }
}

/// Written beside its place and moved onto it, so a blob interrupted halfway
/// is not one `has` will offer to serve.
fn write(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    if let Some(parent) = path.parent() {
        super::directory(parent)?;
    }
    let mut scratch = [0u8; 8];
    rand::fill(&mut scratch);
    let mut partial = path.as_os_str().to_owned();
    partial.push(format!(".{}", crate::crypto::base32(&scratch)));
    let partial = PathBuf::from(partial);

    std::fs::write(&partial, bytes)
        .and_then(|()| std::fs::rename(&partial, path))
        .inspect_err(|_| {
            drop(std::fs::remove_file(&partial));
        })?;
    Ok(())
}

fn rename(from: &Path, to: &Path) -> Result<(), Error> {
    if let Some(parent) = to.parent() {
        super::directory(parent)?;
    }
    Ok(std::fs::rename(from, to)?)
}

/// Takes the files under a directory that nothing in `held` names and that
/// were last written before `cutoff`.
///
/// Age is what keeps an upload in flight: its row is written after its file,
/// so a name nothing holds yet is one nothing holds yet.
fn sweep(
    directory: &Path,
    held: &HashSet<String>,
    cutoff: jiff::Timestamp,
) -> Result<Vec<String>, Error> {
    let entries = match std::fs::read_dir(directory) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        entries => entries?,
    };
    let cutoff = std::time::SystemTime::from(cutoff);
    let mut swept = Vec::new();
    for entry in entries {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(ToOwned::to_owned) else {
            continue;
        };
        if held.contains(&name) {
            continue;
        }
        let about = entry.metadata()?;
        if !about.is_file() || about.modified()? >= cutoff {
            continue;
        }
        match std::fs::remove_file(entry.path()) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            result => result?,
        }
        swept.push(name);
    }
    Ok(swept)
}
