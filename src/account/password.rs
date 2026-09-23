//! Passwords: how one is stored, and how one is checked against what is
//! stored.
//!
//! scrypt at the parameters node picks when it is given none, written as the
//! salt and the derived bytes with a colon between them. The account database
//! is the reference's, so a password set on either server has to satisfy the
//! other.

use sha2::{Digest, Sha256};

use crate::crypto::{hex, same};
use crate::syntax::Did;

/// N is 2^14, the block size is 8, and nothing is parallelized.
const LOG_N: u8 = 14;
const BLOCK: u32 = 8;
const PARALLEL: u32 = 1;

/// How many bytes come out, which is twice what anything needs and is what the
/// stored hashes already are.
const LENGTH: usize = 64;

/// How many bytes of salt, written as twice as many characters.
const SALT: usize = 16;

/// Hashes a password under a salt nothing else will use.
#[must_use]
pub fn hash(password: &str) -> String {
    let mut salt = [0u8; SALT];
    rand::fill(&mut salt);
    with_salt(password, &hex(&salt))
}

/// Hashes an app password, whose salt is the account it belongs to.
///
/// One is checked by looking its hash up rather than by being named first, so
/// the salt has to be the same every time it is hashed.
#[must_use]
pub fn app(did: &Did, password: &str) -> String {
    let digest = Sha256::digest(did.as_str().as_bytes());
    with_salt(password, &hex(&digest[..SALT]))
}

/// Hashes a password against a stored value no password reaches.
///
/// An identifier no account holds has nothing to check, so without this it
/// answers without doing the work — and under load the wait alone says which
/// identifiers exist.
#[must_use]
pub fn nobody(password: &str) -> bool {
    /// Shaped like a stored hash so the work is the same, and a derivation of
    /// nothing so the answer is always no.
    const NOTHING: &str = "00000000000000000000000000000000:00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    verify(password, NOTHING)
}

/// Whether a password is the one behind a stored hash.
#[must_use]
pub fn verify(password: &str, stored: &str) -> bool {
    let Some((salt, _)) = stored.split_once(':') else {
        return false;
    };
    same(&with_salt(password, salt), stored)
}

fn with_salt(password: &str, salt: &str) -> String {
    let params = scrypt::Params::new(LOG_N, BLOCK, PARALLEL).expect("parameters scrypt allows");
    let mut derived = [0u8; LENGTH];
    scrypt::scrypt(password.as_bytes(), salt.as_bytes(), &params, &mut derived)
        .expect("a length scrypt writes");
    format!("{salt}:{}", hex(&derived))
}
