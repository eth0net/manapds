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
    same(with_salt(password, salt).as_bytes(), stored.as_bytes())
}

fn with_salt(password: &str, salt: &str) -> String {
    let params = scrypt::Params::new(LOG_N, BLOCK, PARALLEL).expect("parameters scrypt allows");
    let mut derived = [0u8; LENGTH];
    scrypt::scrypt(password.as_bytes(), salt.as_bytes(), &params, &mut derived)
        .expect("a length scrypt writes");
    format!("{salt}:{}", hex(&derived))
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    #[derive(Debug, Deserialize)]
    struct Fixture {
        account: Vector,
        app: Vector,
    }

    /// One password, and what the reference wrote for it.
    #[derive(Debug, Deserialize)]
    struct Vector {
        #[serde(default)]
        did: String,
        #[serde(default)]
        salt: String,
        password: String,
        stored: String,
    }

    fn fixture() -> Fixture {
        serde_json::from_str(include_str!("../../fixtures/password/scrypt.json"))
            .expect("the fixture")
    }

    #[test]
    fn a_password_hashes_to_what_the_reference_stores() {
        let fixture = fixture();

        assert!(fixture.account.stored.starts_with(&fixture.account.salt));
        assert!(verify(&fixture.account.password, &fixture.account.stored));
        assert!(!verify("something else", &fixture.account.stored));
    }

    #[test]
    fn an_app_password_is_salted_with_the_account_it_belongs_to() {
        let fixture = fixture();
        let did = fixture.app.did.parse().expect("a DID");

        assert_eq!(app(&did, &fixture.app.password), fixture.app.stored);
        // Two accounts choosing the same one store different hashes, which is what
        // the salt is for even though nothing random goes into it.
        let other = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa".parse().expect("a DID");
        assert_ne!(app(&other, &fixture.app.password), fixture.app.stored);
    }

    #[test]
    fn a_fresh_hash_is_salted_and_reads_back() {
        let stored = hash("correct horse battery staple");

        assert!(verify("correct horse battery staple", &stored));
        assert!(!verify("correct horse battery stapl", &stored));
        assert_ne!(stored, hash("correct horse battery staple"));
        // Nothing that is not a salt and a hash is a stored password.
        assert!(!verify("anything", "no colon here"));
    }

    #[test]
    fn the_password_nobody_has_is_nobody_s() {
        for password in [
            "",
            "correct horse battery staple",
            "\u{1f600}",
            "0".repeat(512).as_str(),
        ] {
            assert!(!nobody(password), "{password:?}");
        }
    }
}
