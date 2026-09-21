//! The account layer, against what the reference stores for the same inputs.

use manapds::account::password;
use serde::Deserialize;

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
    serde_json::from_str(include_str!("fixtures/password/scrypt.json")).expect("the fixture")
}

#[test]
fn a_password_hashes_to_what_the_reference_stores() {
    let fixture = fixture();

    assert!(fixture.account.stored.starts_with(&fixture.account.salt));
    assert!(password::verify(
        &fixture.account.password,
        &fixture.account.stored
    ));
    assert!(!password::verify("something else", &fixture.account.stored));
}

#[test]
fn an_app_password_is_salted_with_the_account_it_belongs_to() {
    let fixture = fixture();
    let did = fixture.app.did.parse().expect("a DID");

    assert_eq!(
        password::app(&did, &fixture.app.password),
        fixture.app.stored
    );
    // Two accounts choosing the same one store different hashes, which is what
    // the salt is for even though nothing random goes into it.
    let other = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa".parse().expect("a DID");
    assert_ne!(
        password::app(&other, &fixture.app.password),
        fixture.app.stored
    );
}

#[test]
fn a_fresh_hash_is_salted_and_reads_back() {
    let stored = password::hash("correct horse battery staple");

    assert!(password::verify("correct horse battery staple", &stored));
    assert!(!password::verify("correct horse battery stapl", &stored));
    assert_ne!(stored, password::hash("correct horse battery staple"));
    // Nothing that is not a salt and a hash is a stored password.
    assert!(!password::verify("anything", "no colon here"));
}
