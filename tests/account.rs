//! The account layer, against what the reference stores for the same inputs.

use manapds::account::{handle, password};
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

/// A server handing out handles under one domain, as the configuration would.
fn rules() -> handle::Rules {
    handle::Rules::new(&[".pds.test".to_owned()])
}

#[test]
fn signing_up_takes_a_name_under_a_domain_this_server_serves() {
    let rules = rules();

    assert_eq!(
        rules.signup("Alice.PDS.test").expect("a handle").as_str(),
        "alice.pds.test"
    );
    // Somebody else's domain is refused at creation even though it is a
    // perfectly good handle, because nothing exists yet to point it at.
    assert_eq!(
        rules.signup("alice.example.com"),
        Err(handle::Invalid::Unsupported)
    );
}

#[test]
fn the_part_in_front_of_the_domain_is_one_label_of_a_workable_length() {
    let rules = rules();

    assert!(matches!(
        rules.signup("ab.pds.test"),
        Err(handle::Invalid::Handle("Handle too short"))
    ));
    assert!(matches!(
        rules.signup("nineteen-characters.pds.test"),
        Err(handle::Invalid::Handle("Handle too long"))
    ));
    assert!(matches!(
        rules.signup("alice.and.bob.pds.test"),
        Err(handle::Invalid::Handle("Invalid characters in handle"))
    ));
    // The two ends of the range are both allowed.
    assert!(rules.signup("abc.pds.test").is_ok());
    assert!(rules.signup("eighteen-chars-yes.pds.test").is_ok());
}

#[test]
fn a_name_somebody_would_expect_to_reach_the_server_is_held_back() {
    let rules = rules();

    for name in ["admin", "www", "xrpc", "bsky", "support"] {
        assert_eq!(
            rules.signup(&format!("{name}.pds.test")),
            Err(handle::Invalid::Reserved),
            "{name}"
        );
    }
}

#[test]
fn a_handle_nothing_could_ever_resolve_is_refused_wherever_it_came_from() {
    let rules = rules();

    for input in ["alice.local", "alice.invalid", "alice.onion"] {
        assert!(
            matches!(rules.normalize(input), Err(handle::Invalid::Handle(_))),
            "{input}"
        );
    }
    // `.test` is what a development server runs under, so it stays.
    assert!(rules.normalize("alice.test").is_ok());
}

#[test]
fn the_domain_itself_is_this_server_even_though_no_account_holds_it() {
    let rules = rules();
    let handle = |input: &str| rules.normalize(input).expect("a handle");

    assert!(rules.is_local(&handle("alice.pds.test")));
    assert!(rules.is_local(&handle("pds.test")));
    assert!(!rules.is_local(&handle("alice.example.com")));
    assert_eq!(
        rules.service_domain(&handle("alice.pds.test")),
        Some(".pds.test")
    );
    assert_eq!(rules.service_domain(&handle("pds.test")), None);
}
