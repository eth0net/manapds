//! The account layer, against what the reference stores for the same inputs.

use manapds::account::{self, handle, password};
use manapds::store;
use manapds::syntax::Did;
use manapds::xrpc::auth::{Expired, Scope, Tokens};
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

/// An account on a server holding nothing else, with one app password.
fn manager() -> (account::Manager, Did) {
    let did: Did = "did:plc:mav423b24thku7ezkx7yaray".parse().expect("a DID");
    let mut accounts = store::Accounts::memory().expect("a database");
    accounts
        .create(&store::Account {
            did: did.clone(),
            handle: Some("alice.pds.test".parse().expect("a handle")),
            email: "Alice@Example.com".to_owned(),
            password_scrypt: password::hash("correct horse battery staple"),
        })
        .expect("an account");
    accounts
        .create_app_password(
            &did,
            &store::AppPassword {
                name: "phone".to_owned(),
                privileged: false,
            },
            &password::app(&did, "abcd-efgh-ijkl-mnop"),
        )
        .expect("an app password");

    let tokens = Tokens::new("a secret long enough to not be guessed", "did:web:pds.test");
    (account::Manager::new(accounts, tokens), did)
}

#[tokio::test]
async fn an_identifier_is_whichever_of_three_things_it_looks_like() {
    let (manager, did) = manager();

    for identifier in [
        "alice.pds.test",
        "ALICE.PDS.TEST",
        "alice@example.com",
        "did:plc:mav423b24thku7ezkx7yaray",
    ] {
        let login = manager
            .login(identifier, "correct horse battery staple")
            .await
            .expect("a login");
        assert_eq!(login.account.did, did, "{identifier}");
        assert!(login.app_password.is_none(), "{identifier}");
    }
}

#[tokio::test]
async fn a_password_that_is_not_the_password_says_nothing_else() {
    let (manager, _) = manager();

    for (identifier, password) in [
        ("alice.pds.test", "not the password"),
        ("nobody.pds.test", "correct horse battery staple"),
        ("nobody@example.com", "correct horse battery staple"),
        ("not an identifier at all", "correct horse battery staple"),
    ] {
        let error = manager
            .login(identifier, password)
            .await
            .expect_err("no login");
        assert!(matches!(error, account::Error::Credentials), "{identifier}");
    }
}

#[tokio::test]
async fn an_app_password_opens_a_session_that_may_do_less() {
    let (manager, did) = manager();

    let login = manager
        .login("alice.pds.test", "abcd-efgh-ijkl-mnop")
        .await
        .expect("a login");
    let app_password = login.app_password.as_ref().expect("an app password");
    assert_eq!(app_password.name, "phone");

    let credentials = manager
        .open_session(&did, Some(app_password))
        .expect("a session");
    let tokens = Tokens::new("a secret long enough to not be guessed", "did:web:pds.test");
    assert!(
        tokens
            .verify_access(&credentials.access, &[Scope::AppPassword])
            .is_ok()
    );
    // And the full scope is not among the ones it reaches.
    assert!(
        tokens
            .verify_access(&credentials.access, &[Scope::Access])
            .is_err()
    );
}

#[test]
fn a_session_is_exchanged_for_the_next_one_and_the_old_token_stops_working() {
    let (manager, did) = manager();
    let tokens = Tokens::new("a secret long enough to not be guessed", "did:web:pds.test");
    let opened = manager.open_session(&did, None).expect("a session");
    let id = |token: &str| {
        tokens
            .verify_refresh(token, Expired::Refuse)
            .expect("a refresh token")
            .id
    };

    let refreshed = manager
        .refresh_session(&id(&opened.refresh))
        .expect("no failure")
        .expect("a new session");
    assert_ne!(id(&refreshed.refresh), id(&opened.refresh));

    // Retrying the same exchange lands on the same successor rather than
    // opening a second session beside it.
    let again = manager
        .refresh_session(&id(&opened.refresh))
        .expect("no failure")
        .expect("the same session");
    assert_eq!(id(&again.refresh), id(&refreshed.refresh));
}

#[test]
fn a_revoked_session_cannot_be_exchanged_for_anything() {
    let (manager, did) = manager();
    let tokens = Tokens::new("a secret long enough to not be guessed", "did:web:pds.test");
    let opened = manager.open_session(&did, None).expect("a session");
    let id = tokens
        .verify_refresh(&opened.refresh, Expired::Refuse)
        .expect("a refresh token")
        .id;

    assert!(manager.revoke_session(&id).expect("no failure"));
    assert!(manager.refresh_session(&id).expect("no failure").is_none());
    // And revoking it twice is not an error, only a second answer of no.
    assert!(!manager.revoke_session(&id).expect("no failure"));
}

#[test]
fn changing_what_signs_in_ends_every_session_at_once() {
    let (manager, did) = manager();
    manager.open_session(&did, None).expect("a session");
    manager.open_session(&did, None).expect("another");

    assert_eq!(manager.revoke_sessions(&did).expect("no failure"), 2);
}
