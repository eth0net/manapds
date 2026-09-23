//! The account layer, against what the reference stores for the same inputs.

mod common;

use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use manapds::account::{self, email, handle, password};
use manapds::crypto::{Algorithm, Keypair};
use manapds::repo::Repo;
use manapds::store;
use manapds::syntax::{Did, TidClock};
use manapds::xrpc::auth::{Expired, Scope, Tokens};
use serde::Deserialize;
use tempfile::TempDir;

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

#[test]
fn the_password_nobody_has_is_nobody_s() {
    for password in [
        "",
        "correct horse battery staple",
        "\u{1f600}",
        "0".repeat(512).as_str(),
    ] {
        assert!(!password::nobody(password), "{password:?}");
    }
}

/// A server handing out handles under one domain, as the configuration would.
fn rules() -> handle::Rules {
    handle::Rules::new(&[".pds.test".to_owned()], &[])
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
fn a_server_can_hold_back_names_of_its_own() {
    let rules = handle::Rules::new(
        &[".pds.test".to_owned()],
        &["Mana".to_owned(), "  support  ".to_owned()],
    );

    // Matched however the configuration and the caller happen to spell it.
    assert_eq!(
        rules.signup("mana.pds.test"),
        Err(handle::Invalid::Reserved)
    );
    assert_eq!(
        rules.signup("MANA.pds.test"),
        Err(handle::Invalid::Reserved)
    );
    assert_eq!(
        rules.signup("support.pds.test"),
        Err(handle::Invalid::Reserved)
    );

    // Added to the built-in list rather than replacing it.
    assert_eq!(
        rules.signup("admin.pds.test"),
        Err(handle::Invalid::Reserved)
    );
    assert!(rules.signup("alice.pds.test").is_ok());
}

#[test]
fn holding_back_nothing_holds_back_what_the_reference_does() {
    let rules = rules();

    assert_eq!(
        rules.signup("admin.pds.test"),
        Err(handle::Invalid::Reserved)
    );
    assert_eq!(rules.signup("mana.pds.test").map(|_| ()), Ok(()));
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

fn tokens() -> Tokens {
    Tokens::new(common::SECRET, "did:web:pds.test")
}

/// What a directory was sent: the path and the body, in order.
type Seen = Arc<Mutex<Vec<(String, String)>>>;

/// A directory on a port of its own, which takes whatever it is sent.
async fn directory() -> (String, Seen) {
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&seen);
    let router = axum::Router::new().fallback(move |uri: axum::http::Uri, body: String| {
        let recorded = Arc::clone(&recorded);
        async move {
            recorded
                .lock()
                .expect("nothing panicked while holding it")
                .push((uri.path().to_owned(), body));
            ""
        }
    });
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("a port");
    let url = format!(
        "http://127.0.0.1:{}",
        listener.local_addr().expect("an address").port()
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    (url, seen)
}

/// An account on a server holding nothing else, with one app password.
///
/// Sign-ins answer as fast as they can: the delay is there to hide which
/// identifiers exist, which a test has no reason to hide.
fn manager() -> (account::Manager, Did, TempDir) {
    budgeted(Duration::ZERO)
}

/// The same, holding sign-ins to a budget, which is what testing the budget
/// itself needs.
fn budgeted(budget: Duration) -> (account::Manager, Did, TempDir) {
    let did: Did = "did:plc:mav423b24thku7ezkx7yaray".parse().expect("a DID");
    let data = tempfile::tempdir().expect("a directory");
    let mut accounts = store::Accounts::memory().expect("a database");
    accounts
        .create(&store::Registration {
            account: store::Account {
                did: did.clone(),
                handle: Some("alice.pds.test".parse().expect("a handle")),
                email: "Alice@Example.com".to_owned(),
                password_scrypt: password::hash("correct horse battery staple"),
            },
            root: root(),
            invite: None,
            session: None,
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

    let config = Arc::new(common::config(
        "pds.test",
        data.path(),
        "http://127.0.0.1:1",
    ));
    let manager = account::Manager::new(
        config,
        accounts,
        store::Sequencer::memory().expect("a log"),
        tokens(),
    )
    .answering_in(budget);
    (manager, did, data)
}

/// Where a repository starts, which an account cannot be written without.
fn root() -> store::Root {
    let key = Keypair::generate(Algorithm::Secp256k1);
    let (repo, _) = Repo::create(
        "did:plc:mav423b24thku7ezkx7yaray".parse().expect("a DID"),
        &key,
        &mut TidClock::new(),
    )
    .expect("a repository");
    store::Root {
        cid: repo.cid(),
        rev: repo.rev().clone(),
    }
}

#[tokio::test]
async fn an_identifier_is_whichever_of_three_things_it_looks_like() {
    let (manager, did, _data) = manager();

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
    let (manager, _, _data) = manager();

    for (identifier, password) in [
        ("alice.pds.test", "not the password"),
        ("nobody.pds.test", "correct horse battery staple"),
        ("nobody@example.com", "correct horse battery staple"),
        ("not an identifier at all", "correct horse battery staple"),
        // Longer than any password this server ever stored, so nothing it
        // holds could be it.
        ("alice.pds.test", &"x".repeat(513)),
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
    let (manager, did, _data) = manager();

    let login = manager
        .login("alice.pds.test", "abcd-efgh-ijkl-mnop")
        .await
        .expect("a login");
    let app_password = login.app_password.as_ref().expect("an app password");
    assert_eq!(app_password.name, "phone");

    let credentials = manager
        .open_session(&did, Some(app_password))
        .expect("a session");
    let tokens = tokens();
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
fn a_session_is_named_the_way_the_reference_names_one() {
    let (manager, did, _data) = manager();
    let tokens = tokens();
    let opened = manager.open_session(&did, None).expect("a session");
    let id = tokens
        .verify_refresh(&opened.refresh, Expired::Refuse)
        .expect("a refresh token")
        .id;

    // 32 bytes through an alphabet that carries no padding.
    assert_eq!(id.len(), 43);
    assert!(!id.contains('='));
}

#[test]
fn a_session_is_exchanged_for_the_next_one_and_the_old_token_stops_working() {
    let (manager, did, _data) = manager();
    let tokens = tokens();
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
    let (manager, did, _data) = manager();
    let tokens = tokens();
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
    let (manager, did, _data) = manager();
    manager.open_session(&did, None).expect("a session");
    manager.open_session(&did, None).expect("another");

    assert_eq!(manager.revoke_sessions(&did).expect("no failure"), 2);
}

/// A server nobody has signed up to yet, and the directory it registers at.
async fn empty(invite_required: bool) -> (account::Manager, TempDir, Seen) {
    let (url, seen) = directory().await;
    let data = tempfile::tempdir().expect("a directory");
    let mut config = common::config("pds.test", data.path(), &url);
    config.invite_required = invite_required;
    let accounts = store::Accounts::memory().expect("a database");
    (
        account::Manager::new(
            Arc::new(config),
            accounts,
            store::Sequencer::memory().expect("a log"),
            tokens(),
        )
        .answering_in(Duration::ZERO),
        data,
        seen,
    )
}

fn signup(handle: &str) -> account::Signup {
    account::Signup {
        handle: handle.to_owned(),
        email: "alice@example.com".to_owned(),
        password: "correct horse battery staple".to_owned(),
        invite: None,
        recovery_key: None,
    }
}

#[tokio::test]
async fn signing_up_writes_an_identity_a_repository_and_a_session() {
    let (manager, data, seen) = empty(false).await;

    let created = manager
        .create(&signup("alice.pds.test"))
        .await
        .expect("an account");
    assert_eq!(created.handle.as_str(), "alice.pds.test");
    assert!(created.did.as_str().starts_with("did:plc:"));

    // The account reads back, and the session it was handed opens.
    let account = manager
        .account(&created.did)
        .expect("reads")
        .expect("an account");
    assert_eq!(account.email, "alice@example.com");
    let id = tokens()
        .verify_refresh(&created.credentials.refresh, Expired::Refuse)
        .expect("a refresh token")
        .id;
    assert!(manager.refresh_session(&id).expect("no failure").is_some());

    // Its key and its repository are on disk under the shard the DID hashes
    // to, rather than beside every other account.
    let directory = store::Directory::new(data.path());
    assert!(directory.actor_key(&created.did).exists());
    assert!(directory.actor_store(&created.did).exists());

    // And the directory was told, under the identifier the operation minted.
    let sent = seen.lock().expect("nothing panicked").clone();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].0, format!("/{}", created.did));
    assert!(sent[0].1.contains("alice.pds.test"), "{}", sent[0].1);
}

#[tokio::test]
async fn a_signup_the_directory_will_not_take_leaves_nothing_behind() {
    let data = tempfile::tempdir().expect("a directory");
    // A port nothing answers on, which is the failure that happens after
    // everything local has already been written.
    let config = common::config("pds.test", data.path(), "http://127.0.0.1:1");
    let accounts = store::Accounts::memory().expect("a database");
    let manager = account::Manager::new(
        Arc::new(config),
        accounts,
        store::Sequencer::memory().expect("a log"),
        tokens(),
    );

    let error = manager
        .create(&signup("alice.pds.test"))
        .await
        .expect_err("no account");
    assert!(matches!(error, account::Error::Plc(_)), "{error}");

    // Nothing is left for a second attempt to trip over.
    assert!(
        manager
            .resolve(&"alice.pds.test".parse().expect("a handle"))
            .expect("reads")
            .is_none()
    );
    assert_eq!(files(data.path()), Vec::<String>::new());
}

/// A directory that says nothing about a registration and nothing about what
/// it holds, which is the state no answer can be read out of.
async fn mute() -> String {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("a port");
    let url = format!(
        "http://127.0.0.1:{}",
        listener.local_addr().expect("an address").port()
    );
    tokio::spawn(async move {
        let router = axum::Router::new().fallback(|| async { axum::http::StatusCode::BAD_GATEWAY });
        let _ = axum::serve(listener, router).await;
    });
    url
}

#[tokio::test]
async fn a_signup_the_directory_would_not_speak_for_is_left_standing() {
    let data = tempfile::tempdir().expect("a directory");
    let config = common::config("pds.test", data.path(), &mute().await);
    let accounts = store::Accounts::memory().expect("a database");
    let manager = account::Manager::new(
        Arc::new(config),
        accounts,
        store::Sequencer::memory().expect("a log"),
        tokens(),
    );

    let error = manager
        .create(&signup("alice.pds.test"))
        .await
        .expect_err("no session");
    assert!(matches!(error, account::Error::Plc(_)), "{error}");

    // Kept: a directory that will not say what it holds may be holding this,
    // and an identifier it took is not this server's to give back.
    assert!(
        manager
            .resolve(&"alice.pds.test".parse().expect("a handle"))
            .expect("reads")
            .is_some()
    );
}

/// A directory that accepts the connection and then says nothing, which is
/// what a signup is waiting on when the caller gives up on it.
async fn silent() -> String {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("a port");
    let url = format!(
        "http://127.0.0.1:{}",
        listener.local_addr().expect("an address").port()
    );
    tokio::spawn(async move {
        // Held, because dropping a socket would answer by closing it.
        let mut open = Vec::new();
        while let Ok((socket, _)) = listener.accept().await {
            open.push(socket);
        }
    });
    url
}

#[tokio::test]
async fn a_signup_the_caller_gives_up_on_mid_registration_is_left_standing() {
    let data = tempfile::tempdir().expect("a directory");
    let config = common::config("pds.test", data.path(), &silent().await);
    let accounts = store::Accounts::memory().expect("a database");
    let manager = account::Manager::new(
        Arc::new(config),
        accounts,
        store::Sequencer::memory().expect("a log"),
        tokens(),
    );
    let handle: manapds::syntax::Handle = "alice.pds.test".parse().expect("a handle");

    let request = signup("alice.pds.test");
    let mut attempt = Box::pin(manager.create(&request));
    // Driven until the account is written, which is the point the directory is
    // being waited on and everything local is already there.
    for _ in 0..200 {
        tokio::select! {
            _ = &mut attempt => panic!("the directory answered after all"),
            () = tokio::time::sleep(Duration::from_millis(25)) => {}
        }
        if manager.resolve(&handle).expect("reads").is_some() {
            break;
        }
    }
    assert!(
        manager.resolve(&handle).expect("reads").is_some(),
        "the signup never got as far as the directory"
    );

    // The caller hangs up. Nothing else is going to run on this account's behalf.
    drop(attempt);

    // Kept: hanging up says nothing about what the directory did with the
    // operation, and an identifier it took is not this server's to give back.
    assert!(manager.resolve(&handle).expect("reads").is_some());
    assert!(!files(data.path()).is_empty());
}

/// Every file under a directory, however deep, by name.
fn files(at: &Path) -> Vec<String> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(at).expect("a directory").flatten() {
        if entry.path().is_dir() {
            found.extend(files(&entry.path()));
        } else {
            found.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    found
}

#[tokio::test]
async fn a_server_that_asks_for_an_invite_spends_it_once() {
    let (manager, _data, _seen) = empty(true).await;

    let error = manager
        .create(&signup("alice.pds.test"))
        .await
        .expect_err("no invite");
    assert!(matches!(error, account::Error::InviteRequired), "{error}");

    let mut asked = signup("alice.pds.test");
    asked.invite = Some("pds-test-aaaaa-bbbbb".to_owned());
    let error = manager.create(&asked).await.expect_err("no such code");
    assert!(matches!(error, account::Error::Invite), "{error}");

    let codes = manager.mint_invites("admin", 1, 1).expect("a code");
    // The code names the server it is good for, so one pasted at the wrong
    // one is obviously wrong.
    assert!(codes[0].starts_with("pds-test-"), "{}", codes[0]);
    asked.invite = Some(codes[0].clone());
    manager.create(&asked).await.expect("an account");

    // One use, so the next signup under it is refused.
    let mut second = signup("bob.pds.test");
    second.email = "bob@example.com".to_owned();
    second.invite = Some(codes[0].clone());
    let error = manager.create(&second).await.expect_err("spent");
    assert!(matches!(error, account::Error::Invite), "{error}");
}

#[tokio::test]
async fn a_name_or_an_address_somebody_else_holds_is_refused() {
    let (manager, _data, _seen) = empty(false).await;
    manager
        .create(&signup("alice.pds.test"))
        .await
        .expect("an account");

    let error = manager
        .create(&signup("alice.pds.test"))
        .await
        .expect_err("taken");
    assert!(matches!(error, account::Error::Taken("Handle")), "{error}");
    // Not HandleNotAvailable, which this method keeps for a name held back.
    assert_eq!(error.name(), "InvalidRequest");

    let mut same_email = signup("bob.pds.test");
    same_email.email = "ALICE@example.com".to_owned();
    let error = manager.create(&same_email).await.expect_err("taken");
    assert!(matches!(error, account::Error::Taken("Email")), "{error}");
}

#[tokio::test]
async fn what_a_signup_asks_for_is_checked_before_anything_is_written() {
    let (manager, _data, seen) = empty(false).await;

    let mut long = signup("alice.pds.test");
    long.password = "x".repeat(257);
    assert!(matches!(
        manager.create(&long).await.expect_err("too long"),
        account::Error::PasswordTooLong
    ));

    let mut bad_email = signup("alice.pds.test");
    bad_email.email = "not an address".to_owned();
    assert!(matches!(
        manager.create(&bad_email).await.expect_err("not an email"),
        account::Error::Email
    ));

    assert!(matches!(
        manager
            .create(&signup("admin.pds.test"))
            .await
            .expect_err("reserved"),
        account::Error::Handle(handle::Invalid::Reserved)
    ));

    // None of which reached the directory.
    assert!(seen.lock().expect("nothing panicked").is_empty());
}

#[tokio::test]
async fn a_password_is_measured_in_characters_rather_than_bytes() {
    let (manager, _data, _seen) = empty(false).await;

    // 256 accented letters are 512 bytes, and still a password anybody may
    // choose.
    let mut accented = signup("alice.pds.test");
    accented.password = "é".repeat(256);
    manager.create(&accented).await.expect("an account");

    // One character over is not, however it is spelled.
    let mut over = signup("bob.pds.test");
    over.email = "bob@example.com".to_owned();
    over.password = "é".repeat(257);
    assert!(matches!(
        manager.create(&over).await.expect_err("too long"),
        account::Error::PasswordTooLong
    ));
}

#[test]
fn an_address_is_taken_only_if_something_could_be_sent_to_it() {
    for address in [
        "alice@example.com",
        "alice.smith+tag@mail.example.co.uk",
        "a@b.co",
    ] {
        assert!(email::plausible(address), "{address}");
    }
    for address in [
        "not an address",
        "alice@",
        "@example.com",
        "alice@example",
        "alice@@example.com",
        "alice@exa mple.com",
        ".alice@example.com",
        "alice.@example.com",
        "al..ice@example.com",
        "alice@-example.com",
    ] {
        assert!(!email::plausible(address), "{address}");
    }
}

#[tokio::test]
async fn signing_in_takes_as_long_whether_or_not_the_account_is_there() {
    let budget = Duration::from_millis(120);
    let (manager, _, _data) = budgeted(budget);

    for identifier in ["alice.pds.test", "nobody@example.com"] {
        let started = std::time::Instant::now();
        let _ = manager.login(identifier, "not the password").await;
        let taken = started.elapsed();
        assert!(
            taken >= budget,
            "{identifier} answered in {taken:?}, which says whether it was there"
        );
    }
}

#[test]
fn a_race_lost_inside_the_write_answers_like_one_lost_before_it() {
    let named = |error: store::Error| account::Error::from(error).name();

    assert_eq!(named(store::Error::InviteUnavailable), "InvalidInviteCode");
    assert_eq!(named(store::Error::HandleTaken), "InvalidRequest");
    assert_eq!(named(store::Error::EmailTaken), "InvalidRequest");
}

#[tokio::test]
async fn a_signup_puts_the_account_in_the_log() {
    let data = tempfile::tempdir().expect("a directory");
    let (url, _seen) = directory().await;
    let config = common::config("pds.test", data.path(), &url);
    let log = data.path().join("sequencer.sqlite");
    let manager = account::Manager::new(
        Arc::new(config),
        store::Accounts::memory().expect("a database"),
        store::Sequencer::open(&log).expect("a log"),
        tokens(),
    );

    let created = manager
        .create(&signup("alice.pds.test"))
        .await
        .expect("an account");

    // Read through a second connection, which is all a consumer would be.
    let entries = store::Sequencer::open(&log)
        .expect("a log")
        .since(0, 10)
        .expect("reads");

    let kinds: Vec<store::Event> = entries.iter().map(|entry| entry.event).collect();
    assert_eq!(
        kinds,
        [
            store::Event::Identity,
            store::Event::Account,
            store::Event::Append,
            store::Event::Sync
        ]
    );
    assert!(entries.iter().all(|entry| entry.did == created.did));

    let manapds::repo::Ipld::Map(identity) =
        manapds::repo::decode(&entries[0].body).expect("dag-cbor")
    else {
        panic!("an identity entry is a map")
    };
    assert_eq!(
        identity.get("handle"),
        Some(&manapds::repo::Ipld::String("alice.pds.test".to_owned()))
    );
}

#[tokio::test]
async fn a_signup_the_directory_refuses_puts_nothing_in_the_log() {
    let data = tempfile::tempdir().expect("a directory");
    let config = common::config("pds.test", data.path(), "http://127.0.0.1:1");
    let log = data.path().join("sequencer.sqlite");
    let manager = account::Manager::new(
        Arc::new(config),
        store::Accounts::memory().expect("a database"),
        store::Sequencer::open(&log).expect("a log"),
        tokens(),
    );

    manager
        .create(&signup("alice.pds.test"))
        .await
        .expect_err("no account");

    assert_eq!(
        store::Sequencer::open(&log)
            .expect("a log")
            .latest()
            .expect("reads"),
        None
    );
}
