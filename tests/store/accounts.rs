//! Who is here: their identifiers, sessions, invite codes and app passwords.

use super::*;

/// Where a repository starts, which every account is written with.
fn root() -> Root {
    let mut clock = TidClock::new();
    let key = Keypair::generate(Algorithm::Secp256k1);
    let (repo, _) = Repo::create(account(), &key, &mut clock).expect("creates");
    Root {
        cid: repo.cid(),
        rev: repo.rev().clone(),
    }
}

fn registration(handle: &str, email: &str) -> Registration {
    Registration {
        account: Account {
            did: account(),
            handle: Some(handle.parse().expect("a handle")),
            email: email.to_owned(),
            password_scrypt: "not a real hash".to_owned(),
        },
        root: root(),
        invite: None,
        session: None,
    }
}

fn session(id: &str, expires_at: &str) -> Session {
    Session {
        id: id.to_owned(),
        did: account(),
        expires_at: expires_at.parse().expect("a timestamp"),
        next_id: None,
        app_password: None,
    }
}

#[test]
fn an_account_reads_back_by_did_handle_or_email() {
    let mut accounts = Accounts::memory().expect("opens");
    let registered = registration("alice.example.com", "alice@example.com");
    accounts.create(&registered).expect("creates");

    assert_eq!(
        accounts.by_did(&account()).expect("reads"),
        Some(registered.account.clone())
    );
    assert_eq!(
        accounts
            .by_handle(&"alice.example.com".parse().expect("a handle"))
            .expect("reads"),
        Some(registered.account)
    );
    assert_eq!(
        accounts
            .by_handle(&"bob.example.com".parse().expect("a handle"))
            .expect("reads"),
        None
    );
    // Signing in takes either, and the email is matched the way the index
    // holds it rather than the way it is typed.
    assert!(
        accounts
            .by_email("ALICE@example.com")
            .expect("reads")
            .is_some()
    );
    assert_eq!(accounts.by_email("bob@example.com").expect("reads"), None);
}

#[test]
fn a_handle_is_taken_whatever_case_it_is_asked_in() {
    let mut accounts = Accounts::memory().expect("opens");
    accounts
        .create(&registration("alice.example.com", "alice@example.com"))
        .expect("creates");

    // The unique index is over lower("handle"), so this is the schema
    // refusing rather than the query.
    let mut clash = registration("ALICE.example.com", "other@example.com");
    clash.account.did = "did:plc:zzzzzzzzzzzzzzzzzzzzzzzz".parse().expect("a DID");
    assert!(accounts.create(&clash).is_err());

    let found = accounts
        .by_handle(&"alice.example.com".parse().expect("a handle"))
        .expect("reads")
        .expect("held");
    assert_eq!(found.email, "alice@example.com");
}

#[test]
fn an_email_is_taken_whatever_case_it_is_given_in() {
    let mut accounts = Accounts::memory().expect("opens");
    accounts
        .create(&registration("alice.example.com", "alice@example.com"))
        .expect("creates");

    let mut clash = registration("bob.example.com", "ALICE@example.com");
    clash.account.did = "did:plc:zzzzzzzzzzzzzzzzzzzzzzzz".parse().expect("a DID");
    assert!(accounts.create(&clash).is_err());
}

#[test]
fn a_session_reads_back_until_it_is_revoked() {
    let mut accounts = Accounts::memory().expect("opens");
    accounts
        .create(&registration("alice.example.com", "alice@example.com"))
        .expect("creates");
    let opened = session("first", "2026-12-01T00:00:00Z");
    accounts.store_session(&opened).expect("stores");

    assert_eq!(accounts.session("first").expect("reads"), Some(opened));
    assert_eq!(accounts.session("second").expect("reads"), None);
    assert!(accounts.revoke_session("first").expect("revokes"));
    assert!(!accounts.revoke_session("first").expect("revokes"));
    assert_eq!(accounts.session("first").expect("reads"), None);
}

#[test]
fn storing_a_session_again_leaves_the_one_already_there() {
    let mut accounts = Accounts::memory().expect("opens");
    accounts
        .create(&registration("alice.example.com", "alice@example.com"))
        .expect("creates");
    let opened = session("first", "2026-12-01T00:00:00Z");
    accounts.store_session(&opened).expect("stores");
    accounts
        .store_session(&session("first", "2027-12-01T00:00:00Z"))
        .expect("stores");

    assert_eq!(accounts.session("first").expect("reads"), Some(opened));
}

#[test]
fn a_session_names_one_successor_and_refuses_a_second() {
    let mut accounts = Accounts::memory().expect("opens");
    accounts
        .create(&registration("alice.example.com", "alice@example.com"))
        .expect("creates");
    accounts
        .store_session(&session("first", "2026-12-01T00:00:00Z"))
        .expect("stores");
    let grace: jiff::Timestamp = "2026-09-01T02:00:00Z".parse().expect("a timestamp");

    assert!(
        accounts
            .rotate("first", grace, &session("second", "2026-12-01T00:00:00Z"))
            .expect("rotates")
    );
    // The same exchange arriving twice is answered with the same session.
    assert!(
        accounts
            .rotate("first", grace, &session("second", "2026-12-01T00:00:00Z"))
            .expect("rotates")
    );
    assert!(
        !accounts
            .rotate("first", grace, &session("third", "2026-12-01T00:00:00Z"))
            .expect("rotates")
    );

    let held = accounts.session("first").expect("reads").expect("held");
    assert_eq!(held.next_id.as_deref(), Some("second"));
    assert_eq!(held.expires_at, grace);

    // The successor it named exists, and the one it refused does not.
    assert!(accounts.session("second").expect("reads").is_some());
    assert!(accounts.session("third").expect("reads").is_none());
}

#[test]
fn only_the_sessions_that_have_run_out_are_cleared() {
    let mut accounts = Accounts::memory().expect("opens");
    accounts
        .create(&registration("alice.example.com", "alice@example.com"))
        .expect("creates");
    accounts
        .store_session(&session("old", "2026-01-01T00:00:00Z"))
        .expect("stores");
    accounts
        .store_session(&session("current", "2027-01-01T00:00:00Z"))
        .expect("stores");
    let now: jiff::Timestamp = "2026-09-01T00:00:00Z".parse().expect("a timestamp");

    assert_eq!(
        accounts.expire_sessions(&account(), now).expect("clears"),
        1
    );
    assert_eq!(accounts.session("old").expect("reads"), None);
    assert!(accounts.session("current").expect("reads").is_some());
    assert_eq!(accounts.revoke_sessions(&account()).expect("revokes"), 1);
    assert_eq!(accounts.session("current").expect("reads"), None);
}

#[test]
fn an_invite_code_is_spent_until_it_runs_out() {
    let mut accounts = Accounts::memory().expect("opens");
    accounts
        .create(&registration("alice.example.com", "alice@example.com"))
        .expect("creates");
    accounts
        .create_invites(&["code-one".to_owned()], account().as_str(), "admin", 2)
        .expect("writes");

    assert!(accounts.invite_available("code-one").expect("reads"));
    assert!(!accounts.invite_available("code-two").expect("reads"));

    let first: Did = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa".parse().expect("a DID");
    let second: Did = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb".parse().expect("a DID");
    accounts.spend_invite("code-one", &first).expect("spends");
    assert!(accounts.invite_available("code-one").expect("reads"));
    accounts.spend_invite("code-one", &second).expect("spends");
    assert!(!accounts.invite_available("code-one").expect("reads"));

    // One account cannot spend the same code twice, which the key enforces
    // rather than the count.
    assert!(accounts.spend_invite("code-one", &first).is_err());
}

#[test]
fn a_code_that_was_disabled_or_taken_down_with_its_account_is_not_available() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let path = home.path().join("account.sqlite");
    let mut accounts = Accounts::open(&path).expect("opens");
    accounts
        .create(&registration("alice.example.com", "alice@example.com"))
        .expect("creates");
    accounts
        .create_invites(
            &["disabled".to_owned(), "held".to_owned()],
            account().as_str(),
            "admin",
            1,
        )
        .expect("writes");
    let db = Connection::open(&path).expect("opens");

    db.execute(
        r#"update "invite_code" set "disabled" = 1 where "code" = 'disabled'"#,
        [],
    )
    .expect("writes");
    assert!(!accounts.invite_available("disabled").expect("reads"));

    assert!(accounts.invite_available("held").expect("reads"));
    db.execute(r#"update "actor" set "takedownRef" = 'held'"#, [])
        .expect("writes");
    assert!(!accounts.invite_available("held").expect("reads"));
}

#[test]
fn an_app_password_is_found_by_its_hash_and_revoked_by_its_name() {
    let mut accounts = Accounts::memory().expect("opens");
    accounts
        .create(&registration("alice.example.com", "alice@example.com"))
        .expect("creates");
    let password = AppPassword {
        name: "phone".to_owned(),
        privileged: false,
    };
    accounts
        .create_app_password(&account(), &password, "a hash")
        .expect("writes");

    assert_eq!(
        accounts.app_password(&account(), "a hash").expect("reads"),
        Some(password.clone())
    );
    assert_eq!(
        accounts
            .app_password(&account(), "another hash")
            .expect("reads"),
        None
    );

    let held = accounts.app_passwords(&account()).expect("reads");
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].0, password);

    // A session opened with it goes when it does, which is the only way a
    // client holding one is shut out.
    accounts
        .store_session(&Session {
            app_password: Some(password),
            ..session("phone session", "2027-01-01T00:00:00Z")
        })
        .expect("stores");
    assert!(
        accounts
            .revoke_app_password(&account(), "phone")
            .expect("revokes")
    );
    assert_eq!(accounts.session("phone session").expect("reads"), None);
    assert_eq!(
        accounts.app_passwords(&account()).expect("reads"),
        Vec::new()
    );
    assert!(
        !accounts
            .revoke_app_password(&account(), "phone")
            .expect("revokes")
    );
}

#[test]
fn a_session_carries_what_its_app_password_may_do_now() {
    let mut accounts = Accounts::memory().expect("opens");
    accounts
        .create(&registration("alice.example.com", "alice@example.com"))
        .expect("creates");
    let password = AppPassword {
        name: "phone".to_owned(),
        privileged: true,
    };
    accounts
        .create_app_password(&account(), &password, "a hash")
        .expect("writes");
    accounts
        .store_session(&Session {
            app_password: Some(AppPassword {
                name: "phone".to_owned(),
                privileged: false,
            }),
            ..session("phone session", "2027-01-01T00:00:00Z")
        })
        .expect("stores");

    // The row holds only the name, so what it reaches is read from the
    // password rather than from whatever was true when the session opened.
    let held = accounts
        .session("phone session")
        .expect("reads")
        .expect("held");
    assert_eq!(held.app_password, Some(password));
}

#[test]
fn an_account_comes_in_on_its_code_and_leaves_with_its_session() {
    let mut accounts = Accounts::memory().expect("opens");
    accounts
        .create_invites(&["pds-test-aaaaa-bbbbb".to_owned()], "admin", "admin", 1)
        .expect("writes the code");

    let mut registered = registration("alice.example.com", "alice@example.com");
    registered.invite = Some("pds-test-aaaaa-bbbbb".to_owned());
    registered.session = Some(session("a session", "2030-01-01T00:00:00.000Z"));
    accounts.create(&registered).expect("creates");

    assert!(
        !accounts
            .invite_available("pds-test-aaaaa-bbbbb")
            .expect("reads")
    );
    assert!(accounts.session("a session").expect("reads").is_some());
    assert_eq!(
        accounts.by_did(&account()).expect("reads"),
        Some(registered.account)
    );
}

#[test]
fn a_code_with_nothing_left_takes_the_account_down_with_it() {
    let mut accounts = Accounts::memory().expect("opens");

    let mut registered = registration("alice.example.com", "alice@example.com");
    registered.invite = Some("pds-test-aaaaa-bbbbb".to_owned());
    assert!(matches!(
        accounts.create(&registered),
        Err(Error::InviteUnavailable)
    ));

    // The code was checked inside the write, so nothing else in it landed
    // either.
    assert_eq!(accounts.by_did(&account()).expect("reads"), None);
}

#[test]
fn deleting_an_account_takes_everything_hanging_off_it() {
    let mut accounts = Accounts::memory().expect("opens");
    let mut registered = registration("alice.example.com", "alice@example.com");
    registered.session = Some(session("a session", "2030-01-01T00:00:00.000Z"));
    accounts.create(&registered).expect("creates");
    accounts
        .create_app_password(
            &account(),
            &AppPassword {
                name: "phone".to_owned(),
                privileged: false,
            },
            "not a real hash",
        )
        .expect("writes");

    accounts.delete(&account()).expect("deletes");

    assert_eq!(accounts.by_did(&account()).expect("reads"), None);
    assert_eq!(accounts.session("a session").expect("reads"), None);
    assert_eq!(
        accounts.app_passwords(&account()).expect("reads"),
        Vec::new()
    );
    // And the handle is free again, which is the point of undoing a signup.
    accounts.create(&registered).expect("creates again");
}

#[test]
fn a_handle_lost_to_a_race_is_named_as_taken() {
    let mut accounts = Accounts::memory().expect("opens");
    accounts
        .create(&registration("alice.test", "alice@example.com"))
        .expect("the first account");

    let mut second = registration("ALICE.test", "bob@example.com");
    second.account.did = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb".parse().expect("a did");

    assert!(matches!(
        accounts.create(&second).expect_err("a clash"),
        Error::HandleTaken
    ));
}

#[test]
fn an_email_lost_to_a_race_is_named_as_taken() {
    let mut accounts = Accounts::memory().expect("opens");
    accounts
        .create(&registration("alice.test", "alice@example.com"))
        .expect("the first account");

    let mut second = registration("bob.test", "ALICE@example.com");
    second.account.did = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb".parse().expect("a did");

    assert!(matches!(
        accounts.create(&second).expect_err("a clash"),
        Error::EmailTaken
    ));
}
