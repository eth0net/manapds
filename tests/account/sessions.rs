//! Signing in, what an app password may do, and what ends a session.

use super::*;

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
        .await
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

#[tokio::test]
async fn a_session_is_named_the_way_the_reference_names_one() {
    let (manager, did, _data) = manager();
    let tokens = tokens();
    let opened = manager.open_session(&did, None).await.expect("a session");
    let id = tokens
        .verify_refresh(&opened.refresh, Expired::Refuse)
        .expect("a refresh token")
        .id;

    // 32 bytes through an alphabet that carries no padding.
    assert_eq!(id.len(), 43);
    assert!(!id.contains('='));
}

#[tokio::test]
async fn a_session_is_exchanged_for_the_next_one_and_the_old_token_stops_working() {
    let (manager, did, _data) = manager();
    let tokens = tokens();
    let opened = manager.open_session(&did, None).await.expect("a session");
    let id = |token: &str| {
        tokens
            .verify_refresh(token, Expired::Refuse)
            .expect("a refresh token")
            .id
    };

    let refreshed = manager
        .refresh_session(&id(&opened.refresh))
        .await
        .expect("no failure")
        .expect("a new session");
    assert_ne!(id(&refreshed.refresh), id(&opened.refresh));

    // Retrying the same exchange lands on the same successor rather than
    // opening a second session beside it.
    let again = manager
        .refresh_session(&id(&opened.refresh))
        .await
        .expect("no failure")
        .expect("the same session");
    assert_eq!(id(&again.refresh), id(&refreshed.refresh));
}

#[tokio::test]
async fn a_revoked_session_cannot_be_exchanged_for_anything() {
    let (manager, did, _data) = manager();
    let tokens = tokens();
    let opened = manager.open_session(&did, None).await.expect("a session");
    let id = tokens
        .verify_refresh(&opened.refresh, Expired::Refuse)
        .expect("a refresh token")
        .id;

    assert!(manager.revoke_session(&id).await.expect("no failure"));
    assert!(
        manager
            .refresh_session(&id)
            .await
            .expect("no failure")
            .is_none()
    );
    // And revoking it twice is not an error, only a second answer of no.
    assert!(!manager.revoke_session(&id).await.expect("no failure"));
}

#[tokio::test]
async fn changing_what_signs_in_ends_every_session_at_once() {
    let (manager, did, _data) = manager();
    manager.open_session(&did, None).await.expect("a session");
    manager.open_session(&did, None).await.expect("another");

    assert_eq!(manager.revoke_sessions(&did).await.expect("no failure"), 2);
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
