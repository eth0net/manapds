//! What a signup writes, what it checks first, and what it leaves on the way out.

use super::*;

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
        .await
        .expect("reads")
        .expect("an account");
    assert_eq!(account.email, "alice@example.com");
    let id = tokens()
        .verify_refresh(&created.credentials.refresh, Expired::Refuse)
        .expect("a refresh token")
        .id;
    assert!(
        manager
            .refresh_session(&id)
            .await
            .expect("no failure")
            .is_some()
    );

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

    let minted = manager
        .mint_invites(&["admin".to_owned()], 1, 1)
        .await
        .expect("a code");
    let codes = &minted[0];
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

#[tokio::test]
async fn a_write_lands_under_one_commit_and_moves_the_root() {
    let (manager, data, _seen) = empty(false).await;
    let created = manager
        .create(&signup("alice.pds.test"))
        .await
        .expect("an account");
    let path = store::Directory::new(data.path()).actor_store(&created.did);
    let before = store::Actor::open(&path, created.did.clone())
        .expect("opens")
        .root()
        .expect("reads")
        .expect("a root");

    let written = manager
        .write(
            &created.did,
            vec![record("3jqfcqzm4fc2j", "first").into()],
            None,
        )
        .await
        .expect("a commit")
        .expect("a write");
    assert_eq!(
        written
            .results
            .iter()
            .map(|r| r.uri.as_str())
            .collect::<Vec<_>>(),
        [format!(
            "at://{}/com.example.record/3jqfcqzm4fc2j",
            created.did
        )]
    );
    assert_ne!(written.commit, before.cid);
    assert!(written.rev > before.rev);

    // The tree, the index and the root all moved together.
    let store = store::Actor::open(&path, created.did.clone()).expect("reopens");
    let root = store.root().expect("reads").expect("a root");
    assert_eq!(root.cid, written.commit);
    let held = store
        .record(
            &"com.example.record".parse().expect("an NSID"),
            &"3jqfcqzm4fc2j".parse().expect("a record key"),
        )
        .expect("reads")
        .expect("held");
    assert_eq!(Some(held.cid), written.results[0].cid);

    // And a caller naming the commit it thought it was replacing is refused.
    let refused = manager
        .write(
            &created.did,
            vec![record("3jqfcqzm4fd2j", "second").into()],
            Some(before.cid),
        )
        .await;
    assert!(
        matches!(&refused, Err(account::Error::Swap(at)) if *at == written.commit),
        "{refused:?}"
    );
}
