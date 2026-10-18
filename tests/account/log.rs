//! What a signup puts in the event log, and what a refused one does not.

use super::*;

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
