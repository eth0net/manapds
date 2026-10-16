//! The event log, which numbers what happened and hands it back in order.

use super::*;

#[test]
fn the_log_numbers_events_in_order() {
    let log = Sequencer::memory().expect("opens");
    assert_eq!(log.latest().expect("reads"), None);
    assert_eq!(log.since(0, 10).expect("reads"), vec![]);

    let first = log
        .append(&account(), Event::Append, b"one")
        .expect("writes");
    let second = log
        .append(&account(), Event::Identity, b"two")
        .expect("writes");
    let third = log
        .append(&account(), Event::Account, b"three")
        .expect("writes");

    assert!(first < second && second < third);
    assert_eq!(log.latest().expect("reads"), Some(third));

    let entries = log.since(first, 10).expect("reads");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].seq, second);
    assert_eq!(entries[0].event, Event::Identity);
    assert_eq!(entries[0].body, b"two");
    assert_eq!(&entries[0].did, &account());
    assert_eq!(entries[1].event, Event::Account);

    assert_eq!(log.since(0, 2).expect("reads").len(), 2, "the limit holds");
}

#[test]
fn a_superseded_entry_is_not_handed_out() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let path = home.path().join("sequencer.sqlite");
    let log = Sequencer::open(&path).expect("opens");
    let skipped = log
        .append(&account(), Event::Account, b"gone")
        .expect("writes");
    let kept = log
        .append(&account(), Event::Account, b"here")
        .expect("writes");

    Connection::open(&path)
        .expect("opens")
        .execute(
            r#"update "repo_seq" set "invalidated" = 1 where "seq" = ?1"#,
            rusqlite::params![skipped],
        )
        .expect("writes");

    let entries = log.since(0, 10).expect("reads");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].seq, kept);
    // The number is still spent, so nothing reuses it.
    assert_eq!(log.latest().expect("reads"), Some(kept));
}

#[test]
fn the_log_keeps_its_numbering_across_a_reopen() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let path = home.path().join("sequencer.sqlite");
    let last = {
        let log = Sequencer::open(&path).expect("opens");
        log.append(&account(), Event::Append, b"one")
            .expect("writes");
        log.append(&account(), Event::Append, b"two")
            .expect("writes")
    };

    let log = Sequencer::open(&path).expect("reopens");
    assert_eq!(log.latest().expect("reads"), Some(last));
    assert!(
        log.append(&account(), Event::Append, b"three")
            .expect("writes")
            > last,
        "a restart must not rewind the sequence"
    );
}
