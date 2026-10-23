//! What a download costs the server while nobody is taking it.

use std::time::Duration;

use manapds::repo;
use manapds::store::{Actor, Blocks};

use super::*;

/// How many bytes a block of the repository below holds.
const BLOCK: usize = 256;

/// How many blocks leave more pages than a download reads ahead, which is
/// what it takes to leave one waiting on whoever asked for it.
const BLOCKS: usize = 2_000;

/// How long a piece may go untaken here. Long enough that nothing gives up
/// while the test is still setting up, short enough to wait for twice.
const PATIENCE: Duration = Duration::from_millis(500);

/// An account whose repository is too large to hand over in one go, on a
/// server that sends `at_once` of them and waits `patience` for a piece.
fn stalling(at_once: usize, patience: Duration) -> (account::Manager, Did, TempDir) {
    let (manager, did, data) = manager();
    let mut store = Actor::open(
        &store::Directory::new(data.path()).actor_store(&did),
        did.clone(),
    )
    .expect("a store");

    let mut blocks = repo::BlockMap::new();
    let mut first = None;
    for n in 0..BLOCKS {
        let text = format!("{n:0>BLOCK$}");
        let value = Ipld::Map(std::collections::BTreeMap::from([(
            "text".to_owned(),
            Ipld::String(text),
        )]));
        first.get_or_insert(blocks.add(&value).expect("encodes"));
    }
    let root = store::Root {
        cid: first.expect("a block"),
        rev: "3jqfcqzm4fc2j".parse().expect("a TID"),
    };
    store
        .commit(
            None,
            &root,
            Blocks {
                written: &blocks,
                dropped: &[],
            },
            &[],
            &store::Directory::new(data.path()).blobs(),
        )
        .expect("a commit");

    (manager.downloading(at_once, patience), did, data)
}

/// How many pieces a download hands over to somebody taking them as they come.
async fn taken(manager: &account::Manager, did: &Did) -> usize {
    let mut file = manager.export(did, None).await.expect("a download");
    let mut pieces = 0;
    while let Some(piece) = file.recv().await {
        piece.expect("a piece of it");
        pieces += 1;
    }
    pieces
}

#[tokio::test(flavor = "multi_thread")]
async fn a_download_nobody_takes_is_dropped() {
    let (manager, did, _data) = stalling(1, PATIENCE);
    let whole = taken(&manager, &did).await;

    let mut file = manager.export(&did, None).await.expect("a download");
    tokio::time::sleep(PATIENCE * 2).await;

    let mut pieces = 0;
    while let Some(piece) = file.recv().await {
        piece.expect("a piece of it");
        pieces += 1;
    }
    assert!(
        pieces < whole,
        "a download left sitting still handed over all {whole} of its pieces"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stalled_download_does_not_hold_the_next_one_out() {
    let (manager, did, _data) = stalling(1, PATIENCE);
    let _stalled = manager.export(&did, None).await.expect("a download");

    let while_held = tokio::time::timeout(PATIENCE / 5, manager.export(&did, None)).await;
    assert!(
        while_held.is_err(),
        "a second download started while the first held the only slot"
    );

    let once_dropped = tokio::time::timeout(PATIENCE * 10, manager.export(&did, None)).await;
    assert!(
        once_dropped.is_ok(),
        "no slot came back once the stalled download was given up on"
    );
}
