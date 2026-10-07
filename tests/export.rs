//! What a download costs the server sending it.
//!
//! The allocator below counts every thread in this binary, so the file holds
//! one test and the measurement has the process to itself.

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use manapds::account::{self, Manager};
use manapds::repo::{self, Ipld};
use manapds::store::{self, Account, Actor, Blocks, Directory, Registration, Root};
use manapds::syntax::{Did, Tid};
use manapds::xrpc::auth::Tokens;
use tempfile::TempDir;

/// Live bytes, and the most of them that have been live at once.
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

struct Counting;

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let live = LIVE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
        PEAK.fetch_max(live, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(pointer, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// How many bytes a block of the repositories below holds.
const BLOCK: usize = 256;

fn did(suffix: &str) -> Did {
    format!("did:plc:4cjoyc3cgpal7gnrpzyjhnv{suffix}")
        .parse()
        .expect("a DID")
}

/// A server holding an account per entry, each with `blocks` blocks under a
/// revision of its own.
fn served(repositories: &[(&str, usize)]) -> (Arc<Manager>, TempDir) {
    let data = tempfile::tempdir().expect("a directory");
    let directory = Directory::new(data.path());
    let mut accounts = store::Accounts::memory().expect("a database");

    for (suffix, blocks) in repositories {
        let account = did(suffix);
        let mut store =
            Actor::open(&directory.actor_store(&account), account.clone()).expect("a store");
        let root = filled(&mut store, *blocks);
        accounts
            .create(&Registration {
                account: Account {
                    did: account,
                    handle: Some(
                        format!("{suffix}.pds.example.com")
                            .parse()
                            .expect("a handle"),
                    ),
                    email: format!("{suffix}@example.com"),
                    password_scrypt: account::password::hash("correct horse battery staple"),
                },
                root,
                invite: None,
                session: None,
            })
            .expect("an account");
    }

    let config = Arc::new(common::config(
        "pds.example.com",
        data.path(),
        "http://127.0.0.1:1",
    ));
    let manager = Arc::new(Manager::new(
        Arc::clone(&config),
        accounts,
        store::Sequencer::memory().expect("a log"),
        Tokens::new(common::SECRET, "did:web:pds.example.com"),
    ));
    (manager, data)
}

/// One revision holding `count` blocks nobody reads, which is all a download
/// cares about.
fn filled(store: &mut Actor, count: usize) -> Root {
    let mut blocks = repo::BlockMap::new();
    let mut first = None;
    for n in 0..count {
        let text = format!("{n:0>BLOCK$}");
        let value = Ipld::Map(BTreeMap::from([("text".to_owned(), Ipld::String(text))]));
        first.get_or_insert(blocks.add(&value).expect("encodes"));
    }
    let root = Root {
        cid: first.expect("a block"),
        rev: "3jqfcqzm4fc2j".parse::<Tid>().expect("a TID"),
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
            &Directory::new("/nonexistent/manapds").blobs(),
        )
        .expect("a commit");
    root
}

/// How large a repository's file is, and the most the server held at once
/// while sending it.
async fn downloaded(manager: &Manager, account: &Did) -> (usize, usize) {
    let settled = LIVE.load(Ordering::Relaxed);
    PEAK.store(settled, Ordering::Relaxed);

    let mut file = manager.export(account, None).await.expect("a download");
    let mut sent = 0;
    while let Some(piece) = file.recv().await {
        sent += piece.expect("a piece of it").len();
    }
    (sent, PEAK.load(Ordering::Relaxed) - settled)
}

#[tokio::test(flavor = "multi_thread")]
async fn what_a_download_holds_does_not_grow_with_the_repository() {
    let (manager, _data) = served(&[("1", 1000), ("2", 8000)]);

    let (small, held) = downloaded(&manager, &did("1")).await;
    let (large, holding) = downloaded(&manager, &did("2")).await;

    assert!(
        large > small * 4,
        "the larger repository is {large} bytes against {small}"
    );
    assert!(
        holding < held * 2,
        "sending {large} bytes held {holding} against {held} for {small}"
    );
    assert!(
        holding < large / 4,
        "sending {large} bytes held {holding} of them"
    );
}
