//! Commits, the index they move, and the blocks a reader walks back out.

use super::*;

/// A revision of `count` blocks nothing else points at, rooted at the first
/// of them.
fn revision(store: &mut Actor, from: Option<&Root>, rev: &str, count: usize) -> Root {
    let mut blocks = repo::BlockMap::new();
    let mut first = None;
    for n in 0..count {
        let cid = blocks.add(&post(&format!("{rev}-{n}"))).expect("encodes");
        first.get_or_insert(cid);
    }
    let root = Root {
        cid: first.expect("a block"),
        rev: rev.parse::<Tid>().expect("a TID"),
    };
    store
        .commit(from, &root, genesis(&blocks), &[], &blobs())
        .expect("commits");
    root
}

/// Every block a download would carry, read a page at a time.
fn walked(store: &Actor, since: Option<&Tid>, limit: u32) -> Vec<(repo::Cid, Vec<u8>)> {
    let mut carried = Vec::new();
    let mut from = None;
    loop {
        let page = store
            .blocks_since(since, from.as_ref(), limit)
            .expect("reads");
        carried.extend(page.blocks);
        match page.next {
            Some(mark) => from = Some(mark),
            None => return carried,
        }
    }
}

#[test]
fn a_repository_round_trips_through_a_file() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let path = Directory::new(home.path()).actor_store(&account());
    let key = Keypair::generate(Algorithm::Secp256k1);
    let mut clock = TidClock::new();

    let (mut repo, blocks) = Repo::create(account(), &key, &mut clock).expect("creates");
    {
        let mut store = Actor::open(&path, account()).expect("opens");
        store
            .commit(
                None,
                &Root {
                    cid: repo.cid(),
                    rev: repo.rev().clone(),
                },
                genesis(&blocks),
                &[],
                &blobs(),
            )
            .expect("commits");

        let from = at(&repo);
        let written = repo
            .apply(
                &store,
                &[
                    create("3jqfcqzm4fc2j", "first"),
                    create("3jqfcqzm4fd2j", "second"),
                ],
                &key,
                &mut clock,
            )
            .expect("applies");
        store
            .commit(
                Some(&from),
                &Root {
                    cid: repo.cid(),
                    rev: repo.rev().clone(),
                },
                stored(&written),
                &[
                    indexed("3jqfcqzm4fc2j", "first"),
                    indexed("3jqfcqzm4fd2j", "second"),
                ],
                &blobs(),
            )
            .expect("commits");
    }

    // Everything above is gone; only the file is left.
    let store = Actor::open(&path, account()).expect("reopens");
    let root = store.root().expect("reads").expect("a root");
    assert_eq!(root.cid, repo.cid());
    assert_eq!(&root.rev, repo.rev());

    let mut reloaded = Repo::load(&store, root.cid).expect("loads");
    assert_eq!(reloaded.verify(&key.public_key()), Ok(()));
    assert_eq!(reloaded.records(&store), repo.records(&store));
    assert_eq!(reloaded.records(&store).expect("reads").len(), 2);

    let found = reloaded
        .get(
            &store,
            &"com.example.record".parse().expect("an NSID"),
            &"3jqfcqzm4fc2j".parse().expect("a record key"),
        )
        .expect("reads")
        .expect("held");
    assert_eq!(
        manapds::repo::decode::<Ipld>(&store.get(&found).expect("stored")),
        Ok(post("first"))
    );
}

#[test]
fn the_index_follows_what_the_commit_did() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let path = Directory::new(home.path()).actor_store(&account());
    let key = Keypair::generate(Algorithm::Secp256k1);
    let mut clock = TidClock::new();
    let collection = "com.example.record".parse::<Nsid>().expect("an NSID");
    let rkey = "3jqfcqzm4fc2j".parse::<RecordKey>().expect("a record key");
    let uri = format!("at://{}/{collection}/{rkey}", account());

    let (mut repo, blocks) = Repo::create(account(), &key, &mut clock).expect("creates");
    let mut store = Actor::open(&path, account()).expect("opens");
    store
        .commit(None, &at(&repo), genesis(&blocks), &[], &blobs())
        .expect("commits");
    assert_eq!(indexed_rows(&path), vec![]);

    let from = at(&repo);
    let written = repo
        .apply(
            &store,
            &[create("3jqfcqzm4fc2j", "first")],
            &key,
            &mut clock,
        )
        .expect("applies");
    store
        .commit(
            Some(&from),
            &at(&repo),
            stored(&written),
            &[indexed("3jqfcqzm4fc2j", "first")],
            &blobs(),
        )
        .expect("commits");
    assert_eq!(
        indexed_rows(&path),
        vec![(
            uri.clone(),
            repo::cid_for(&repo::encode(&post("first")).expect("encodes")).to_string(),
            collection.to_string(),
            rkey.to_string(),
        )]
    );

    let from = at(&repo);
    let written = repo
        .apply(
            &store,
            &[Write::Update {
                collection: collection.clone(),
                rkey: rkey.clone(),
                record: post("second"),
            }],
            &key,
            &mut clock,
        )
        .expect("applies");
    store
        .commit(
            Some(&from),
            &at(&repo),
            stored(&written),
            &[indexed("3jqfcqzm4fc2j", "second")],
            &blobs(),
        )
        .expect("commits");
    // The same row, moved on rather than written twice.
    assert_eq!(
        indexed_rows(&path),
        vec![(
            uri,
            repo::cid_for(&repo::encode(&post("second")).expect("encodes")).to_string(),
            collection.to_string(),
            rkey.to_string(),
        )]
    );

    let from = at(&repo);
    let written = repo
        .apply(
            &store,
            &[Write::Delete {
                collection: collection.clone(),
                rkey: rkey.clone(),
            }],
            &key,
            &mut clock,
        )
        .expect("applies");
    store
        .commit(
            Some(&from),
            &at(&repo),
            stored(&written),
            &[Indexed::Delete { collection, rkey }],
            &blobs(),
        )
        .expect("commits");
    assert_eq!(indexed_rows(&path), vec![]);
}

#[test]
fn a_commit_built_on_a_root_somebody_else_moved_is_refused() {
    let key = Keypair::generate(Algorithm::Secp256k1);
    let mut clock = TidClock::new();

    let (repo, blocks) = Repo::create(account(), &key, &mut clock).expect("creates");
    let mut store = Actor::memory(account()).expect("opens");
    store
        .commit(None, &at(&repo), genesis(&blocks), &[], &blobs())
        .expect("commits");

    // Two writers, both working from the root the genesis left.
    let from = at(&repo);
    let (mut first, mut second) = (repo.clone(), repo);
    let one = first
        .apply(&store, &[create("3jqfcqzm4fa2j", "mine")], &key, &mut clock)
        .expect("applies");
    let other = second
        .apply(
            &store,
            &[create("3jqfcqzm4fb2j", "theirs")],
            &key,
            &mut clock,
        )
        .expect("applies");

    assert!(
        store
            .commit(
                Some(&from),
                &at(&first),
                stored(&one),
                &[indexed("3jqfcqzm4fa2j", "mine")],
                &blobs(),
            )
            .expect("commits")
            .is_some()
    );
    // The second was worked out against a tree that has moved, so taking it
    // would drop the first write rather than land beside it.
    assert!(
        store
            .commit(
                Some(&from),
                &at(&second),
                stored(&other),
                &[indexed("3jqfcqzm4fb2j", "theirs")],
                &blobs(),
            )
            .expect("answers")
            .is_none()
    );

    assert_eq!(store.root().expect("reads"), Some(at(&first)));
    let collection = "com.example.record".parse::<Nsid>().expect("an NSID");
    assert_eq!(
        store
            .records(&collection, 10, None, false)
            .expect("reads")
            .len(),
        1
    );
}

#[test]
fn a_collection_pages_newest_first_unless_asked_the_other_way() {
    let key = Keypair::generate(Algorithm::Secp256k1);
    let mut clock = TidClock::new();
    let collection = "com.example.record".parse::<Nsid>().expect("an NSID");

    let (mut repo, blocks) = Repo::create(account(), &key, &mut clock).expect("creates");
    let mut store = Actor::memory(account()).expect("opens");
    store
        .commit(None, &at(&repo), genesis(&blocks), &[], &blobs())
        .expect("commits");

    let from = at(&repo);
    let written = repo
        .apply(
            &store,
            &[
                create("3jqfcqzm4fa2j", "first"),
                create("3jqfcqzm4fb2j", "second"),
                create("3jqfcqzm4fc2j", "third"),
                create_in("com.example.other", "3jqfcqzm4fd2j", "elsewhere"),
                create_in("com.example.recordx", "3jqfcqzm4fe2j", "next door"),
            ],
            &key,
            &mut clock,
        )
        .expect("applies");
    store
        .commit(
            Some(&from),
            &at(&repo),
            stored(&written),
            &[
                indexed("3jqfcqzm4fa2j", "first"),
                indexed("3jqfcqzm4fb2j", "second"),
                indexed("3jqfcqzm4fc2j", "third"),
                indexed_in("com.example.other", "3jqfcqzm4fd2j", "elsewhere"),
                indexed_in("com.example.recordx", "3jqfcqzm4fe2j", "next door"),
            ],
            &blobs(),
        )
        .expect("commits");

    assert_eq!(
        store.collections().expect("reads"),
        [
            "com.example.other",
            "com.example.record",
            "com.example.recordx"
        ]
        .map(|nsid| nsid.parse::<Nsid>().expect("an NSID"))
    );

    // A TID sorts as time, so the default page is the most recent first and a
    // collection nobody asked about stays out of it.
    let page = store.records(&collection, 10, None, false).expect("reads");
    assert_eq!(
        keys(&page),
        ["3jqfcqzm4fc2j", "3jqfcqzm4fb2j", "3jqfcqzm4fa2j"]
    );

    let page = store.records(&collection, 2, None, false).expect("reads");
    assert_eq!(keys(&page), ["3jqfcqzm4fc2j", "3jqfcqzm4fb2j"]);
    let next = store
        .records(&collection, 2, Some("3jqfcqzm4fb2j"), false)
        .expect("reads");
    assert_eq!(keys(&next), ["3jqfcqzm4fa2j"]);

    let page = store.records(&collection, 10, None, true).expect("reads");
    assert_eq!(
        keys(&page),
        ["3jqfcqzm4fa2j", "3jqfcqzm4fb2j", "3jqfcqzm4fc2j"]
    );
    let next = store
        .records(&collection, 10, Some("3jqfcqzm4fb2j"), true)
        .expect("reads");
    assert_eq!(keys(&next), ["3jqfcqzm4fc2j"]);

    // The pages above are what keep the neighbors out, by naming a collection
    // entire. This is the other side of that: each neighbor still answers.
    for (neighbor, rkey) in [
        ("com.example.other", "3jqfcqzm4fd2j"),
        ("com.example.recordx", "3jqfcqzm4fe2j"),
    ] {
        let nsid = neighbor.parse::<Nsid>().expect("an NSID");
        let page = store.records(&nsid, 10, None, false).expect("reads");
        assert_eq!(keys(&page), [rkey], "{neighbor}");
    }

    let held = store
        .record(&collection, &"3jqfcqzm4fb2j".parse().expect("a record key"))
        .expect("reads")
        .expect("held");
    assert_eq!(repo::decode::<Ipld>(&held.value), Ok(post("second")));
    assert_eq!(
        store
            .record(&collection, &"3jqfcqzm4fz2j".parse().expect("a record key"))
            .expect("reads"),
        None
    );
}

#[test]
fn a_download_pages_through_every_block_once() {
    let mut store = Actor::memory(account()).expect("opens");
    let first = revision(&mut store, None, "3jqfcqzm4fa2j", 7);
    let second = revision(&mut store, Some(&first), "3jqfcqzm4fb2j", 5);
    revision(&mut store, Some(&second), "3jqfcqzm4fc2j", 9);

    let whole = walked(&store, None, 1000);
    assert_eq!(whole.len(), 21);

    // A page is where the read stops, not what it answers: the same blocks
    // come out in the same order whatever it holds, including the page that
    // ends on the last block.
    for limit in [1, 2, 4, 7, 20, 21] {
        assert_eq!(walked(&store, None, limit), whole, "{limit} to a page");
    }

    // A download since a revision leaves out what that revision wrote, across
    // pages as much as in one.
    let after = walked(&store, Some(&first.rev), 1000);
    assert_eq!(after.len(), 14);
    for limit in [1, 3, 14] {
        assert_eq!(walked(&store, Some(&first.rev), limit), after, "{limit}");
    }
    assert_eq!(walked(&store, Some(&second.rev), 4).len(), 9);
}

#[test]
fn the_blocks_a_caller_names_come_back_across_as_many_reads_as_it_takes() {
    let mut store = Actor::memory(account()).expect("opens");
    // Past the batch a read asks about at once, and not a multiple of it.
    revision(&mut store, None, "3jqfcqzm4fa2j", 1200);
    let held: Vec<repo::Cid> = walked(&store, None, 2000)
        .into_iter()
        .map(|(cid, _)| cid)
        .collect();
    assert_eq!(held.len(), 1200);

    let absent = [
        repo::cid_for(b"nothing is stored under this"),
        repo::cid_for(b"nor under this"),
    ];
    let mut asked = held[..600].to_vec();
    asked.push(absent[0]);
    asked.extend_from_slice(&held[600..]);
    asked.push(absent[1]);
    // A caller naming one twice is answered for it twice.
    asked.push(held[0]);

    let (blocks, missing) = store.blocks(&asked).expect("reads");
    assert_eq!(missing, absent);
    assert_eq!(blocks.len(), held.len());
    for cid in &held {
        assert_eq!(repo::cid_for(&blocks.get(cid).expect("stored")), *cid);
    }
}

#[test]
fn a_record_that_names_no_collection_is_refused_before_it_can_be_a_node() {
    let key = Keypair::generate(Algorithm::Secp256k1);
    let mut clock = TidClock::new();
    let (mut repo, blocks) = Repo::create(account(), &key, &mut clock).expect("creates");
    let mut store = Actor::memory(account()).expect("opens");
    store
        .commit(None, &at(&repo), genesis(&blocks), &[], &blobs())
        .expect("commits");

    // A record shaped like a node of the tree holding it. Taking one in would
    // let a later delete of it take the node, and nothing downstream could
    // tell the two apart.
    for shape in [
        Ipld::Map(BTreeMap::from([
            ("e".to_owned(), Ipld::List(Vec::new())),
            ("l".to_owned(), Ipld::Null),
        ])),
        Ipld::Map(BTreeMap::from([(
            "text".to_owned(),
            Ipld::String("no type at all".to_owned()),
        )])),
        Ipld::Map(BTreeMap::from([(
            "$type".to_owned(),
            Ipld::String("com.example.other".to_owned()),
        )])),
    ] {
        let refused = repo.apply(
            &store,
            &[Write::Create {
                collection: "com.example.record".parse().expect("an NSID"),
                rkey: "3jqfcqzm4fa2j".parse().expect("a record key"),
                record: shape,
            }],
            &key,
            &mut clock,
        );
        assert!(refused.is_err(), "took a record naming no collection");
    }
}

#[test]
fn a_read_sees_one_revision_even_while_another_lands() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let path = Directory::new(home.path()).actor_store(&account());
    let key = Keypair::generate(Algorithm::Secp256k1);
    let mut clock = TidClock::new();

    let (mut repo, blocks) = Repo::create(account(), &key, &mut clock).expect("creates");
    let mut store = Actor::open(&path, account()).expect("opens");
    store
        .commit(None, &at(&repo), genesis(&blocks), &[], &blobs())
        .expect("commits");
    let before = at(&repo);

    // A second handle on the same file, which is what a reader and a writer
    // are: the write lands partway through the read's two queries.
    let reader = Actor::open(&path, account()).expect("opens again");
    let held = reader
        .reading(|reader| {
            let root = reader.root()?.expect("a root");

            let written = repo
                .apply(
                    &store,
                    &[create("3jqfcqzm4fa2j", "first")],
                    &key,
                    &mut clock,
                )
                .expect("applies");
            store
                .commit(
                    Some(&before),
                    &at(&repo),
                    stored(&written),
                    &[indexed("3jqfcqzm4fa2j", "first")],
                    &blobs(),
                )
                .expect("commits");

            // Still the revision the read opened on, not the one that landed.
            Ok::<_, manapds::store::Error>((root, reader.root()?.expect("a root")))
        })
        .expect("reads");

    assert_eq!(held.0.cid, held.1.cid);
    assert_eq!(held.0.cid, before.cid);
    assert_ne!(at(&repo).cid, before.cid);
}
