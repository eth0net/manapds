//! Blobs on disk: what holds one, what sweeps one, and what a commit says it took.

use manapds::store::blobs;

use super::*;

#[test]
fn a_blob_is_stored_under_the_cid_of_its_bytes() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let blobs = Directory::new(home.path()).blobs();
    let bytes = b"not really a picture";
    let cid = blobs::cid_for(bytes);

    // An upload holds nothing, so it is not yet served from its own name.
    blobs
        .put(&account(), "somekey", &cid, bytes)
        .expect("stores");
    assert!(!blobs.has(&account(), &cid));

    // A record claiming it is what puts it where it is served from, and the
    // upload stays until that commit is on disk.
    blobs.claim(&account(), "somekey", &cid).expect("claims");
    assert!(blobs.has(&account(), &cid));
    assert_eq!(blobs.get(&account(), &cid).expect("reads"), bytes);
    blobs
        .claim(&account(), "somekey", &cid)
        .expect("claiming twice is claiming once");
    blobs
        .delete_upload(&account(), "somekey")
        .expect("clears the upload");
    assert_eq!(blobs.get(&account(), &cid).expect("reads"), bytes);

    // The reference lays them out as <blocks>/<did>/<cid>.
    assert_eq!(
        blobs.path(&account(), &cid),
        home.path()
            .join("blocks")
            .join("did:plc:4cjoyc3cgpal7gnrpzyjhnv3")
            .join(cid.to_string())
    );

    // Upstream spells the temporary directory "tempt", and a blob lands there
    // before its CID is known.
    assert_eq!(
        blobs.temp_path(&account(), "somekey"),
        home.path()
            .join("blocks")
            .join("tempt")
            .join("did:plc:4cjoyc3cgpal7gnrpzyjhnv3")
            .join("somekey")
    );

    blobs.delete(&account(), &cid).expect("deletes");
    assert!(!blobs.has(&account(), &cid));
    blobs
        .delete(&account(), &cid)
        .expect("deleting twice is quiet");
}

#[test]
fn bytes_that_are_not_their_cid_are_refused() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let blobs = Directory::new(home.path()).blobs();
    let cid = blobs::cid_for(b"one thing");

    assert!(
        blobs
            .put(&account(), "somekey", &cid, b"another thing")
            .is_err()
    );
    assert!(!blobs.has(&account(), &cid));
}

#[test]
fn quarantine_hides_a_blob_without_losing_it() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let blobs = Directory::new(home.path()).blobs();
    let bytes = b"not really a picture";
    let cid = blobs::cid_for(bytes);
    blobs
        .put(&account(), "somekey", &cid, bytes)
        .expect("stores");
    blobs.claim(&account(), "somekey", &cid).expect("claims");

    blobs.quarantine(&account(), &cid).expect("quarantines");
    assert!(!blobs.has(&account(), &cid));
    assert!(blobs.quarantine_path(&account(), &cid).is_file());

    blobs.unquarantine(&account(), &cid).expect("restores");
    assert!(blobs.has(&account(), &cid));
    assert_eq!(blobs.get(&account(), &cid).expect("reads"), bytes);
}

#[test]
fn a_stored_blob_leaves_nothing_beside_it_and_no_way_in() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let blobs = Directory::new(home.path()).blobs();
    let bytes = b"a blob, written whole or not at all";
    let cid = blobs::cid_for(bytes);
    blobs
        .put(&account(), "somekey", &cid, bytes)
        .expect("stores");
    blobs.claim(&account(), "somekey", &cid).expect("claims");

    let path = blobs.path(&account(), &cid);
    let parent = path.parent().expect("a parent");
    let held: Vec<_> = std::fs::read_dir(parent)
        .expect("reads")
        .map(|entry| entry.expect("an entry").file_name())
        .collect();
    assert_eq!(held, [path.file_name().expect("a name")]);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(parent)
            .expect("reads")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700, "{mode:o}");
    }
}

#[test]
fn a_blob_that_cannot_be_put_in_place_leaves_nothing_behind() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let blobs = Directory::new(home.path()).blobs();
    let bytes = b"a blob that never lands";
    let cid = blobs::cid_for(bytes);

    // Something already occupies the name, and is not a file, so the move onto
    // it cannot succeed.
    let path = blobs.temp_path(&account(), "somekey");
    std::fs::create_dir_all(&path).expect("a directory in the way");

    blobs
        .put(&account(), "somekey", &cid, bytes)
        .expect_err("cannot land");

    let parent = path.parent().expect("a parent");
    let held: Vec<_> = std::fs::read_dir(parent)
        .expect("reads")
        .map(|entry| entry.expect("an entry").file_name())
        .collect();
    assert_eq!(held, [path.file_name().expect("a name")]);
}

#[test]
fn an_upload_file_outlives_its_row_only_as_long_as_the_window() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let blobs = Directory::new(home.path()).blobs();
    blobs
        .put(&account(), "heldkey", &blobs::cid_for(b"held"), b"held")
        .expect("stores");
    blobs
        .put(
            &account(),
            "strandedkey",
            &blobs::cid_for(b"loose"),
            b"loose",
        )
        .expect("stores");
    let held = std::collections::HashSet::from(["heldkey".to_owned()]);

    // An upload arrives before the row naming it, so one written since the
    // cutoff is not the sweep's to take.
    assert_eq!(
        blobs
            .sweep_uploads(
                &account(),
                &held,
                jiff::Timestamp::now() - jiff::SignedDuration::from_hours(1)
            )
            .expect("sweeps"),
        Vec::<String>::new()
    );
    assert!(blobs.temp_path(&account(), "strandedkey").is_file());

    assert_eq!(
        blobs
            .sweep_uploads(
                &account(),
                &held,
                jiff::Timestamp::now() + jiff::SignedDuration::from_hours(1)
            )
            .expect("sweeps"),
        vec!["strandedkey".to_owned()]
    );
    assert!(blobs.temp_path(&account(), "heldkey").is_file());
    assert!(!blobs.temp_path(&account(), "strandedkey").exists());
}

#[test]
fn the_accounts_with_blobs_on_disk_are_the_ones_named() {
    let other: Did = "did:plc:mav423b24thku7ezkx7yaray".parse().expect("a DID");
    let home = tempfile::tempdir().expect("a temporary directory");
    let blobs = Directory::new(home.path()).blobs();
    let cid = blobs::cid_for(b"blob");
    blobs
        .put(&account(), "akey", &cid, b"blob")
        .expect("stores");
    blobs.put(&other, "bkey", &cid, b"blob").expect("stores");
    blobs.claim(&other, "bkey", &cid).expect("claims");
    blobs.quarantine(&other, &cid).expect("quarantines");

    assert_eq!(blobs.accounts().expect("reads"), vec![account(), other]);
}

#[test]
fn a_sweep_of_an_account_that_has_uploaded_nothing_finds_nothing() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let blobs = Directory::new(home.path()).blobs();
    assert_eq!(
        blobs
            .sweep_uploads(
                &account(),
                &std::collections::HashSet::new(),
                jiff::Timestamp::now() + jiff::SignedDuration::from_hours(1)
            )
            .expect("sweeps"),
        Vec::<String>::new()
    );
}

#[test]
fn every_key_an_upload_is_held_under_is_named() {
    let store = Actor::memory(account()).expect("opens");
    let blob = Blob {
        cid: blobs::cid_for(b"held"),
        mime: "image/png".to_owned(),
        size: 4,
    };
    store.add_blob(&blob, "firstkey").expect("writes");
    assert_eq!(
        store.upload_keys().expect("reads"),
        std::collections::HashSet::from(["firstkey".to_owned()])
    );

    // A second upload of the same bytes moves the row, and the key it moved
    // off is what nothing names any more.
    store.add_blob(&blob, "secondkey").expect("writes again");
    assert_eq!(
        store.upload_keys().expect("reads"),
        std::collections::HashSet::from(["secondkey".to_owned()])
    );
}

#[test]
fn a_blob_nothing_ever_named_is_swept_and_one_a_record_holds_is_not() {
    let store = Actor::memory(account()).expect("opens");
    let held = Blob {
        cid: manapds::store::blobs::cid_for(b"held"),
        mime: "image/png".to_owned(),
        size: 4,
    };
    let loose = Blob {
        cid: manapds::store::blobs::cid_for(b"loose"),
        mime: "image/png".to_owned(),
        size: 5,
    };
    // Both uploaded, so a record claiming one has something to claim.
    let home = tempfile::tempdir().expect("a temporary directory");
    let blobs = Directory::new(home.path()).blobs();
    blobs
        .put(&account(), "heldkey", &held.cid, b"held")
        .expect("stores");
    blobs
        .put(&account(), "loosekey", &loose.cid, b"loose")
        .expect("stores");
    store.add_blob(&held, "heldkey").expect("writes");
    store.add_blob(&loose, "loosekey").expect("writes");

    // Nothing is old enough yet, which is what the window is for.
    assert_eq!(
        store
            .sweep_unclaimed(jiff::Timestamp::now() - jiff::SignedDuration::from_hours(1))
            .expect("sweeps"),
        Vec::<String>::new()
    );

    // One of them is claimed by a record, the way a write claims it.
    let key = Keypair::generate(Algorithm::Secp256k1);
    let mut clock = TidClock::new();
    let (repo, mut blocks) = Repo::create(account(), &key, &mut clock).expect("creates");
    let record = blocks.add(&post("first")).expect("encodes");
    let mut store = store;
    store
        .commit(
            None,
            &at(&repo),
            genesis(&blocks),
            &[Indexed::Put {
                collection: "com.example.record".parse().expect("an NSID"),
                rkey: "3jqfcqzm4fc2j".parse().expect("a record key"),
                cid: record,
                links: Vec::new(),
                blobs: vec![held.clone()],
            }],
            &blobs,
        )
        .expect("commits");

    let waited = jiff::Timestamp::now() + jiff::SignedDuration::from_hours(1);
    assert_eq!(
        store.sweep_unclaimed(waited).expect("sweeps"),
        vec!["loosekey".to_owned()]
    );
    store.add_blob(&loose, "loosekey").expect("writes again");
    assert_eq!(
        store
            .sweep_unclaimed(jiff::Timestamp::now() - jiff::SignedDuration::from_hours(1))
            .expect("sweeps"),
        Vec::<String>::new()
    );

    // Past the window, the one nothing named goes and the held one stays.
    let swept = store
        .sweep_unclaimed(jiff::Timestamp::now() + jiff::SignedDuration::from_hours(1))
        .expect("sweeps");
    assert_eq!(swept, vec!["loosekey".to_owned()]);
    assert_eq!(store.blob(&held.cid).expect("reads"), Some(held));
    assert_eq!(store.blob(&loose.cid).expect("reads"), None);
}

#[test]
fn a_commit_hands_back_the_uploads_it_took_and_the_blobs_it_let_go() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let blobs = Directory::new(home.path()).blobs();
    let blob = Blob {
        cid: manapds::store::blobs::cid_for(b"held"),
        mime: "image/png".to_owned(),
        size: 4,
    };
    blobs
        .put(&account(), "heldkey", &blob.cid, b"held")
        .expect("stores");

    let mut store = Actor::memory(account()).expect("opens");
    store.add_blob(&blob, "heldkey").expect("writes");

    let key = Keypair::generate(Algorithm::Secp256k1);
    let mut clock = TidClock::new();
    let (repo, mut blocks) = Repo::create(account(), &key, &mut clock).expect("creates");
    let record = blocks.add(&post("first")).expect("encodes");
    let rkey = "3jqfcqzm4fc2j".parse().expect("a record key");
    let collection = "com.example.record".parse().expect("an NSID");
    let taken = store
        .commit(
            None,
            &at(&repo),
            genesis(&blocks),
            &[Indexed::Put {
                collection,
                rkey,
                cid: record,
                links: Vec::new(),
                blobs: vec![blob.clone()],
            }],
            &blobs,
        )
        .expect("commits")
        .expect("lands");

    // Without these the upload's name is never dropped, and because it is a
    // link to the same bytes the blob is served from, nothing can free them.
    assert_eq!(taken.taken, vec!["heldkey".to_owned()]);
    assert_eq!(taken.orphaned, []);

    let let_go = store
        .commit(
            Some(&at(&repo)),
            &at(&repo),
            genesis(&blocks),
            &[Indexed::Delete {
                collection: "com.example.record".parse().expect("an NSID"),
                rkey: "3jqfcqzm4fc2j".parse().expect("a record key"),
            }],
            &blobs,
        )
        .expect("commits")
        .expect("lands");

    assert_eq!(let_go.orphaned, vec![blob.cid]);
}

#[test]
fn a_blob_held_again_is_as_new_as_the_record_that_held_it() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let blobs = Directory::new(home.path()).blobs();
    let bytes = b"not really a picture";
    let cid = manapds::store::blobs::cid_for(bytes);

    blobs.put(&account(), "first", &cid, bytes).expect("stores");
    assert!(blobs.claim(&account(), "first", &cid).expect("claims"));

    // A revision that never landed leaves the file linked and nothing holding
    // it, so it ages where it lies.
    let served = blobs.path(&account(), &cid);
    let long_ago = std::time::SystemTime::now() - std::time::Duration::from_hours(48);
    std::fs::File::options()
        .write(true)
        .open(&served)
        .expect("opens")
        .set_modified(long_ago)
        .expect("ages it");

    // Claimed again, it is a blob in use, and a reconcile that reads age must
    // not take it for one nothing came back for.
    blobs
        .put(&account(), "second", &cid, bytes)
        .expect("stores");
    assert!(
        !blobs
            .claim(&account(), "second", &cid)
            .expect("claims again")
    );

    let since = std::fs::metadata(&served)
        .expect("reads")
        .modified()
        .expect("a time")
        .elapsed()
        .expect("not ahead");
    assert!(since < std::time::Duration::from_secs(60), "{since:?}");
}
