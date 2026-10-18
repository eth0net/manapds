//! A signup against a directory that refuses, stalls, relents or never answers.

use super::*;

/// Every reserved key, by name, which is a `did:key`.
fn reservations(data: &Path) -> Vec<String> {
    let at = data.join("actors").join("reserved_keys");
    match std::fs::read_dir(at) {
        Ok(entries) => entries
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect(),
        Err(_) => Vec::new(),
    }
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

/// A directory that says nothing while the registration is in flight and then
/// comes back: it takes the tombstone and owns up to holding nothing.
///
/// `quiet` is how many of each kind of request come before it answers, which
/// is the two attempts and the two read backs the registration itself makes.
async fn relenting(quiet: usize) -> String {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("a port");
    let url = format!(
        "http://127.0.0.1:{}",
        listener.local_addr().expect("an address").port()
    );
    let asked = Arc::new(Mutex::new(Vec::new()));
    tokio::spawn(async move {
        let router = axum::Router::new().fallback(move |method: axum::http::Method| {
            let asked = Arc::clone(&asked);
            async move {
                let before = {
                    let mut asked = asked.lock().expect("nothing panicked while holding it");
                    asked.push(method.clone());
                    asked.iter().filter(|seen| **seen == method).count() - 1
                };
                if before < quiet {
                    return axum::http::StatusCode::BAD_GATEWAY;
                }
                if method == axum::http::Method::GET {
                    return axum::http::StatusCode::NOT_FOUND;
                }
                axum::http::StatusCode::OK
            }
        });
        let _ = axum::serve(listener, router).await;
    });
    url
}

/// A directory that accepts the connection and then says nothing, which is
/// what a signup is waiting on when the caller gives up on it. The flag goes
/// up when it is reached.
async fn silent() -> (String, Arc<AtomicBool>) {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("a port");
    let url = format!(
        "http://127.0.0.1:{}",
        listener.local_addr().expect("an address").port()
    );
    let reached = Arc::new(AtomicBool::new(false));
    let arrived = Arc::clone(&reached);
    tokio::spawn(async move {
        // Held, because dropping a socket would answer by closing it.
        let mut open = Vec::new();
        while let Ok((socket, _)) = listener.accept().await {
            arrived.store(true, Ordering::Relaxed);
            open.push(socket);
        }
    });
    (url, reached)
}

#[tokio::test]
async fn a_signup_leaves_the_operation_its_identifier_was_minted_from() {
    let (manager, data, _seen) = empty(false).await;

    let created = manager
        .create(&signup("alice.pds.test"))
        .await
        .expect("an account");

    let directory = store::Directory::new(data.path());
    let bytes = std::fs::read(directory.actor_op(&created.did)).expect("the operation");
    let operation: plc::Operation = serde_ipld_dagcbor::from_slice(&bytes).expect("an operation");
    assert_eq!(operation.did().expect("an identifier"), created.did);
    operation.verify().expect("the rotation key signed it");
}

#[tokio::test]
async fn a_key_is_reserved_for_as_long_as_no_account_names_it() {
    let data = tempfile::tempdir().expect("a directory");
    let midway: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&midway);
    let path = data.path().to_path_buf();
    let router = axum::Router::new().fallback(move || {
        let recorded = Arc::clone(&recorded);
        let path = path.clone();
        async move {
            recorded
                .lock()
                .expect("nothing panicked while holding it")
                .extend(reservations(&path));
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

    let config = common::config("pds.test", data.path(), &url);
    let manager = account::Manager::new(
        Arc::new(config),
        store::Accounts::memory().expect("a database"),
        store::Sequencer::memory().expect("a log"),
        tokens(),
    );
    let created = manager
        .create(&signup("alice.pds.test"))
        .await
        .expect("an account");

    // The reservation stands while the identifier is being registered, and
    // names the key the account ends up holding.
    let key = store::keys::read(&store::Directory::new(data.path()).actor_key(&created.did))
        .expect("a signing key");
    assert_eq!(
        midway.lock().expect("nothing panicked").clone(),
        vec![key.public_key().to_string()]
    );
    assert_eq!(reservations(data.path()), Vec::<String>::new());
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
            .await
            .expect("reads")
            .is_none()
    );
    assert_eq!(files(data.path()), Vec::<String>::new());
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
            .await
            .expect("reads")
            .is_some()
    );

    // The account keeping its key is what spends the reservation, so a copy of
    // one a live account signs with is left nowhere.
    assert_eq!(reservations(data.path()), Vec::<String>::new());
}

#[tokio::test]
async fn a_signup_whose_identifier_is_retired_is_taken_back_out() {
    let data = tempfile::tempdir().expect("a directory");
    let config = common::config("pds.test", data.path(), &relenting(2).await);
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

    // The tombstone was taken and the identifier resolves nowhere, so the
    // handle is somebody else's to claim.
    assert!(
        manager
            .resolve(&"alice.pds.test".parse().expect("a handle"))
            .await
            .expect("reads")
            .is_none()
    );
    assert_eq!(files(data.path()), Vec::<String>::new());
}

#[tokio::test]
async fn a_signup_the_caller_gives_up_on_mid_registration_is_left_standing() {
    let data = tempfile::tempdir().expect("a directory");
    let (plc, reached) = silent().await;
    let config = common::config("pds.test", data.path(), &plc);
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
    // Driven until the operation reaches the directory, which is where the
    // rollback stops being a discard. The deadline only stops a hang, since
    // scrypt makes the timing unpredictable.
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    while std::time::Instant::now() < deadline && !reached.load(Ordering::Relaxed) {
        tokio::select! {
            _ = &mut attempt => panic!("the directory answered after all"),
            () = tokio::time::sleep(Duration::from_millis(25)) => {}
        }
    }
    assert!(
        reached.load(Ordering::Relaxed),
        "the signup never got as far as the directory"
    );
    assert!(manager.resolve(&handle).await.expect("reads").is_some());

    // The caller hangs up. Nothing else is going to run on this account's behalf.
    drop(attempt);

    // Kept: hanging up says nothing about what the directory did with the
    // operation.
    assert!(manager.resolve(&handle).await.expect("reads").is_some());
    assert_ne!(files(data.path()), Vec::<String>::new());
}
