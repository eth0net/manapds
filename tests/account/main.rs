//! The account layer, against what the reference stores for the same inputs.
//!
//! One binary, a module per subject, and the fixtures every subject builds on.

mod directory;
mod log;
mod sessions;
mod signup;

#[path = "../common/mod.rs"]
mod common;

use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use manapds::account::{self, handle, password};
use manapds::crypto::{Algorithm, Keypair};
use manapds::plc;
use manapds::repo::{Ipld, Repo, Write};
use manapds::store;
use manapds::syntax::{Did, Nsid, RecordKey, TidClock};
use manapds::xrpc::auth::{Expired, Scope, Tokens};
use tempfile::TempDir;

fn tokens() -> Tokens {
    Tokens::new(common::SECRET, "did:web:pds.test")
}

/// Every operation the directory was handed, in the order it took them.
type Seen = Arc<Mutex<Vec<(String, String)>>>;

/// A directory on a port of its own, which takes whatever it is sent.
async fn directory() -> (String, Seen) {
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&seen);
    let router = axum::Router::new().fallback(move |uri: axum::http::Uri, body: String| {
        let recorded = Arc::clone(&recorded);
        async move {
            recorded
                .lock()
                .expect("nothing panicked while holding it")
                .push((uri.path().to_owned(), body));
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
    (url, seen)
}

/// An account on a server holding nothing else, with one app password.
///
/// Sign-ins answer as fast as they can: the delay is there to hide which
/// identifiers exist, which a test has no reason to hide.
fn manager() -> (account::Manager, Did, TempDir) {
    budgeted(Duration::ZERO)
}

/// The same, holding sign-ins to a budget, which is what testing the budget
/// itself needs.
fn budgeted(budget: Duration) -> (account::Manager, Did, TempDir) {
    let did: Did = "did:plc:mav423b24thku7ezkx7yaray".parse().expect("a DID");
    let data = tempfile::tempdir().expect("a directory");
    let mut accounts = store::Accounts::memory().expect("a database");
    accounts
        .create(&store::Registration {
            account: store::Account {
                did: did.clone(),
                handle: Some("alice.pds.test".parse().expect("a handle")),
                email: "Alice@Example.com".to_owned(),
                password_scrypt: password::hash("correct horse battery staple"),
            },
            root: root(),
            invite: None,
            session: None,
        })
        .expect("an account");
    accounts
        .create_app_password(
            &did,
            &store::AppPassword {
                name: "phone".to_owned(),
                privileged: false,
            },
            &password::app(&did, "abcd-efgh-ijkl-mnop"),
        )
        .expect("an app password");

    let config = Arc::new(common::config(
        "pds.test",
        data.path(),
        "http://127.0.0.1:1",
    ));
    let manager = account::Manager::new(
        config,
        accounts,
        store::Sequencer::memory().expect("a log"),
        tokens(),
    )
    .answering_in(budget);
    (manager, did, data)
}

/// Where a repository starts, which an account cannot be written without.
fn root() -> store::Root {
    let key = Keypair::generate(Algorithm::Secp256k1);
    let (repo, _) = Repo::create(
        "did:plc:mav423b24thku7ezkx7yaray".parse().expect("a DID"),
        &key,
        &mut TidClock::new(),
    )
    .expect("a repository");
    store::Root {
        cid: repo.cid(),
        rev: repo.rev().clone(),
    }
}

/// A server nobody has signed up to yet, and the directory it registers at.
async fn empty(invite_required: bool) -> (account::Manager, TempDir, Seen) {
    let (url, seen) = directory().await;
    let data = tempfile::tempdir().expect("a directory");
    let mut config = common::config("pds.test", data.path(), &url);
    config.invite_required = invite_required;
    let accounts = store::Accounts::memory().expect("a database");
    (
        account::Manager::new(
            Arc::new(config),
            accounts,
            store::Sequencer::memory().expect("a log"),
            tokens(),
        )
        .answering_in(Duration::ZERO),
        data,
        seen,
    )
}

fn signup(handle: &str) -> account::Signup {
    account::Signup {
        handle: handle.to_owned(),
        email: "alice@example.com".to_owned(),
        password: "correct horse battery staple".to_owned(),
        invite: None,
        recovery_key: None,
    }
}

/// One record in a collection this server has no lexicon for, which is every
/// collection as far as it is concerned.
fn record(rkey: &str, text: &str) -> Write {
    Write::Create {
        collection: "com.example.record".parse::<Nsid>().expect("an NSID"),
        rkey: rkey.parse::<RecordKey>().expect("a record key"),
        record: Ipld::Map(std::collections::BTreeMap::from([
            (
                "$type".to_owned(),
                Ipld::String("com.example.record".to_owned()),
            ),
            ("text".to_owned(), Ipld::String(text.to_owned())),
        ])),
    }
}

/// Every file under a directory, however deep, by name.
fn files(at: &Path) -> Vec<String> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(at).expect("a directory").flatten() {
        if entry.path().is_dir() {
            found.extend(files(&entry.path()));
        } else {
            found.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    found
}
