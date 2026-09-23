//! `did:plc`, against an operation the reference implementation wrote.

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::http::{StatusCode, Uri};
use manapds::crypto::{Algorithm, Keypair, PublicKey};
use manapds::plc::{Client, Error, Operation};
use manapds::syntax::Handle;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Fixture {
    did: String,
    signing_key: String,
    rotation_key: String,
    rotation_scalar: String,
    handle: String,
    pds: String,
    operation: Operation,
}

fn fixture() -> (Fixture, Keypair) {
    let fixture: Fixture =
        serde_json::from_str(include_str!("fixtures/plc/genesis.json")).expect("the fixture");
    let rotation = Keypair::from_bytes(
        Algorithm::Secp256k1,
        &hex::decode(&fixture.rotation_scalar).expect("hex"),
    )
    .expect("a key");
    assert_eq!(rotation.public_key().to_string(), fixture.rotation_key);
    (fixture, rotation)
}

fn create(fixture: &Fixture, rotation: &Keypair) -> Operation {
    Operation::create(
        &Handle::normalize(&fixture.handle).expect("a handle"),
        &fixture.pds,
        &fixture.signing_key.parse::<PublicKey>().expect("a key"),
        &[],
        rotation,
    )
    .expect("builds")
}

#[test]
fn genesis_is_what_the_reference_writes() {
    let (fixture, rotation) = fixture();

    // Both sides sign deterministically, so every byte matches and not merely
    // the shape.
    assert_eq!(create(&fixture, &rotation), fixture.operation);
    assert_eq!(
        fixture.operation.did().expect("hashes").as_str(),
        fixture.did
    );
    fixture.operation.verify().expect("the key signed it");
}

#[test]
fn a_recovery_key_outranks_the_server() {
    let (fixture, rotation) = fixture();
    let recovery = Keypair::generate(Algorithm::Secp256k1).public_key();
    let operation = Operation::create(
        &Handle::normalize(&fixture.handle).expect("a handle"),
        &fixture.pds,
        &fixture.signing_key.parse::<PublicKey>().expect("a key"),
        std::slice::from_ref(&recovery),
        &rotation,
    )
    .expect("builds");

    assert_eq!(
        operation.rotation_keys,
        vec![recovery.to_string(), rotation.public_key().to_string()]
    );
    operation.verify().expect("the server still signed it");
    assert_ne!(operation.did().expect("hashes").as_str(), fixture.did);
}

#[test]
fn an_edited_operation_is_a_different_account() {
    let (fixture, rotation) = fixture();
    let mut operation = create(&fixture, &rotation);
    operation.also_known_as = vec!["at://bob.test".to_owned()];

    assert_ne!(operation.did().expect("hashes").as_str(), fixture.did);
    assert!(operation.verify().is_err());
}

#[test]
fn an_operation_of_another_kind_is_refused() {
    let (fixture, rotation) = fixture();
    let mut operation = create(&fixture, &rotation);
    operation.kind = "plc_tombstone".to_owned();

    assert!(operation.verify().is_err());
}

/// What a directory was sent: the path and the body, in order.
type Seen = Arc<Mutex<Vec<(String, String)>>>;

/// A directory on a port of its own, which refuses anything whose path says
/// to.
async fn directory() -> (String, Seen) {
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&seen);
    let router = Router::new().fallback(move |uri: Uri, body: String| {
        let recorded = Arc::clone(&recorded);
        async move {
            if uri.path().contains("refused") {
                return (StatusCode::BAD_REQUEST, "Invalid signature on op");
            }
            recorded
                .lock()
                .expect("nothing panicked while holding it")
                .push((uri.path().to_owned(), body));
            (StatusCode::OK, "")
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

#[tokio::test]
async fn an_operation_is_registered_under_the_identifier_it_mints() {
    let (fixture, rotation) = fixture();
    let operation = create(&fixture, &rotation);
    let did = operation.did().expect("hashes");
    let (url, seen) = directory().await;

    Client::new(&url)
        .send(&did, &operation)
        .await
        .expect("sends");

    let seen = seen.lock().expect("nothing panicked while holding it");
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].0, format!("/{did}"));
    // What arrives is the operation itself, signature and all, since the
    // directory checks it before it stores it.
    let sent: Operation = serde_json::from_str(&seen[0].1).expect("json");
    assert_eq!(sent, operation);
}

#[tokio::test]
async fn a_directory_that_refuses_says_so() {
    let (fixture, rotation) = fixture();
    let operation = create(&fixture, &rotation);
    let refused: manapds::syntax::Did = "did:plc:refused".parse().expect("a DID");
    let (url, _) = directory().await;

    let error = Client::new(&url)
        .send(&refused, &operation)
        .await
        .expect_err("refused");
    assert!(
        matches!(&error, Error::Refused(400, said) if said.contains("Invalid signature")),
        "{error}"
    );
}

#[tokio::test]
async fn a_directory_that_is_not_there_is_not_a_signature_problem() {
    let (fixture, rotation) = fixture();
    let operation = create(&fixture, &rotation);
    let did = operation.did().expect("hashes");

    // Bound and dropped, so the port is one nothing is listening on.
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("a port");
    let url = format!(
        "http://127.0.0.1:{}",
        listener.local_addr().expect("an address").port()
    );
    drop(listener);

    let error = Client::new(&url)
        .send(&did, &operation)
        .await
        .expect_err("nothing there");
    assert!(matches!(error, Error::Unreachable(_)), "{error}");
}

/// A directory that sends a refusal and then holds the body open.
///
/// Raw sockets rather than axum, because the point is a response no HTTP
/// server would produce on purpose.
async fn stalling() -> String {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("a port");
    let url = format!(
        "http://127.0.0.1:{}",
        listener.local_addr().expect("an address").port()
    );
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                // A length that is promised and never sent.
                if socket.writable().await.is_ok() {
                    let _ =
                        socket.try_write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 64\r\n\r\n");
                }
                std::future::pending::<()>().await;
            });
        }
    });
    url
}

#[tokio::test]
async fn a_refusal_that_never_finishes_arriving_gives_up() {
    let (fixture, rotation) = fixture();
    let operation = create(&fixture, &rotation);
    let did = operation.did().expect("hashes");
    let url = stalling().await;

    let error = Client::new(&url)
        .waiting(std::time::Duration::from_millis(250))
        .send(&did, &operation)
        .await
        .expect_err("gives up");

    assert!(matches!(error, Error::Unreachable(_)), "{error:?}");
}
