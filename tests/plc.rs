//! `did:plc`, against an operation the reference implementation wrote.

use manapds::crypto::{Algorithm, Keypair, PublicKey};
use manapds::plc::Operation;
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
