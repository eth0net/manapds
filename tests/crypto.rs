//! The published crypto vectors, plus a round trip through this code.

use std::{fs, path::Path, str::FromStr};

use base64::Engine as _;
use manapds::crypto::{Algorithm, Error, Keypair, PublicKey};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignatureFixture {
    comment: String,
    message_base64: String,
    public_key_did: String,
    signature_base64: String,
    valid_signature: bool,
    tags: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DidKeyFixture {
    // The K-256 file writes the scalar as hex and the P-256 one as base58.
    private_key_bytes_hex: Option<String>,
    private_key_bytes_base58: Option<String>,
    public_did_key: String,
}

impl DidKeyFixture {
    fn private_key(&self) -> Vec<u8> {
        match (&self.private_key_bytes_hex, &self.private_key_bytes_base58) {
            (Some(hex), _) => hex::decode(hex).expect("hex"),
            (_, Some(base58)) => bs58::decode(base58).into_vec().expect("base58"),
            _ => panic!("fixture has no private key"),
        }
    }
}

#[test]
fn signatures() {
    let fixtures: Vec<SignatureFixture> = load("signature-fixtures.json");
    for fixture in fixtures {
        let key = PublicKey::from_str(&fixture.public_key_did).expect("a did:key");
        let message = base64(&fixture.message_base64);
        let signature = base64(&fixture.signature_base64);
        let result = key.verify(&message, &signature);
        assert_eq!(
            result.is_ok(),
            fixture.valid_signature,
            "{}",
            fixture.comment,
        );

        // Which way it is wrong, not only that it is: a DER signature read as
        // a high-S one would pass the check above.
        let expected = match fixture.tags.first().map(String::as_str) {
            Some("high-s") => Some(Error::HighS),
            Some("der-encoded") => Some(Error::MalformedSignature),
            _ => None,
        };
        assert_eq!(result.err(), expected, "{}", fixture.comment);
    }
}

#[test]
fn did_keys() {
    for (file, algorithm) in [
        ("w3c_didkey_K256.json", Algorithm::Secp256k1),
        ("w3c_didkey_P256.json", Algorithm::P256),
    ] {
        let fixtures: Vec<DidKeyFixture> = load(file);
        for fixture in fixtures {
            let bytes = fixture.private_key();
            let keypair = Keypair::from_bytes(algorithm, &bytes).expect("a scalar");
            assert_eq!(keypair.public_key().to_string(), fixture.public_did_key);
            assert_eq!(keypair.to_bytes(), bytes);

            let parsed = PublicKey::from_str(&fixture.public_did_key).expect("a did:key");
            assert_eq!(parsed, keypair.public_key());
        }
    }
}

#[test]
fn signs_what_it_verifies() {
    for algorithm in [Algorithm::P256, Algorithm::Secp256k1] {
        let keypair = Keypair::generate(algorithm);
        let key = keypair.public_key();
        let signature = keypair.sign(b"hello");

        assert_eq!(key.verify(b"hello", &signature), Ok(()));
        assert_eq!(key.verify(b"goodbye", &signature), Err(Error::BadSignature));
        assert_eq!(
            key.verify(b"hello", &signature[..63]),
            Err(Error::MalformedSignature),
        );
        assert_eq!(PublicKey::from_str(&key.to_string()), Ok(key));
    }
}

#[test]
fn rejects_what_is_not_a_did_key() {
    assert_eq!(PublicKey::from_str("did:plc:abc"), Err(Error::NotDidKey));
    assert_eq!(
        PublicKey::from_str("did:key:zzz"),
        Err(Error::UnsupportedKey)
    );
}

fn load<T: serde::de::DeserializeOwned>(file: &str) -> T {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/crypto")
        .join(file);
    let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_str(&text).expect("fixture")
}

fn base64(input: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(input)
        .expect("base64")
}
