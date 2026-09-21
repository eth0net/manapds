//! `did:plc`: the operation that mints an identifier, and the identifier that
//! falls out of it.
//!
//! The identifier is a hash of the genesis operation, so a document is its own
//! proof — change a field and it belongs to a different account. Everything
//! after genesis is signed by a key the operation before it named, which is
//! why the rotation key outranks anything an account holds.

use std::collections::BTreeMap;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as BASE64};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::{Keypair, PublicKey};
use crate::repo;
use crate::syntax::{Did, Handle};

/// The `type` of every operation written since the legacy format.
const OPERATION: &str = "plc_operation";

/// Where an account's signing key is named.
const ATPROTO: &str = "atproto";

/// Where the repository host is named, and what that entry calls itself.
const PDS: &str = "atproto_pds";
const PDS_TYPE: &str = "AtprotoPersonalDataServer";

/// How much of the hash the identifier keeps.
const LENGTH: usize = 24;

/// Lowercase base32 without padding, which is how the hash is spelled.
const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// What went wrong building or reading an operation.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum Error {
    /// An operation that has no dag-cbor form, which nothing built here is.
    #[error("dag-cbor: {0}")]
    Encode(String),
    /// A signature no key the operation names accounts for.
    #[error("no rotation key signed this operation")]
    Signature,
    /// An operation no directory would have accepted.
    #[error("{0}")]
    Malformed(&'static str),
}

impl From<repo::Error> for Error {
    fn from(error: repo::Error) -> Self {
        Self::Encode(error.to_string())
    }
}

/// Somewhere an account is served from.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Service {
    /// What kind of service it is, which for a repository host is one string.
    #[serde(rename = "type")]
    pub kind: String,
    /// Its origin, scheme and all.
    pub endpoint: String,
}

/// An operation, as the directory takes it and hands it back.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Operation {
    /// Always [`OPERATION`] for anything this server writes.
    #[serde(rename = "type")]
    pub kind: String,
    /// The keys allowed to sign what comes next, most trusted first.
    pub rotation_keys: Vec<String>,
    /// Keys the account uses for something other than rotation, of which
    /// `atproto` signs its commits.
    pub verification_methods: BTreeMap<String, String>,
    /// The handles claimed, each as an `at://` URI.
    pub also_known_as: Vec<String>,
    /// Where the account is served from.
    pub services: BTreeMap<String, Service>,
    /// The operation this one follows, which genesis does not have.
    pub prev: Option<String>,
    /// Base64url over the dag-cbor of everything above.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
}

impl Operation {
    /// Builds the operation that creates an account, and signs it.
    ///
    /// Recovery keys are listed ahead of the server's own, because the
    /// directory settles a fork in favor of the earlier key: whoever holds one
    /// can take an account back off this server for 72 hours afterwards.
    ///
    /// # Errors
    ///
    /// If the operation will not encode, which none of these fields can
    /// arrange.
    pub fn create(
        handle: &Handle,
        pds: &str,
        signing_key: &PublicKey,
        recovery_keys: &[PublicKey],
        rotation: &Keypair,
    ) -> Result<Self, Error> {
        let mut rotation_keys: Vec<String> =
            recovery_keys.iter().map(PublicKey::to_string).collect();
        rotation_keys.push(rotation.public_key().to_string());

        let mut operation = Self {
            kind: OPERATION.to_owned(),
            rotation_keys,
            verification_methods: BTreeMap::from([(ATPROTO.to_owned(), signing_key.to_string())]),
            also_known_as: vec![format!("at://{handle}")],
            services: BTreeMap::from([(
                PDS.to_owned(),
                Service {
                    kind: PDS_TYPE.to_owned(),
                    endpoint: pds.to_owned(),
                },
            )]),
            prev: None,
            sig: None,
        };
        let signature = rotation.sign(&operation.payload()?);
        operation.sig = Some(BASE64.encode(signature));
        Ok(operation)
    }

    /// The identifier this operation mints.
    ///
    /// # Errors
    ///
    /// If the operation will not encode.
    #[expect(
        clippy::missing_panics_doc,
        reason = "24 base32 characters after a fixed prefix is a DID"
    )]
    pub fn did(&self) -> Result<Did, Error> {
        let mut identifier = base32(&Sha256::digest(repo::encode(self)?));
        identifier.truncate(LENGTH);
        Ok(format!("did:plc:{identifier}")
            .parse()
            .expect("a hash spelled in base32 parses"))
    }

    /// Checks the operation against the keys it carries.
    ///
    /// Genesis answers to nothing earlier, so agreeing with itself is the
    /// whole check — what stops it being rewritten is that the identifier
    /// would no longer be the one anybody resolved.
    ///
    /// # Errors
    ///
    /// If it is another kind of operation, carries no signature, or none of
    /// its rotation keys signed it.
    pub fn verify(&self) -> Result<(), Error> {
        if self.kind != OPERATION {
            return Err(Error::Malformed("not a plc operation"));
        }
        let signature = self
            .sig
            .as_deref()
            .ok_or(Error::Malformed("operation carries no signature"))?;
        let signature = BASE64.decode(signature).map_err(|_| Error::Signature)?;
        let payload = self.payload()?;
        self.rotation_keys
            .iter()
            .filter_map(|key| key.parse::<PublicKey>().ok())
            .any(|key| key.verify(&payload, &signature).is_ok())
            .then_some(())
            .ok_or(Error::Signature)
    }

    /// What the signature covers: the operation without it.
    fn payload(&self) -> Result<Vec<u8>, Error> {
        let mut unsigned = self.clone();
        unsigned.sig = None;
        Ok(repo::encode(&unsigned)?)
    }
}

fn base32(bytes: &[u8]) -> String {
    let mut encoded = String::new();
    let (mut buffer, mut bits) = (0u32, 0u32);
    for byte in bytes {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            encoded.push(char::from(ALPHABET[((buffer >> bits) & 31) as usize]));
        }
    }
    if bits > 0 {
        encoded.push(char::from(ALPHABET[((buffer << (5 - bits)) & 31) as usize]));
    }
    encoded
}
