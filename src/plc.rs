//! `did:plc`: the operation that mints an identifier, and the identifier that
//! falls out of it.
//!
//! The identifier is a hash of the genesis operation, so a document is its own
//! proof — change a field and it belongs to a different account. Everything
//! after genesis is signed by a key the operation before it named, which is
//! why the rotation key outranks anything an account holds.

use std::collections::BTreeMap;
use std::time::Duration;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as BASE64};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::header;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::{Keypair, PublicKey, base32};
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

/// How long the directory has to answer before the account creation that is
/// waiting on it fails.
const TIMEOUT: Duration = Duration::from_secs(30);

/// How much of a refusal is read back, since the message is for a log rather
/// than for anything that parses it.
const REFUSAL: usize = 4 * 1024;

/// What went wrong building or reading an operation.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum Error {
    /// An operation with no encoding, which nothing built here is.
    #[error("encoding an operation: {0}")]
    Encode(String),
    /// A signature no key the operation names accounts for.
    #[error("no rotation key signed this operation")]
    Signature,
    /// An operation no directory would have accepted.
    #[error("{0}")]
    Malformed(&'static str),
    /// The directory could not be reached, or did not answer in time.
    #[error("plc directory: {0}")]
    Unreachable(String),
    /// The directory was reached and said no.
    #[error("plc directory refused the operation: {0} {1}")]
    Refused(u16, String),
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

/// The directory operations are registered at.
///
/// An identifier nothing has been sent to resolves nowhere, so an account is
/// not an account until this has been called for it.
#[derive(Clone, Debug)]
pub struct Client {
    url: String,
    answer: Duration,
    http: hyper_util::client::legacy::Client<HttpsConnector<HttpConnector>, Full<Bytes>>,
}

impl Client {
    /// Points at a directory.
    #[must_use]
    pub fn new(url: impl Into<String>) -> Self {
        let tls = hyper_rustls::HttpsConnectorBuilder::new()
            .with_webpki_roots()
            // Plain HTTP as well, because a directory run for a test is served
            // over it and the address is configuration either way.
            .https_or_http()
            .enable_http1()
            .build();
        Self {
            url: url.into().trim_end_matches('/').to_owned(),
            answer: TIMEOUT,
            http: hyper_util::client::legacy::Client::builder(TokioExecutor::new()).build(tls),
        }
    }

    /// Gives the directory this long rather than the usual, which is what a
    /// test waiting on one that never answers wants.
    #[must_use]
    pub fn waiting(mut self, answer: Duration) -> Self {
        self.answer = answer;
        self
    }

    /// Registers an operation against an identifier.
    ///
    /// # Errors
    ///
    /// If the operation will not encode, the directory cannot be reached, or
    /// it refuses what it is sent.
    pub async fn send(&self, did: &Did, operation: &Operation) -> Result<(), Error> {
        let body =
            serde_json::to_vec(operation).map_err(|error| Error::Encode(error.to_string()))?;
        let request = hyper::Request::builder()
            .method(hyper::Method::POST)
            .uri(format!("{}/{did}", self.url))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(body)))
            .map_err(|error| Error::Unreachable(error.to_string()))?;

        tokio::time::timeout(self.answer, self.exchange(request))
            .await
            .map_err(|_| Error::Unreachable("no answer in time".to_owned()))?
    }

    /// The whole exchange, refusal and all.
    ///
    /// Reading the refusal is inside the budget because a directory that sends
    /// a status and then stops is the same wait as one that sends nothing.
    async fn exchange(&self, request: hyper::Request<Full<Bytes>>) -> Result<(), Error> {
        let response = self
            .http
            .request(request)
            .await
            .map_err(|error| Error::Unreachable(error.to_string()))?;

        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        let said = Limited::new(response.into_body(), REFUSAL)
            .collect()
            .await
            .map(|body| String::from_utf8_lossy(&body.to_bytes()).into_owned())
            .unwrap_or_default();
        Err(Error::Refused(status.as_u16(), said))
    }
}
