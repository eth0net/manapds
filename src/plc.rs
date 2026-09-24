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

/// The `type` of the operation that retires an identifier.
const TOMBSTONE: &str = "plc_tombstone";

/// Where an account's signing key is named.
const ATPROTO: &str = "atproto";

/// Where the repository host is named, and what that entry calls itself.
const PDS: &str = "atproto_pds";
const PDS_TYPE: &str = "AtprotoPersonalDataServer";

/// How much of the hash the identifier keeps.
const LENGTH: usize = 24;

/// How long the directory has to answer, across every exchange registering an
/// operation takes. Retiring one is two exchanges past that.
const TIMEOUT: Duration = Duration::from_secs(30);

/// What share of that budget one attempt may take, the rest being kept back
/// for the read backs; `docs/architecture.md` has why.
const ATTEMPT: u32 = 2;

/// How the rest is split: a read back, another attempt, and the read back that
/// decides whether the account behind the operation stands.
const STEPS: u32 = 3;

/// How much of a refusal is read back, since the message is for a log rather
/// than for anything that parses it.
const REFUSAL: usize = 4 * 1024;

/// How much of a document is read back, which only has to reach the one field
/// worth reading.
const DOCUMENT: usize = 64 * 1024;

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
    /// The directory could not be reached, so nothing it holds has changed.
    #[error("plc directory: {0}")]
    Unreachable(String),
    /// The directory was reached and would not say what it holds, so whether
    /// the operation landed is not known.
    #[error("plc directory would not say: {0}")]
    Uncertain(String),
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

/// The operation that retires an identifier, after which it resolves nowhere.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Tombstone {
    /// Always [`TOMBSTONE`].
    #[serde(rename = "type")]
    pub kind: String,
    /// The operation this one follows, addressed by its CID.
    pub prev: String,
    /// Base64url over the dag-cbor of everything above.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
}

impl Tombstone {
    /// Builds the operation that retires what `previous` created, and signs it.
    ///
    /// The CID is taken here rather than read back, which is what lets an
    /// identifier be retired without knowing whether it was ever taken;
    /// `docs/architecture.md` has why.
    ///
    /// # Errors
    ///
    /// If either operation will not encode, which neither of these can.
    pub fn create(previous: &Operation, rotation: &Keypair) -> Result<Self, Error> {
        let mut tombstone = Self {
            kind: TOMBSTONE.to_owned(),
            prev: repo::cid_for(&repo::encode(previous)?).to_string(),
            sig: None,
        };
        let signature = rotation.sign(&repo::encode(&tombstone)?);
        tombstone.sig = Some(BASE64.encode(signature));
        Ok(tombstone)
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
    /// If the operation will not encode, the directory cannot be reached, it
    /// refuses what it is sent, or it will not say what it holds.
    pub async fn send(&self, did: &Did, operation: &Operation) -> Result<(), Error> {
        match self.attempt(did, operation, self.answer / ATTEMPT).await {
            // Never connected, so it is not in there, and a read back that
            // cannot connect either says as much.
            Err(Error::Unreachable(_)) => self.confirm(did, operation, false).await,
            // Connected, so it may be in there whatever fails to say so.
            Err(Error::Uncertain(_)) => self.confirm(did, operation, true).await,
            // A refusal is the directory's decision, and sending it again
            // changes nothing.
            answered => answered,
        }
    }

    /// Retires an identifier a registration may have taken, and says whether
    /// the directory is left holding nothing under it.
    ///
    /// Only a tombstone the directory took proves anything: one it refused may
    /// have been refused because the operation it follows is still on its way
    /// in, and a read back agreeing is answering about that same moment.
    pub async fn retire(&self, did: &Did, tombstone: &Tombstone) -> bool {
        if self.attempt(did, tombstone, self.share()).await.is_err() {
            return false;
        }
        self.holds(did, self.share()).await == Held::No
    }

    /// What one exchange gets once the budget is down to the read backs.
    fn share(&self) -> Duration {
        self.answer / ATTEMPT / STEPS
    }

    /// Finds out what became of an operation whose answer never arrived, and
    /// sends it again if it never arrived either.
    ///
    /// `sent` says whether the first attempt reached the directory at all. An
    /// operation that never left cannot be in there, which is what lets a read
    /// back nobody answered still settle the question.
    async fn confirm(&self, did: &Did, operation: &Operation, sent: bool) -> Result<(), Error> {
        let each = self.share();
        if self.holds(did, each).await == Held::Yes {
            return Ok(());
        }
        let Err(again) = self.attempt(did, operation, each).await else {
            return Ok(());
        };
        match self.holds(did, each).await {
            Held::Yes => Ok(()),
            Held::No => Err(again),
            // Nothing answered, so only an operation neither attempt got out
            // settles it: a second attempt refused as a duplicate would be the
            // first one having landed after all.
            Held::Unknown if !sent && !matches!(again, Error::Uncertain(_)) => Err(again),
            Held::Unknown => Err(Error::Uncertain(format!(
                "asked twice what it holds and answered neither time: {again}"
            ))),
        }
    }

    /// What the directory has under the identifier, which can only ever be
    /// this operation; `docs/architecture.md` has why.
    ///
    /// The answer has to name the identifier back, since a directory is not
    /// the only thing that can answer at an address.
    async fn holds(&self, did: &Did, budget: Duration) -> Held {
        let Ok(request) = hyper::Request::builder()
            .method(hyper::Method::GET)
            .uri(format!("{}/{did}", self.url))
            .body(Full::new(Bytes::new()))
        else {
            return Held::Unknown;
        };
        tokio::time::timeout(budget, self.document(did, request))
            .await
            .unwrap_or(Held::Unknown)
    }

    /// The document under an identifier, read only far enough to see whose it
    /// is. Anything short of an answer is no answer.
    async fn document(&self, did: &Did, request: hyper::Request<Full<Bytes>>) -> Held {
        let Ok(response) = self.http.request(request).await else {
            return Held::Unknown;
        };
        if response.status() == hyper::StatusCode::NOT_FOUND {
            return Held::No;
        }
        if !response.status().is_success() {
            return Held::Unknown;
        }
        let Ok(body) = Limited::new(response.into_body(), DOCUMENT).collect().await else {
            return Held::Unknown;
        };
        match serde_json::from_slice::<Document>(&body.to_bytes()) {
            Ok(document) if document.id == did.as_str() => Held::Yes,
            _ => Held::Unknown,
        }
    }

    /// One operation, sent.
    async fn attempt<T: Serialize>(
        &self,
        did: &Did,
        operation: &T,
        budget: Duration,
    ) -> Result<(), Error> {
        let body =
            serde_json::to_vec(operation).map_err(|error| Error::Encode(error.to_string()))?;
        let request = hyper::Request::builder()
            .method(hyper::Method::POST)
            .uri(format!("{}/{did}", self.url))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(body)))
            .map_err(|error| Error::Unreachable(error.to_string()))?;
        self.within(request, budget).await
    }

    /// One exchange, held to what is left of the budget.
    async fn within(
        &self,
        request: hyper::Request<Full<Bytes>>,
        budget: Duration,
    ) -> Result<(), Error> {
        tokio::time::timeout(budget, self.exchange(request))
            .await
            .unwrap_or_else(|_| Err(Error::Uncertain("no answer in time".to_owned())))
    }

    /// The whole exchange, refusal and all.
    ///
    /// Reading the refusal is inside the budget because a directory that sends
    /// a status and then stops is the same wait as one that sends nothing.
    async fn exchange(&self, request: hyper::Request<Full<Bytes>>) -> Result<(), Error> {
        let response = self.http.request(request).await.map_err(|error| {
            // A connection never made cannot have carried the operation; one
            // that broke after it was made might have.
            if error.is_connect() {
                Error::Unreachable(error.to_string())
            } else {
                Error::Uncertain(error.to_string())
            }
        })?;

        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        let said = Limited::new(response.into_body(), REFUSAL)
            .collect()
            .await
            .map(|body| String::from_utf8_lossy(&body.to_bytes()).into_owned())
            .unwrap_or_default();
        if status.is_server_error() {
            // The directory failing to answer rather than answering, so what
            // it did with the operation is still open.
            return Err(Error::Uncertain(format!("{} {said}", status.as_u16())));
        }
        Err(Error::Refused(status.as_u16(), said))
    }
}

/// Just enough of a DID document to know whose it is.
#[derive(Deserialize)]
struct Document {
    id: String,
}

/// What the directory said when asked what it holds under an identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Held {
    /// The operation.
    Yes,
    /// Nothing.
    No,
    /// It would not say.
    Unknown,
}
