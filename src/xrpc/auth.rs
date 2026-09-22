//! Session tokens: what signing in hands out, and what a request is read back
//! from.
//!
//! The tokens are HS256 JWTs under one server-wide secret, because that is
//! what the reference issues and a takeover has to keep every session alive.
//! `typ` separates the two kinds, so an access token cannot be spent as a
//! refresh token or the other way about.

use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::{
    extract::{FromRef, FromRequestParts, Request},
    http::{HeaderMap, HeaderValue, header, request::Parts},
    middleware::Next,
    response::Response,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as BASE64};
use hmac::{Hmac, KeyInit, Mac};
use jiff::{SignedDuration, Timestamp};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::syntax::Did;

use super::Error;

/// How long an access token is good for.
pub const ACCESS_LIFETIME: SignedDuration = SignedDuration::from_mins(120);

/// How long a refresh token is good for.
pub const REFRESH_LIFETIME: SignedDuration = SignedDuration::from_hours(90 * 24);

/// What a token is allowed to do.
///
/// The names are lexicon-shaped but are this server's own: they travel only in
/// its tokens and mean nothing to anything it talks to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Scope {
    /// A session from a password, which may do anything.
    Access,
    /// The other half of that session, which may only be exchanged.
    Refresh,
    /// A session from an app password, which may not touch the account.
    AppPassword,
    /// An app password session trusted with a little more.
    PrivilegedAppPassword,
    /// An account still waiting to be let in.
    SignupQueued,
    /// An account that has been taken down.
    TakenDown,
}

impl Scope {
    /// A full session, or an app password trusted with more than posting.
    pub const PRIVILEGED: [Self; 2] = [Self::Access, Self::PrivilegedAppPassword];

    /// Any session a client signs in with, which is what most methods take.
    pub const STANDARD: [Self; 3] = [Self::Access, Self::PrivilegedAppPassword, Self::AppPassword];

    /// How the scope travels in a token.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Access => "com.atproto.access",
            Self::Refresh => "com.atproto.refresh",
            Self::AppPassword => "com.atproto.appPass",
            Self::PrivilegedAppPassword => "com.atproto.appPassPrivileged",
            Self::SignupQueued => "com.atproto.signupQueued",
            Self::TakenDown => "com.atproto.takendown",
        }
    }
}

/// A scope string this server does not issue.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("not a scope this server issues")]
pub struct UnknownScope;

impl FromStr for Scope {
    type Err = UnknownScope;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "com.atproto.access" => Ok(Self::Access),
            "com.atproto.refresh" => Ok(Self::Refresh),
            "com.atproto.appPass" => Ok(Self::AppPassword),
            "com.atproto.appPassPrivileged" => Ok(Self::PrivilegedAppPassword),
            "com.atproto.signupQueued" => Ok(Self::SignupQueued),
            "com.atproto.takendown" => Ok(Self::TakenDown),
            _ => Err(UnknownScope),
        }
    }
}

/// Whether a refresh token past its expiry is still read.
///
/// A client that has been away longer than the token lives still has to be
/// able to end its session, which is the one thing an expired one may do.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Expired {
    /// Refuse it, which is what exchanging one for a new session does.
    Refuse,
    /// Read it anyway.
    Allow,
}

impl std::fmt::Display for Scope {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A verified access token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Access {
    /// Whose session it is.
    pub did: Did,
    /// What that session may do.
    pub scope: Scope,
}

/// A verified refresh token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Refresh {
    /// Whose session it is.
    pub did: Did,
    /// The `jti`, which is the row the account database holds it under.
    pub id: String,
}

/// The secret every session token is signed under, and the service it names
/// as its audience.
#[derive(Clone)]
pub struct Tokens {
    key: Arc<[u8]>,
    audience: Arc<str>,
}

impl std::fmt::Debug for Tokens {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Tokens")
            .field("audience", &&*self.audience)
            .finish_non_exhaustive()
    }
}

impl Tokens {
    /// Holds the secret and the DID tokens are minted for.
    ///
    /// Cloned once per authenticated request, so both are shared rather than
    /// copied: the secret has no business being scattered across the heap.
    pub fn new(secret: impl AsRef<[u8]>, audience: impl AsRef<str>) -> Self {
        Self {
            key: Arc::from(secret.as_ref()),
            audience: Arc::from(audience.as_ref()),
        }
    }

    /// Mints an access token.
    #[must_use]
    pub fn access(&self, did: &Did, scope: Scope) -> String {
        self.access_for(did, scope, ACCESS_LIFETIME)
    }

    /// Mints an access token good for something other than the usual.
    #[must_use]
    pub fn access_for(&self, did: &Did, scope: Scope, lifetime: SignedDuration) -> String {
        self.mint("at+jwt", did, scope, None, lifetime)
    }

    /// Mints a refresh token under an id the account database can find it by.
    #[must_use]
    pub fn refresh(&self, did: &Did, id: &str) -> String {
        self.mint(
            "refresh+jwt",
            did,
            Scope::Refresh,
            Some(id.to_owned()),
            REFRESH_LIFETIME,
        )
    }

    /// Reads an access token back, holding it to one of the scopes given.
    ///
    /// # Errors
    ///
    /// If it is not a token this server signed, has expired, or carries a
    /// scope not in the list.
    pub fn verify_access(&self, token: &str, scopes: &[Scope]) -> Result<Access, Error> {
        let claims = self.verify(token, "at+jwt", scopes, Expired::Refuse)?;
        Ok(Access {
            did: did(&claims.sub)?,
            scope: scope(&claims.scope)?,
        })
    }

    /// Reads a refresh token back.
    ///
    /// # Errors
    ///
    /// If it is not a token this server signed, carries another scope, or has
    /// no `jti` to find the stored session by.
    pub fn verify_refresh(&self, token: &str, expired: Expired) -> Result<Refresh, Error> {
        let claims = self.verify(token, "refresh+jwt", &[Scope::Refresh], expired)?;
        let id = claims.jti.ok_or_else(|| {
            Error::auth_required("Unexpected missing refresh token id").named("MissingTokenId")
        })?;
        Ok(Refresh {
            did: did(&claims.sub)?,
            id,
        })
    }

    fn mint(
        &self,
        typ: &str,
        did: &Did,
        scope: Scope,
        jti: Option<String>,
        lifetime: SignedDuration,
    ) -> String {
        let now = Timestamp::now();
        let claims = Claims {
            scope: scope.to_string(),
            sub: did.as_str().to_owned(),
            aud: self.audience.to_string(),
            iat: now.as_second(),
            exp: (now + lifetime).as_second(),
            jti,
            lxm: None,
            cnf: None,
        };
        let header = Header {
            alg: "HS256".to_owned(),
            typ: typ.to_owned(),
        };
        let signed = format!("{}.{}", part(&header), part(&claims));
        let signature = BASE64.encode(self.mac(signed.as_bytes()).finalize().into_bytes());
        format!("{signed}.{signature}")
    }

    fn verify(
        &self,
        token: &str,
        typ: &str,
        scopes: &[Scope],
        expired: Expired,
    ) -> Result<Claims, Error> {
        let (signed, signature) = token.rsplit_once('.').ok_or_else(unverifiable)?;
        let (header, payload) = signed.split_once('.').ok_or_else(unverifiable)?;
        if payload.contains('.') {
            return Err(unverifiable());
        }

        let header: Header = decode(header)?;
        if header.alg != "HS256" || header.typ != typ {
            return Err(unverifiable());
        }

        let signature = BASE64.decode(signature).map_err(|_| unverifiable())?;
        self.mac(signed.as_bytes())
            .verify_slice(&signature)
            .map_err(|_| unverifiable())?;

        let claims: Claims = decode(payload)?;
        if expired == Expired::Refuse && claims.exp <= Timestamp::now().as_second() {
            return Err(Error::invalid_request("Token has expired").named("ExpiredToken"));
        }
        if claims.aud != *self.audience {
            return Err(unverifiable());
        }
        // A service auth token proves something else entirely, and this server
        // signs both kinds, so one must never be read as the other.
        if claims.lxm.is_some() || claims.cnf.is_some() {
            return Err(malformed());
        }
        if !claims
            .scope
            .parse()
            .is_ok_and(|scope| scopes.contains(&scope))
        {
            return Err(Error::invalid_request("Bad token scope").named("InvalidToken"));
        }
        Ok(claims)
    }

    fn mac(&self, message: &[u8]) -> Hmac<Sha256> {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&self.key)
            .expect("hmac takes a key of any length");
        mac.update(message);
        mac
    }
}

/// What a request offered in its `Authorization` header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Credential {
    /// A session token, or a service token proving who called.
    Bearer(String),
    /// An OAuth token bound to a key the client holds.
    Dpop(String),
    /// A username and password, which is how the admin endpoints authenticate.
    Basic {
        /// The name before the colon.
        username: String,
        /// Everything after it, colons and all.
        password: String,
    },
}

/// The credential a request carried, if it carried one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Authorization(pub Option<Credential>);

impl Authorization {
    /// Reads the header, which is absent, one of three schemes, or a refusal.
    ///
    /// # Errors
    ///
    /// If the header is not two parts, or names a scheme nothing here speaks.
    pub fn parse(header: Option<&str>) -> Result<Self, Error> {
        let Some(header) = header else {
            return Ok(Self(None));
        };
        let Some((scheme, token)) = header.split_once(' ') else {
            return Err(
                Error::invalid_request("Malformed authorization header").named("InvalidToken")
            );
        };
        if token.contains(' ') {
            return Err(
                Error::invalid_request("Malformed authorization header").named("InvalidToken")
            );
        }
        let credential = match scheme.to_ascii_uppercase().as_str() {
            "BEARER" => Credential::Bearer(token.to_owned()),
            "DPOP" => Credential::Dpop(token.to_owned()),
            "BASIC" => return Ok(Self(basic(token))),
            _ => {
                return Err(Error::invalid_request(format!(
                    "Unsupported authorization type: {scheme}"
                ))
                .named("InvalidToken"));
            }
        };
        Ok(Self(Some(credential)))
    }

    /// Reads it off a request's headers.
    ///
    /// # Errors
    ///
    /// If the header is not two parts, not text, or names a scheme nothing
    /// here speaks.
    pub fn from_headers(headers: &HeaderMap) -> Result<Self, Error> {
        let header = headers
            .get(header::AUTHORIZATION)
            .map(|value| value.to_str())
            .transpose()
            .map_err(|_| {
                Error::invalid_request("Malformed authorization header").named("InvalidToken")
            })?;
        Self::parse(header)
    }

    /// The bearer token, if that is what was offered.
    #[must_use]
    pub fn bearer(&self) -> Option<&str> {
        match &self.0 {
            Some(Credential::Bearer(token)) => Some(token),
            _ => None,
        }
    }
}

impl<S: Sync> FromRequestParts<S> for Authorization {
    type Rejection = Error;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Error>> {
        if let Some(Read(read)) = parts.extensions.get::<Read>() {
            read.store(true, Ordering::Relaxed);
        }
        std::future::ready(Self::from_headers(&parts.headers))
    }
}

impl<S: Sync> FromRequestParts<S> for Access
where
    Tokens: FromRef<S>,
{
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Error> {
        let authorization = Authorization::from_request_parts(parts, state).await?;
        let token = authorization.bearer().ok_or_else(|| {
            Error::new(super::Status::AuthenticationRequired).named("AuthMissing")
        })?;
        Tokens::from_ref(state).verify_access(token, &Scope::STANDARD)
    }
}

impl<S: Sync> FromRequestParts<S> for Refresh
where
    Tokens: FromRef<S>,
{
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Error> {
        refresh(parts, state, Expired::Refuse).await
    }
}

/// A refresh token read whether or not it has run out.
///
/// Ending a session is the one thing a client that has been away longer than
/// the token lives may still do, since the alternative is a session nobody
/// can close.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Closing(pub Refresh);

impl<S: Sync> FromRequestParts<S> for Closing
where
    Tokens: FromRef<S>,
{
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Error> {
        refresh(parts, state, Expired::Allow).await.map(Self)
    }
}

async fn refresh<S: Sync>(parts: &mut Parts, state: &S, expired: Expired) -> Result<Refresh, Error>
where
    Tokens: FromRef<S>,
{
    let authorization = Authorization::from_request_parts(parts, state).await?;
    let token = authorization
        .bearer()
        .ok_or_else(|| Error::new(super::Status::AuthenticationRequired).named("AuthMissing"))?;
    Tokens::from_ref(state).verify_refresh(token, expired)
}

/// Set on a request so that reading its credentials can be noticed after the
/// handler has finished with it.
#[derive(Clone, Debug)]
struct Read(Arc<AtomicBool>);

/// Marks every response that depended on who was asking, so that nothing
/// between here and the client hands one account's answer to another.
///
/// The mark is set where the credential is read rather than where the route is
/// declared, so a method that authenticates cannot be added without it.
pub async fn private(mut request: Request, next: Next) -> Response {
    let read = Arc::new(AtomicBool::new(false));
    request.extensions_mut().insert(Read(Arc::clone(&read)));

    let mut response = next.run(request).await;
    if read.load(Ordering::Relaxed) {
        let headers = response.headers_mut();
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("private"));
        headers.append(header::VARY, HeaderValue::from_static("Authorization"));
    }
    response
}

#[derive(Debug, Deserialize, Serialize)]
struct Header {
    alg: String,
    typ: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct Claims {
    scope: String,
    sub: String,
    aud: String,
    iat: i64,
    exp: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    jti: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    lxm: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cnf: Option<serde_json::Value>,
}

fn part<T: Serialize>(value: &T) -> String {
    BASE64.encode(serde_json::to_vec(value).expect("a token's own claims encode as JSON"))
}

fn decode<T: for<'a> Deserialize<'a>>(part: &str) -> Result<T, Error> {
    let bytes = BASE64.decode(part).map_err(|_| unverifiable())?;
    serde_json::from_slice(&bytes).map_err(|_| malformed())
}

/// Reads a `Basic` credential, or nothing if it will not decode.
///
/// Nothing rather than a refusal, so that an unreadable header reaches the
/// same "no credentials" answer as an absent one instead of a different
/// status.
fn basic(token: &str) -> Option<Credential> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(token)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())?;
    // Split at the first colon, since only the username is forbidden one.
    let (username, password) = decoded.split_once(':')?;
    Some(Credential::Basic {
        username: username.to_owned(),
        password: password.to_owned(),
    })
}

fn did(sub: &str) -> Result<Did, Error> {
    sub.parse().map_err(|_| malformed())
}

fn scope(value: &str) -> Result<Scope, Error> {
    value.parse().map_err(|UnknownScope| malformed())
}

fn unverifiable() -> Error {
    Error::invalid_request("Token could not be verified").named("InvalidToken")
}

fn malformed() -> Error {
    Error::invalid_request("Malformed token").named("InvalidToken")
}
