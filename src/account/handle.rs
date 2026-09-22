//! Handle rules: which handles this server hands out, and which it only takes
//! from an account that can already prove it owns the name.
//!
//! [`crate::syntax::Handle`] answers whether a string is a handle at all.
//! These are the rules on top of that, and every one of them is the reference
//! server's rather than the protocol's.

mod reserved;

use crate::syntax::Handle;

/// How short and how long the part in front of a service domain may be.
const SHORTEST: usize = 3;
const LONGEST: usize = 18;

/// Endings that resolve to nothing on the public internet, so a handle under
/// one could never be proven. `.test` is missing on purpose: it is what a
/// development server uses.
const DISALLOWED: [&str; 8] = [
    ".local",
    ".arpa",
    ".invalid",
    ".localhost",
    ".internal",
    ".example",
    ".alt",
    ".onion",
];

/// Why a handle was refused.
///
/// Each carries the name its lexicon gives the failure, since that is what a
/// client branches on and the three are not interchangeable.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum Invalid {
    /// Not a handle, or not one shaped the way this server hands them out.
    #[error("{0}")]
    Handle(&'static str),
    /// A handle held back rather than malformed.
    #[error("Reserved handle")]
    Reserved,
    /// A domain this server does not answer for, which an account may take
    /// only once it exists and can point the name here itself.
    #[error("Not a supported handle domain")]
    Unsupported,
}

impl Invalid {
    /// What the client sees in `error`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Handle(_) => "InvalidHandle",
            Self::Reserved => "HandleNotAvailable",
            Self::Unsupported => "UnsupportedDomain",
        }
    }
}

/// The domains this server hands handles out under.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Rules {
    domains: Vec<String>,
}

impl Rules {
    /// Takes the suffixes, each with its leading dot, as the configuration
    /// writes them.
    #[must_use]
    pub fn new(domains: &[String]) -> Self {
        Self {
            domains: domains.to_vec(),
        }
    }

    /// Lowercases and checks what holds for every handle here, whoever it
    /// belongs to.
    ///
    /// # Errors
    ///
    /// If it is not a handle, or ends in something nothing could resolve.
    pub fn normalize(&self, input: &str) -> Result<Handle, Invalid> {
        let handle = Handle::normalize(input).map_err(|_| Invalid::Handle("Invalid handle"))?;
        if DISALLOWED.iter().any(|tld| handle.as_str().ends_with(tld)) {
            return Err(Invalid::Handle("Handle TLD is invalid or disallowed"));
        }
        Ok(handle)
    }

    /// The service domain a handle sits under, if it sits under one.
    ///
    /// The first match rather than the longest, which is what the reference
    /// does and what decides where the front label starts.
    #[must_use]
    pub fn service_domain(&self, handle: &Handle) -> Option<&str> {
        self.domains
            .iter()
            .find(|domain| handle.as_str().ends_with(domain.as_str()))
            .map(String::as_str)
    }

    /// Whether this server answers for the handle at all, counting the bare
    /// domain that a suffix is written as.
    #[must_use]
    pub fn is_local(&self, handle: &Handle) -> bool {
        self.domains.iter().any(|domain| {
            handle.as_str().ends_with(domain.as_str())
                || domain.strip_prefix('.') == Some(handle.as_str())
        })
    }

    /// The handle a new account may be created under.
    ///
    /// Only a service domain, because nothing has been created yet to point a
    /// name of one's own at. Changing to one is what comes after.
    ///
    /// # Errors
    ///
    /// If it is not a handle, is not under a domain this server serves, or is
    /// one of the names held back.
    pub fn signup(&self, input: &str) -> Result<Handle, Invalid> {
        let handle = self.normalize(input)?;
        let domain = self.service_domain(&handle).ok_or(Invalid::Unsupported)?;
        let front = &handle.as_str()[..handle.as_str().len() - domain.len()];

        if front.contains('.') {
            return Err(Invalid::Handle("Invalid characters in handle"));
        }
        if front.len() < SHORTEST {
            return Err(Invalid::Handle("Handle too short"));
        }
        if front.len() > LONGEST {
            return Err(Invalid::Handle("Handle too long"));
        }
        if reserved::held(front) {
            return Err(Invalid::Reserved);
        }
        // todo: the reference refuses explicit slurs anywhere in a handle too.
        Ok(handle)
    }
}
