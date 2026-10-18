//! Handle rules: which handles this server hands out, and which it only takes
//! from an account that can already prove it owns the name.
//!
//! [`crate::syntax::Handle`] answers whether a string is a handle at all.
//! These are the rules on top of that, and every one of them is the reference
//! server's rather than the protocol's.

mod reserved;

use crate::syntax::Handle;

/// What an account with no handle is shown as, which is a handle nothing can
/// resolve and the same string the reference writes.
pub const INVALID: &str = "handle.invalid";

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

/// The domains this server hands handles out under, and the names it will not
/// hand out beneath them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Rules {
    domains: Vec<String>,
    held: Vec<String>,
}

impl Rules {
    /// Takes the suffixes, each with its leading dot, as the configuration
    /// writes them, along with any names this server holds back of its own.
    #[must_use]
    pub fn new(domains: &[String], held: &[String]) -> Self {
        let mut held: Vec<String> = held
            .iter()
            .map(|name| name.trim().to_ascii_lowercase())
            .filter(|name| !name.is_empty())
            .collect();
        held.sort();
        held.dedup();
        Self {
            domains: domains.to_vec(),
            held,
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
        if reserved::held(front)
            || self
                .held
                .binary_search_by(|held| held.as_str().cmp(front))
                .is_ok()
        {
            return Err(Invalid::Reserved);
        }
        // todo: the reference refuses explicit slurs anywhere in a handle too.
        Ok(handle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A server handing out handles under one domain, as the configuration would.
    fn rules() -> Rules {
        Rules::new(&[".pds.test".to_owned()], &[])
    }

    #[test]
    fn signing_up_takes_a_name_under_a_domain_this_server_serves() {
        let rules = rules();

        assert_eq!(
            rules.signup("Alice.PDS.test").expect("a handle").as_str(),
            "alice.pds.test"
        );
        // Somebody else's domain is refused at creation even though it is a
        // perfectly good handle, because nothing exists yet to point it at.
        assert_eq!(rules.signup("alice.example.com"), Err(Invalid::Unsupported));
    }

    #[test]
    fn a_server_can_hold_back_names_of_its_own() {
        let rules = Rules::new(
            &[".pds.test".to_owned()],
            &["Mana".to_owned(), "  support  ".to_owned()],
        );

        // Matched however the configuration and the caller happen to spell it.
        assert_eq!(rules.signup("mana.pds.test"), Err(Invalid::Reserved));
        assert_eq!(rules.signup("MANA.pds.test"), Err(Invalid::Reserved));
        assert_eq!(rules.signup("support.pds.test"), Err(Invalid::Reserved));

        // Added to the built-in list rather than replacing it.
        assert_eq!(rules.signup("admin.pds.test"), Err(Invalid::Reserved));
        assert!(rules.signup("alice.pds.test").is_ok());
    }

    #[test]
    fn holding_back_nothing_holds_back_what_the_reference_does() {
        let rules = rules();

        assert_eq!(rules.signup("admin.pds.test"), Err(Invalid::Reserved));
        assert_eq!(rules.signup("mana.pds.test").map(|_| ()), Ok(()));
    }

    #[test]
    fn the_part_in_front_of_the_domain_is_one_label_of_a_workable_length() {
        let rules = rules();

        assert!(matches!(
            rules.signup("ab.pds.test"),
            Err(Invalid::Handle("Handle too short"))
        ));
        assert!(matches!(
            rules.signup("nineteen-characters.pds.test"),
            Err(Invalid::Handle("Handle too long"))
        ));
        assert!(matches!(
            rules.signup("alice.and.bob.pds.test"),
            Err(Invalid::Handle("Invalid characters in handle"))
        ));
        // The two ends of the range are both allowed.
        assert!(rules.signup("abc.pds.test").is_ok());
        assert!(rules.signup("eighteen-chars-yes.pds.test").is_ok());
    }

    #[test]
    fn a_name_somebody_would_expect_to_reach_the_server_is_held_back() {
        let rules = rules();

        for name in ["admin", "www", "xrpc", "bsky", "support"] {
            assert_eq!(
                rules.signup(&format!("{name}.pds.test")),
                Err(Invalid::Reserved),
                "{name}"
            );
        }
    }

    #[test]
    fn a_handle_nothing_could_ever_resolve_is_refused_wherever_it_came_from() {
        let rules = rules();

        for input in ["alice.local", "alice.invalid", "alice.onion"] {
            assert!(
                matches!(rules.normalize(input), Err(Invalid::Handle(_))),
                "{input}"
            );
        }
        // `.test` is what a development server runs under, so it stays.
        assert!(rules.normalize("alice.test").is_ok());
    }

    #[test]
    fn the_domain_itself_is_this_server_even_though_no_account_holds_it() {
        let rules = rules();
        let handle = |input: &str| rules.normalize(input).expect("a handle");

        assert!(rules.is_local(&handle("alice.pds.test")));
        assert!(rules.is_local(&handle("pds.test")));
        assert!(!rules.is_local(&handle("alice.example.com")));
        assert_eq!(
            rules.service_domain(&handle("alice.pds.test")),
            Some(".pds.test")
        );
        assert_eq!(rules.service_domain(&handle("pds.test")), None);
    }
}
