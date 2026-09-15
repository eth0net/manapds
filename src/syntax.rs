//! Identifiers: DIDs, handles, NSIDs, record keys, TIDs and AT-URIs.
//!
//! Every type here is built only by parsing, so holding one is proof that it
//! validated. The rules are the reference implementation's rules, checked
//! against the vectors it publishes.

/// What was rejected and which rule it broke.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum Error {
    /// An AT-URI, in the strict form [`AtUri`] parses.
    #[error("invalid AT-URI: {0}")]
    AtUri(&'static str),
    /// A DID.
    #[error("invalid DID: {0}")]
    Did(&'static str),
    /// A handle.
    #[error("invalid handle: {0}")]
    Handle(&'static str),
    /// An NSID.
    #[error("invalid NSID: {0}")]
    Nsid(&'static str),
    /// A record key.
    #[error("invalid record key: {0}")]
    RecordKey(&'static str),
    /// A TID.
    #[error("invalid TID: {0}")]
    Tid(&'static str),
}

/// Gives a tuple struct over `String` the traits every identifier wants, from
/// a `validate` in the same module.
macro_rules! string_newtype {
    ($name:ident) => {
        impl $name {
            /// The identifier as it was written.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Unwraps to the string, dropping the proof that it parsed.
            #[must_use]
            pub fn into_string(self) -> String {
                self.0
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl std::str::FromStr for $name {
            type Err = $crate::syntax::Error;

            fn from_str(input: &str) -> Result<Self, Self::Err> {
                validate(input)?;
                Ok(Self(input.to_owned()))
            }
        }

        impl TryFrom<String> for $name {
            type Error = $crate::syntax::Error;

            fn try_from(input: String) -> Result<Self, Self::Error> {
                validate(&input)?;
                Ok(Self(input))
            }
        }

        impl TryFrom<&str> for $name {
            type Error = $crate::syntax::Error;

            fn try_from(input: &str) -> Result<Self, Self::Error> {
                input.parse()
            }
        }

        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                <String as serde::Deserialize>::deserialize(deserializer)?
                    .try_into()
                    .map_err(serde::de::Error::custom)
            }
        }
    };
}

mod at_identifier;
mod at_uri;
mod did;
mod handle;
mod nsid;
mod record_key;
mod tid;

pub use at_identifier::AtIdentifier;
pub use at_uri::AtUri;
pub use did::Did;
pub use handle::Handle;
pub use nsid::Nsid;
pub use record_key::RecordKey;
pub use tid::{Clock as TidClock, Tid};
