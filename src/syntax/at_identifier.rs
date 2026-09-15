//! The union of the two ways to name a repository.

use std::{fmt, str::FromStr};

use super::{Did, Error, Handle};

/// Whichever identifier a caller happened to have: the DID itself, or a handle
/// that has to be resolved to one first.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AtIdentifier {
    /// A DID.
    Did(Did),
    /// A handle.
    Handle(Handle),
}

impl AtIdentifier {
    /// The identifier as it was written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Did(did) => did.as_str(),
            Self::Handle(handle) => handle.as_str(),
        }
    }
}

impl fmt::Display for AtIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for AtIdentifier {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if input.starts_with("did:") {
            input.parse().map(Self::Did)
        } else {
            input.parse().map(Self::Handle)
        }
    }
}

impl serde::Serialize for AtIdentifier {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for AtIdentifier {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let input = <String as serde::Deserialize>::deserialize(deserializer)?;
        input.parse().map_err(serde::de::Error::custom)
    }
}
