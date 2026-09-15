//! AT-URIs.

use std::{fmt, str::FromStr};

use super::{AtIdentifier, Error, Nsid, RecordKey};

const MAX_LEN: usize = 8192;

/// An `at://` URI naming a repository, one collection in it, or one record.
///
/// Only the form lexicons use parses: no query, no trailing slash, and a
/// record key a repository could really hold. The fragment stays percent-
/// encoded as written so that printing gives back the input.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AtUri {
    authority: AtIdentifier,
    collection: Option<Nsid>,
    rkey: Option<RecordKey>,
    fragment: Option<String>,
}

impl AtUri {
    /// The repository the URI points into.
    #[must_use]
    pub fn authority(&self) -> &AtIdentifier {
        &self.authority
    }

    /// The collection, absent when the URI names the repository alone.
    #[must_use]
    pub fn collection(&self) -> Option<&Nsid> {
        self.collection.as_ref()
    }

    /// The record key, absent when the URI stops at the collection.
    #[must_use]
    pub fn rkey(&self) -> Option<&RecordKey> {
        self.rkey.as_ref()
    }

    /// The JSON pointer into the record, without its leading `#`.
    #[must_use]
    pub fn fragment(&self) -> Option<&str> {
        self.fragment.as_deref()
    }
}

impl fmt::Display for AtUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "at://{}", self.authority)?;
        if let Some(collection) = &self.collection {
            write!(f, "/{collection}")?;
        }
        if let Some(rkey) = &self.rkey {
            write!(f, "/{rkey}")?;
        }
        if let Some(fragment) = &self.fragment {
            write!(f, "#{fragment}")?;
        }
        Ok(())
    }
}

impl FromStr for AtUri {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if input.len() > MAX_LEN {
            return Err(Error::AtUri("longer than 8192 characters"));
        }
        if !input.bytes().all(is_allowed) {
            return Err(Error::AtUri("disallowed character"));
        }
        let Some(rest) = input.strip_prefix("at://") else {
            return Err(Error::AtUri("does not start with \"at://\""));
        };

        let (rest, fragment) = match rest.split_once('#') {
            Some((rest, fragment)) => (rest, Some(fragment)),
            None => (rest, None),
        };
        if rest.contains('?') {
            return Err(Error::AtUri("query strings do not address anything"));
        }
        if rest.ends_with('/') {
            return Err(Error::AtUri("trailing slash"));
        }

        let mut segments = rest.split('/');
        let authority = segments.next().unwrap_or_default();
        let collection = segments.next();
        let rkey = segments.next();
        if segments.next().is_some() {
            return Err(Error::AtUri("more than two path segments"));
        }

        Ok(Self {
            authority: authority
                .parse()
                .map_err(|_| Error::AtUri("authority is not a DID or a handle"))?,
            collection: collection
                .map(str::parse)
                .transpose()
                .map_err(|_| Error::AtUri("collection is not an NSID"))?,
            rkey: rkey
                .map(str::parse)
                .transpose()
                .map_err(|_| Error::AtUri("not a record key"))?,
            fragment: fragment.map(validate_fragment).transpose()?,
        })
    }
}

impl TryFrom<&str> for AtUri {
    type Error = Error;

    fn try_from(input: &str) -> Result<Self, Error> {
        input.parse()
    }
}

impl serde::Serialize for AtUri {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for AtUri {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let input = <String as serde::Deserialize>::deserialize(deserializer)?;
        input.parse().map_err(serde::de::Error::custom)
    }
}

fn validate_fragment(fragment: &str) -> Result<String, Error> {
    if !fragment.starts_with('/') {
        return Err(Error::AtUri("fragment is not a JSON pointer"));
    }
    if !fragment.bytes().all(is_pointer_byte) {
        return Err(Error::AtUri("disallowed character in the fragment"));
    }
    validate_percent_encoding(fragment)?;
    Ok(fragment.to_owned())
}

/// Every escape has to be two hex digits, and the bytes they spell have to be
/// text, because a reader will decode this before matching it against a record.
fn validate_percent_encoding(fragment: &str) -> Result<(), Error> {
    let mut decoded = Vec::with_capacity(fragment.len());
    let mut bytes = fragment.bytes();
    while let Some(byte) = bytes.next() {
        if byte != b'%' {
            decoded.push(byte);
            continue;
        }
        let (high, low) = bytes
            .next()
            .zip(bytes.next())
            .ok_or(Error::AtUri("truncated escape in the fragment"))?;
        let value = hex(high)
            .zip(hex(low))
            .ok_or(Error::AtUri("escape is not two hex digits"))?;
        decoded.push(value.0 << 4 | value.1);
    }
    if std::str::from_utf8(&decoded).is_err() {
        return Err(Error::AtUri("escapes in the fragment do not spell text"));
    }
    Ok(())
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn is_allowed(byte: u8) -> bool {
    is_pointer_byte(byte) || matches!(byte, b'#' | b'?' | b'\\')
}

fn is_pointer_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'.' | b'_'
                | b'~'
                | b':'
                | b'@'
                | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b'%'
                | b'/'
                | b'['
                | b']'
                | b'-'
        )
}
