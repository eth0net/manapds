//! Record keys.

use super::Error;

const MAX_LEN: usize = 512;

/// A record key: the second half of a record's MST path, under a collection.
///
/// The character set is the generic URI unreserved set plus a colon, so a key
/// is safe both in the tree path and in an AT-URI without escaping.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RecordKey(String);

string_newtype!(RecordKey);

fn validate(input: &str) -> Result<(), Error> {
    if input.is_empty() {
        return Err(Error::RecordKey("empty"));
    }
    if input.len() > MAX_LEN {
        return Err(Error::RecordKey("longer than 512 characters"));
    }
    if input == "." || input == ".." {
        return Err(Error::RecordKey("\".\" and \"..\" are reserved"));
    }
    if !input.bytes().all(is_allowed) {
        return Err(Error::RecordKey("disallowed character"));
    }
    Ok(())
}

fn is_allowed(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b':' | b'-')
}
