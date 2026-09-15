//! DIDs.

use super::Error;

/// The maximum the reference accepts. W3C sets none.
const MAX_LEN: usize = 2048;

/// A DID: the identity an account keeps when its handle changes.
///
/// Any method parses. atproto blesses only `did:plc` and `did:web`, but that
/// is a question for whoever resolves it, not for the syntax.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Did(String);

string_newtype!(Did);

fn validate(input: &str) -> Result<(), Error> {
    if input.len() > MAX_LEN {
        return Err(Error::Did("longer than 2048 characters"));
    }
    let Some(rest) = input.strip_prefix("did:") else {
        return Err(Error::Did("does not start with \"did:\""));
    };
    let Some((method, id)) = rest.split_once(':') else {
        return Err(Error::Did("no method-specific identifier"));
    };
    if method.is_empty() || !method.bytes().all(|byte| byte.is_ascii_lowercase()) {
        return Err(Error::Did("method is not lowercase letters"));
    }
    if id.is_empty() {
        return Err(Error::Did("empty method-specific identifier"));
    }
    if !id.bytes().all(is_allowed) {
        return Err(Error::Did("disallowed character"));
    }
    // Percent encoding is allowed but not checked, so a trailing "%" is the
    // only part of it the syntax catches.
    if id.ends_with(':') || id.ends_with('%') {
        return Err(Error::Did("ends with \":\" or \"%\""));
    }
    Ok(())
}

fn is_allowed(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'%' | b'-')
}
