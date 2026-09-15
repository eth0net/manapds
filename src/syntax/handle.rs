//! Handles.

use super::Error;

/// Both limits are the domain name's, not atproto's.
const MAX_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;

/// A handle: a domain name whose owner has pointed it at a DID.
///
/// Parsing accepts either case because DNS is case-insensitive; everything
/// that stores or compares one wants [`Handle::normalize`] first.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Handle(String);

impl Handle {
    /// Lowercases, then parses.
    ///
    /// # Errors
    ///
    /// If the input is not a handle.
    pub fn normalize(input: &str) -> Result<Self, Error> {
        input.to_ascii_lowercase().try_into()
    }
}

string_newtype!(Handle);

fn validate(input: &str) -> Result<(), Error> {
    if input.len() > MAX_LEN {
        return Err(Error::Handle("longer than 253 characters"));
    }
    let mut parts = 0usize;
    let mut tld = "";
    for label in input.split('.') {
        validate_label(label)?;
        tld = label;
        parts += 1;
    }
    if parts < 2 {
        return Err(Error::Handle("not a domain name"));
    }
    if !tld.starts_with(|c: char| c.is_ascii_alphabetic()) {
        return Err(Error::Handle("last part does not start with a letter"));
    }
    Ok(())
}

fn validate_label(label: &str) -> Result<(), Error> {
    if label.is_empty() {
        return Err(Error::Handle("empty part"));
    }
    if label.len() > MAX_LABEL_LEN {
        return Err(Error::Handle("part longer than 63 characters"));
    }
    if !label
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(Error::Handle("disallowed character"));
    }
    if label.starts_with('-') || label.ends_with('-') {
        return Err(Error::Handle("part starts or ends with a hyphen"));
    }
    Ok(())
}
