//! NSIDs.

use super::Error;

/// A domain, a separator, and a name.
const MAX_LEN: usize = 253 + 1 + 63;
const MAX_SEGMENT_LEN: usize = 63;

/// An NSID: a lexicon name, written as its authority's domain reversed
/// followed by the name within that authority.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Nsid(String);

string_newtype!(Nsid);

fn validate(input: &str) -> Result<(), Error> {
    if input.len() > MAX_LEN {
        return Err(Error::Nsid("longer than 317 characters"));
    }
    let mut segments = 0usize;
    let mut first = "";
    let mut name = "";
    for segment in input.split('.') {
        validate_segment(segment)?;
        if segments == 0 {
            first = segment;
        }
        name = segment;
        segments += 1;
    }
    if segments < 3 {
        return Err(Error::Nsid("fewer than three parts"));
    }
    if first.starts_with(|c: char| c.is_ascii_digit()) {
        return Err(Error::Nsid("authority starts with a digit"));
    }
    if name.starts_with(|c: char| c.is_ascii_digit()) || name.contains('-') {
        return Err(Error::Nsid(
            "name is not a letter followed by letters and digits",
        ));
    }
    Ok(())
}

fn validate_segment(segment: &str) -> Result<(), Error> {
    if segment.is_empty() {
        return Err(Error::Nsid("empty part"));
    }
    if segment.len() > MAX_SEGMENT_LEN {
        return Err(Error::Nsid("part longer than 63 characters"));
    }
    if !segment
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(Error::Nsid("disallowed character"));
    }
    if segment.starts_with('-') || segment.ends_with('-') {
        return Err(Error::Nsid("part starts or ends with a hyphen"));
    }
    Ok(())
}
