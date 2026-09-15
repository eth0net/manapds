//! TIDs.

use super::Error;

const LEN: usize = 13;

/// A TID: a timestamp identifier, sorting in the same order as the time it
/// encodes because base32-sortable's digits are in ASCII order.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Tid(String);

string_newtype!(Tid);

fn validate(input: &str) -> Result<(), Error> {
    if input.len() != LEN {
        return Err(Error::Tid("not 13 characters"));
    }
    let bytes = input.as_bytes();
    if !bytes.iter().copied().all(is_digit) {
        return Err(Error::Tid("character outside base32-sortable"));
    }
    // The encoded integer's top bit is always clear, which caps the first
    // digit at 15.
    if !matches!(bytes[0], b'2'..=b'7' | b'a'..=b'j') {
        return Err(Error::Tid("high bit set"));
    }
    Ok(())
}

fn is_digit(byte: u8) -> bool {
    matches!(byte, b'2'..=b'7' | b'a'..=b'z')
}
