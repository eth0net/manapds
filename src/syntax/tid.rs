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

/// Mints TIDs that only ever go up.
///
/// A TID is a microsecond timestamp next to a clock id, so two servers minting
/// in the same microsecond still disagree. Within one process the count never
/// repeats and never goes backwards, whatever the system clock does.
#[derive(Debug)]
pub struct Clock {
    clock_id: u64,
    last: u64,
}

impl Clock {
    /// Starts a clock on a random id.
    #[must_use]
    pub fn new() -> Self {
        Self {
            clock_id: rand::random_range(0..CLOCK_IDS),
            last: 0,
        }
    }

    /// The next TID, kept above one already written, or `None` where the
    /// field has no room above it.
    ///
    /// A revision read from a stored commit is whatever that commit says, and
    /// one at the top of the range has nothing following it. Refusing is the
    /// only answer that does not hand back a revision sorting under the one it
    /// was meant to follow.
    pub fn mint_after(&mut self, previous: &Tid) -> Option<Tid> {
        self.last = self.last.max(previous.to_parts().0);
        (self.last < MICROS - 1).then(|| self.mint())
    }

    /// The next TID, one microsecond past the last if the clock has not moved.
    pub fn mint(&mut self) -> Tid {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| {
                u64::try_from(since.as_micros()).unwrap_or(u64::MAX)
            });
        // Saturating rather than wrapping: a timestamp past the field would
        // come back around and sort under everything already written.
        self.last = now.max(self.last.saturating_add(1)).min(MICROS - 1);
        Tid::from_parts(self.last, self.clock_id)
    }
}

impl Default for Clock {
    fn default() -> Self {
        Self::new()
    }
}

impl Tid {
    /// A TID over a microsecond timestamp and a clock id, both truncated to the
    /// width the encoding gives them.
    #[must_use]
    pub fn from_parts(micros: u64, clock_id: u64) -> Self {
        Self(encode((micros % MICROS) * CLOCK_IDS + clock_id % CLOCK_IDS))
    }

    /// The microsecond timestamp and the clock id it was minted under.
    #[must_use]
    pub fn to_parts(&self) -> (u64, u64) {
        let value = self
            .0
            .bytes()
            .fold(0, |value, byte| value * 32 + digit(byte));
        (value / CLOCK_IDS, value % CLOCK_IDS)
    }
}

/// The value of a base32-sortable digit, which parsing has already checked.
fn digit(byte: u8) -> u64 {
    match byte {
        b'2'..=b'7' => u64::from(byte - b'2'),
        _ => u64::from(byte - b'a') + 6,
    }
}

/// One past the largest timestamp, at 53 bits.
const MICROS: u64 = 1 << 53;

/// One past the largest clock id, at 10 bits.
const CLOCK_IDS: u64 = 1 << 10;

const DIGITS: &[u8; 32] = b"234567abcdefghijklmnopqrstuvwxyz";

fn encode(value: u64) -> String {
    (0..LEN)
        .rev()
        .map(|digit| DIGITS[(value >> (digit * 5) & 31) as usize] as char)
        .collect()
}
