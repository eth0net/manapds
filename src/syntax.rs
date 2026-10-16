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

#[cfg(test)]
mod tests {
    use std::{fs, path::Path, str::FromStr};

    use super::*;

    #[test]
    fn at_identifier() {
        accepts::<AtIdentifier>("atidentifier_syntax_valid.txt");
        rejects::<AtIdentifier>("atidentifier_syntax_invalid.txt");
    }

    #[test]
    fn at_uri() {
        accepts::<AtUri>("aturi_syntax_valid.txt");
        rejects::<AtUri>("aturi_syntax_invalid.txt");
    }

    #[test]
    fn did() {
        accepts::<Did>("did_syntax_valid.txt");
        rejects::<Did>("did_syntax_invalid.txt");
    }

    #[test]
    fn handle() {
        accepts::<Handle>("handle_syntax_valid.txt");
        rejects::<Handle>("handle_syntax_invalid.txt");
    }

    #[test]
    fn nsid() {
        accepts::<Nsid>("nsid_syntax_valid.txt");
        rejects::<Nsid>("nsid_syntax_invalid.txt");
    }

    #[test]
    fn record_key() {
        accepts::<RecordKey>("recordkey_syntax_valid.txt");
        rejects::<RecordKey>("recordkey_syntax_invalid.txt");
    }

    #[test]
    fn tid() {
        accepts::<Tid>("tid_syntax_valid.txt");
        rejects::<Tid>("tid_syntax_invalid.txt");
    }

    #[test]
    fn at_uri_round_trips() {
        for vector in vectors("aturi_syntax_valid.txt") {
            let parsed = AtUri::from_str(&vector).expect("valid");
            assert_eq!(parsed.to_string(), vector);
        }
    }

    #[test]
    fn an_at_uri_comes_apart_into_the_pieces_it_names() {
        let uri =
            AtUri::from_str("at://alice.test/app.bsky.feed.post/3jui7kd54zh2y").expect("an AT-URI");
        assert_eq!(uri.authority().to_string(), "alice.test");
        assert_eq!(
            uri.collection().map(ToString::to_string).as_deref(),
            Some("app.bsky.feed.post")
        );
        assert_eq!(
            uri.rkey().map(ToString::to_string).as_deref(),
            Some("3jui7kd54zh2y")
        );
        assert_eq!(uri.fragment(), None);

        // A bare authority has neither, and a fragment is kept without its hash so
        // that it reads as the JSON pointer it is.
        let repo = AtUri::from_str("at://did:plc:4cjoyc3cgpal7gnrpzyjhnv3").expect("an AT-URI");
        assert_eq!(repo.collection(), None);
        assert_eq!(repo.rkey(), None);

        let field = AtUri::from_str("at://alice.test/app.bsky.feed.post/3jui7kd54zh2y#/text")
            .expect("an AT-URI");
        assert_eq!(field.fragment(), Some("/text"));
    }

    #[test]
    fn tid_from_parts() {
        // The reference pads the clock id to two digits and the timestamp not at
        // all, so it agrees only above a timestamp of 32^10.
        assert_eq!(
            Tid::from_parts(1_700_000_000_000_000, 17).as_str(),
            "3ke6kg3wk222l"
        );
        assert_eq!(
            Tid::from_parts(1_758_000_000_000_000, 1023).as_str(),
            "3lywl4sbs22zz"
        );
        assert_eq!(Tid::from_parts(0, 0).as_str(), "2222222222222");
    }

    #[test]
    fn minted_tids_parse_and_climb() {
        let mut clock = TidClock::new();
        let mut previous = clock.mint();
        for _ in 0..10_000 {
            let tid = clock.mint();
            assert!(tid.as_str().parse::<Tid>().is_ok(), "minted {tid}");
            assert!(tid > previous, "{tid} follows {previous}");
            previous = tid;
        }
    }

    #[test]
    fn a_tid_decodes_to_the_parts_it_was_made_from() {
        for (micros, clock_id) in [(1_700_000_000_000_000, 17), (0, 0), (1 << 52, 1023)] {
            assert_eq!(
                Tid::from_parts(micros, clock_id).to_parts(),
                (micros, clock_id)
            );
        }
    }

    #[test]
    fn minting_clears_a_tid_already_written() {
        // A clock this far ahead of the wall clock only moves on by being pushed.
        let ahead = Tid::from_parts(1 << 52, 1023);
        let mut clock = TidClock::new();

        let next = clock.mint_after(&ahead).expect("there is room above it");
        assert!(next > ahead, "{next} follows {ahead}");
        assert!(clock.mint() > next, "the floor sticks for the next one too");
    }

    #[test]
    fn a_clock_at_the_top_of_its_range_still_only_goes_forward() {
        // The field is 53 bits of microseconds, and a rev read from a stored
        // commit is whatever that commit says. One at the ceiling must not wrap a
        // minted TID back under it.
        let ceiling = Tid::from_parts((1 << 53) - 1, 1023);
        let mut clock = TidClock::new();
        assert_eq!(
            clock.mint_after(&ceiling),
            None,
            "nothing follows {ceiling}"
        );

        // One step under it still has room, and what comes back is above it.
        let near = Tid::from_parts((1 << 53) - 2, 0);
        let mut clock = TidClock::new();
        let next = clock.mint_after(&near).expect("one left");
        assert!(next > near, "{next} follows {near}");
    }

    fn accepts<T: FromStr>(file: &str) {
        for vector in vectors(file) {
            assert!(T::from_str(&vector).is_ok(), "rejected {vector:?}");
        }
    }

    fn rejects<T: FromStr>(file: &str) {
        for vector in vectors(file) {
            assert!(T::from_str(&vector).is_err(), "accepted {vector:?}");
        }
    }

    fn vectors(file: &str) -> Vec<String> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/syntax")
            .join(file);
        let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        text.lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(str::to_owned)
            .collect()
    }
}
