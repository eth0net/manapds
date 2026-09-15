//! The published interop vectors, run against every identifier parser.
//!
//! A vector file is one case per line; the reference harness treats a leading
//! `#` as a comment, so this does too even though that drops one case.

use std::{fs, path::Path, str::FromStr};

use manapds::syntax::{AtIdentifier, AtUri, Did, Handle, Nsid, RecordKey, Tid, TidClock};

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
