//! The published interop vectors, run against every identifier parser.
//!
//! A vector file is one case per line; the reference harness treats a leading
//! `#` as a comment, so this does too even though that drops one case.

use std::{fs, path::Path, str::FromStr};

use manapds::syntax::{AtIdentifier, AtUri, Did, Handle, Nsid, RecordKey, Tid};

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
