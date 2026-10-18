//! The values the tests below the repository layer are written against.
//!
//! One account, one collection and one record, shared so that a tree, a
//! commit and a file are all built from the same thing.

use std::collections::BTreeMap;

use super::{Cid, Ipld};
use crate::syntax::{Did, Nsid, RecordKey};

/// The record every tree below points its leaves at; only the keys matter to
/// the shape, so one CID does for all of them.
const RECORD: &str = "bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454";

pub(crate) fn record() -> Cid {
    RECORD.parse().expect("a CID")
}

pub(crate) fn account() -> Did {
    "did:plc:4cjoyc3cgpal7gnrpzyjhnv3".parse().expect("a DID")
}

pub(crate) fn collection() -> Nsid {
    "com.example.record".parse().expect("an NSID")
}

pub(crate) fn rkey(key: &str) -> RecordKey {
    key.parse().expect("a record key")
}

pub(crate) fn post(text: &str) -> Ipld {
    Ipld::Map(BTreeMap::from([
        (
            "$type".to_owned(),
            Ipld::String("com.example.record".to_owned()),
        ),
        ("text".to_owned(), Ipld::String(text.to_owned())),
    ]))
}
