//! The blobs a record names.
//!
//! A record refers to a blob by an object of exactly four keys, so anything
//! carrying a fifth is an ordinary map that happens to look like one and is
//! walked into rather than taken as a reference.

use crate::repo::Ipld;
use crate::store::Blob;

/// What a record's blob reference has to hold, and all it may hold.
const KEYS: [&str; 4] = ["$type", "ref", "mimeType", "size"];

/// Every blob a record names, in the order they are met. What it says they
/// are is the record's claim, which the store checks against the upload.
#[must_use]
pub fn of(record: &Ipld) -> Vec<Blob> {
    let mut found = Vec::new();
    walk(record, &mut found);
    found
}

fn walk(value: &Ipld, found: &mut Vec<Blob>) {
    match value {
        Ipld::List(held) => held.iter().for_each(|held| walk(held, found)),
        Ipld::Map(fields) => match named(fields) {
            // A reference is a leaf: whatever is inside it is part of it.
            Some(blob) => found.push(blob),
            None => fields.values().for_each(|held| walk(held, found)),
        },
        _ => {}
    }
}

/// The reference this map is, if it is one.
fn named(fields: &std::collections::BTreeMap<String, Ipld>) -> Option<Blob> {
    if fields.len() != KEYS.len() || !KEYS.iter().all(|key| fields.contains_key(*key)) {
        return None;
    }
    let Some(Ipld::String(kind)) = fields.get("$type") else {
        return None;
    };
    if kind != "blob" {
        return None;
    }
    let Some(Ipld::Link(cid)) = fields.get("ref") else {
        return None;
    };
    // The whole of what the other server checks a type for, which leaves the
    // rest to whoever reads the blob.
    let Some(Ipld::String(mime)) = fields.get("mimeType") else {
        return None;
    };
    if !mime.contains('/') {
        return None;
    }
    let Some(Ipld::Integer(size)) = fields.get("size") else {
        return None;
    };
    Some(Blob {
        cid: *cid,
        mime: mime.clone(),
        size: u64::try_from(*size).ok()?,
    })
}
