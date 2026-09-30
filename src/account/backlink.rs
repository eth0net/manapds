//! What a record points at, for the four kinds that may only point once.
//!
//! No lexicon carries the rule, so the four are named here and the index does
//! the rest; `docs/architecture.md` has why they work this way.

use crate::repo::Ipld;
use crate::store::Backlink;
use crate::syntax::{AtUri, Did, Nsid};

/// The collections a record is held to one of.
const FOLLOW: &str = "app.bsky.graph.follow";
const BLOCK: &str = "app.bsky.graph.block";
const LIKE: &str = "app.bsky.feed.like";
const REPOST: &str = "app.bsky.feed.repost";

/// Where the subject sits in each of them.
const SUBJECT: &str = "subject";
const SUBJECT_URI: &str = "subject.uri";

/// What this record may only hold one of, if it is one of the four.
///
/// A subject that will not parse is left unindexed rather than refused: the
/// record is the caller's to write, and all this decides is whether anything
/// else has to make way for it.
#[must_use]
pub fn of(record: &Ipld) -> Vec<Backlink> {
    let Ipld::Map(fields) = record else {
        return Vec::new();
    };
    let Some(Ipld::String(kind)) = fields.get("$type") else {
        return Vec::new();
    };

    let link = match kind.as_str() {
        FOLLOW | BLOCK => match fields.get(SUBJECT) {
            Some(Ipld::String(did)) if did.parse::<Did>().is_ok() => (SUBJECT, did.clone()),
            _ => return Vec::new(),
        },
        LIKE | REPOST => match fields.get(SUBJECT) {
            Some(Ipld::Map(subject)) => match subject.get("uri") {
                Some(Ipld::String(uri)) if uri.parse::<AtUri>().is_ok() => {
                    (SUBJECT_URI, uri.clone())
                }
                _ => return Vec::new(),
            },
            _ => return Vec::new(),
        },
        _ => return Vec::new(),
    };

    vec![Backlink {
        path: link.0,
        link_to: link.1,
    }]
}

/// Whether a collection is one of the four at all, which is what decides
/// whether the index is asked anything.
#[must_use]
pub fn held_to_one(collection: &Nsid) -> bool {
    matches!(collection.as_str(), FOLLOW | BLOCK | LIKE | REPOST)
}
