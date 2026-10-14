//! The strings a caller is held to, and the refusal each one owes.
//!
//! Every wording here is sent to clients that match on it, so it is written
//! once and read from everywhere rather than copied to each method that asks.

use crate::repo::Cid;
use crate::syntax::{Did, Nsid, RecordKey, Tid};
use crate::xrpc;

/// # Errors
///
/// If the string is not a DID.
pub(crate) fn did(did: &str) -> xrpc::Result<Did> {
    did.parse()
        .map_err(|_| xrpc::Error::invalid_request("Invalid did"))
}

/// # Errors
///
/// If the string is not a CID.
pub(crate) fn cid(cid: &str) -> xrpc::Result<Cid> {
    cid.parse()
        .map_err(|_| xrpc::Error::invalid_request("Invalid cid"))
}

/// # Errors
///
/// If the string is not an NSID.
pub(crate) fn collection(collection: &str) -> xrpc::Result<Nsid> {
    collection
        .parse()
        .map_err(|_| xrpc::Error::invalid_request("Invalid collection"))
}

/// # Errors
///
/// If the string is not a record key.
pub(crate) fn record_key(rkey: &str) -> xrpc::Result<RecordKey> {
    rkey.parse()
        .map_err(|_| xrpc::Error::invalid_request("Invalid record key"))
}

/// The revision a caller asks to read from, named for the parameter carrying
/// it rather than for its type, which is what the refusal says.
///
/// # Errors
///
/// If the string is not a revision.
pub(crate) fn since(since: &str) -> xrpc::Result<Tid> {
    since
        .parse()
        .map_err(|_| xrpc::Error::invalid_request("Invalid since"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // A refusal is matched on by whoever called, so each wording is pinned
    // here the way any other value crossing the wire would be.

    #[test]
    fn a_did_is_taken_and_anything_else_is_refused() {
        let held = "did:plc:4cjoyc3cgpal7gnrpzyjhnv3";
        assert_eq!(did(held).expect("a DID").to_string(), held);
        assert_eq!(
            did("nothing like one").expect_err("refused"),
            xrpc::Error::invalid_request("Invalid did")
        );
    }

    #[test]
    fn a_cid_is_taken_and_anything_else_is_refused() {
        let held = crate::repo::cid_for(b"a block").to_string();
        assert_eq!(cid(&held).expect("a CID").to_string(), held);
        assert_eq!(
            cid("nothing like one").expect_err("refused"),
            xrpc::Error::invalid_request("Invalid cid")
        );
    }

    #[test]
    fn a_collection_is_taken_and_anything_else_is_refused() {
        let held = "app.bsky.feed.post";
        assert_eq!(collection(held).expect("an NSID").to_string(), held);
        assert_eq!(
            collection("nothing-like-one").expect_err("refused"),
            xrpc::Error::invalid_request("Invalid collection")
        );
    }

    #[test]
    fn a_record_key_is_taken_and_anything_else_is_refused() {
        let held = "3jqfcqzm4fb2j";
        assert_eq!(record_key(held).expect("a key").to_string(), held);
        assert_eq!(
            record_key("nothing/like/one").expect_err("refused"),
            xrpc::Error::invalid_request("Invalid record key")
        );
    }

    #[test]
    fn a_revision_is_taken_and_anything_else_is_refused() {
        let held = "3jqfcqzm4fb2j";
        assert_eq!(since(held).expect("a revision").to_string(), held);
        assert_eq!(
            since("nothing like one").expect_err("refused"),
            xrpc::Error::invalid_request("Invalid since")
        );
    }
}
