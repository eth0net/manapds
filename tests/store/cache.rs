//! The cached DID documents of everyone this server has had to resolve.

use super::*;

#[test]
fn a_cached_document_comes_back_with_its_age() {
    let cache = DidCache::memory().expect("opens");
    let before = jiff::Timestamp::now().as_millisecond();
    assert_eq!(cache.get(&account()).expect("reads"), None);

    cache.put(&account(), r#"{"id":"one"}"#).expect("writes");
    let held = cache.get(&account()).expect("reads").expect("held");
    assert_eq!(held.document, r#"{"id":"one"}"#);
    assert!(held.updated_at >= before, "the write time is recorded");

    cache
        .put(&account(), r#"{"id":"two"}"#)
        .expect("overwrites");
    assert_eq!(
        cache
            .get(&account())
            .expect("reads")
            .expect("held")
            .document,
        r#"{"id":"two"}"#
    );

    cache.forget(&account()).expect("forgets");
    assert_eq!(cache.get(&account()).expect("reads"), None);
}
