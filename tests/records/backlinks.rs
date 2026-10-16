//! One like, repost, follow or block per subject, and the caller who waives it.

use super::*;

/// A like of a post, which is one of the four records an account holds one of.
fn like(subject: &str) -> Value {
    serde_json::json!({
        "$type": "app.bsky.feed.like",
        "subject": { "uri": subject, "cid": "bafyreidfcltdzyzp4dmvoeohhrhi6z2lhsbhgorpuoqqzvpxrbfuspqsoq" },
        "createdAt": "2026-09-30T00:00:00.000Z",
    })
}

async fn liking(router: &NormalizePath<Router>, rkey: &str, subject: &str) -> (StatusCode, Value) {
    post(
        router,
        "/xrpc/com.atproto.repo.createRecord",
        serde_json::json!({
            "repo": account().as_str(),
            "collection": "app.bsky.feed.like",
            "rkey": rkey,
            "record": like(subject),
        }),
    )
    .await
}

#[tokio::test]
async fn a_second_like_of_one_post_takes_the_place_of_the_first() {
    let (router, _manager, _data) = served();
    let one = "at://did:plc:ewvi7nxzyoun6zhxrhs64oiz/app.bsky.feed.post/3jqfcqzm4fc2j";
    let other = "at://did:plc:ewvi7nxzyoun6zhxrhs64oiz/app.bsky.feed.post/3jqfcqzm4fd2j";

    for (rkey, subject) in [("3jqfcqzm4fa2j", one), ("3jqfcqzm4fb2j", other)] {
        let (status, written) = liking(&router, rkey, subject).await;
        assert_eq!(status, StatusCode::OK, "{written}");
    }

    // Liking the same post again: the account is left holding one like of it,
    // and the like of the other post is untouched.
    let (status, written) = liking(&router, "3jqfcqzm4fe2j", one).await;
    assert_eq!(status, StatusCode::OK, "{written}");
    assert_eq!(
        written["uri"],
        format!("at://{}/app.bsky.feed.like/3jqfcqzm4fe2j", account())
    );

    let (_, page) = get(
        &router,
        "/xrpc/com.atproto.repo.listRecords\
         ?repo=alice.pds.example.com&collection=app.bsky.feed.like&reverse=true",
    )
    .await;
    let held: Vec<&str> = page["records"]
        .as_array()
        .expect("records")
        .iter()
        .map(|record| {
            record["uri"]
                .as_str()
                .expect("a uri")
                .rsplit('/')
                .next()
                .expect("a key")
        })
        .collect();
    assert_eq!(held, ["3jqfcqzm4fb2j", "3jqfcqzm4fe2j"]);
}

#[tokio::test]
async fn a_caller_that_turns_the_checks_off_keeps_both_likes() {
    let (router, _manager, _data) = served();
    let subject = "at://did:plc:ewvi7nxzyoun6zhxrhs64oiz/app.bsky.feed.post/3jqfcqzm4fc2j";

    let (status, _) = liking(&router, "3jqfcqzm4fa2j", subject).await;
    assert_eq!(status, StatusCode::OK);

    // Only an explicit false turns them off; a client that sends nothing gets
    // the checks.
    let (status, written) = post(
        &router,
        "/xrpc/com.atproto.repo.createRecord",
        serde_json::json!({
            "repo": account().as_str(),
            "collection": "app.bsky.feed.like",
            "rkey": "3jqfcqzm4fb2j",
            "record": like(subject),
            "validate": false,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{written}");

    let (_, page) = get(
        &router,
        "/xrpc/com.atproto.repo.listRecords\
         ?repo=alice.pds.example.com&collection=app.bsky.feed.like",
    )
    .await;
    assert_eq!(page["records"].as_array().expect("records").len(), 2);
}

#[tokio::test]
async fn a_record_that_holds_nothing_to_one_is_left_alone() {
    let (router, _manager, _data) = served();

    // A collection outside the four never asks the index anything, so two
    // records naming the same subject both stand.
    for rkey in ["3jqfcqzm4fa2j", "3jqfcqzm4fb2j"] {
        let (status, written) = post(
            &router,
            "/xrpc/com.atproto.repo.createRecord",
            serde_json::json!({
                "repo": account().as_str(),
                "collection": "com.example.record",
                "rkey": rkey,
                "record": { "$type": "com.example.record", "subject": "the same" },
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{written}");
    }

    let (_, page) = get(
        &router,
        "/xrpc/com.atproto.repo.listRecords\
         ?repo=alice.pds.example.com&collection=com.example.record",
    )
    .await;
    assert_eq!(page["records"].as_array().expect("records").len(), 2);
}

#[tokio::test]
async fn liking_one_post_twice_at_one_key_lands() {
    let (router, _manager, _data) = served();
    let subject = "at://did:plc:ewvi7nxzyoun6zhxrhs64oiz/app.bsky.feed.post/3jqfcqzm4fc2j";

    // The second one supersedes the first at the key the first is already at,
    // so the key has to be emptied before it is written again.
    for _ in 0..2 {
        let (status, written) = liking(&router, "3jqfcqzm4fa2j", subject).await;
        assert_eq!(status, StatusCode::OK, "{written}");
    }

    let (_, page) = get(
        &router,
        "/xrpc/com.atproto.repo.listRecords\
         ?repo=alice.pds.example.com&collection=app.bsky.feed.like",
    )
    .await;
    assert_eq!(page["records"].as_array().expect("records").len(), 1);
}
