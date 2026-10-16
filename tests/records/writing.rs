//! Writing a record, replacing one, taking one out, and doing several at once.

use super::*;

/// One record, in a collection nothing here has a lexicon for.
fn record(rkey: &str, text: &str) -> Write {
    Write::Create {
        collection: "com.example.record".parse::<Nsid>().expect("an NSID"),
        rkey: rkey.parse::<RecordKey>().expect("a record key"),
        record: Ipld::Map(BTreeMap::from([
            (
                "$type".to_owned(),
                Ipld::String("com.example.record".to_owned()),
            ),
            ("text".to_owned(), Ipld::String(text.to_owned())),
        ])),
    }
}

#[tokio::test]
async fn a_record_is_read_back_by_its_key() {
    let (router, manager, _data) = served();
    manager
        .write(
            &account(),
            vec![record("3jqfcqzm4fc2j", "first").into()],
            None,
        )
        .await
        .expect("a commit")
        .expect("a write");

    let (status, body) = get(
        &router,
        "/xrpc/com.atproto.repo.getRecord\
         ?repo=alice.pds.example.com&collection=com.example.record&rkey=3jqfcqzm4fc2j",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["uri"],
        format!("at://{}/com.example.record/3jqfcqzm4fc2j", account())
    );
    assert_eq!(body["value"]["text"], "first");

    // Asking for the block it is not in is asking for a record nobody holds.
    let (status, body) = get(
        &router,
        "/xrpc/com.atproto.repo.getRecord\
         ?repo=alice.pds.example.com&collection=com.example.record&rkey=3jqfcqzm4fc2j\
         &cid=bafyreidfcltdzyzp4dmvoeohhrhi6z2lhsbhgorpuoqqzvpxrbfuspqsoq",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "RecordNotFound");

    // And so is asking a repository nobody holds.
    let (status, body) = get(
        &router,
        "/xrpc/com.atproto.repo.getRecord\
         ?repo=nobody.pds.example.com&collection=com.example.record&rkey=3jqfcqzm4fc2j",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "RepoNotFound");
}

#[tokio::test]
async fn a_collection_is_paged_newest_first_and_stops_saying_so() {
    let (router, manager, _data) = served();
    manager
        .write(
            &account(),
            vec![
                record("3jqfcqzm4fa2j", "first").into(),
                record("3jqfcqzm4fb2j", "second").into(),
                record("3jqfcqzm4fc2j", "third").into(),
            ],
            None,
        )
        .await
        .expect("a commit")
        .expect("a write");

    let (status, body) = get(
        &router,
        "/xrpc/com.atproto.repo.listRecords\
         ?repo=alice.pds.example.com&collection=com.example.record&limit=2",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["records"]
            .as_array()
            .expect("records")
            .iter()
            .map(|held| held["value"]["text"].as_str().expect("text"))
            .collect::<Vec<_>>(),
        ["third", "second"]
    );
    assert_eq!(body["cursor"], "3jqfcqzm4fb2j");

    // The page that empties the collection carries no cursor, which is how a
    // client knows to stop asking.
    let (status, body) = get(
        &router,
        "/xrpc/com.atproto.repo.listRecords\
         ?repo=alice.pds.example.com&collection=com.example.record&limit=2\
         &cursor=3jqfcqzm4fb2j",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["records"].as_array().expect("records").len(), 1);
    assert_eq!(body["cursor"], Value::Null);
}

#[tokio::test]
async fn a_record_is_written_read_replaced_and_taken_out() {
    let (router, _manager, _data) = served();
    let did = account();

    let (status, written) = post(
        &router,
        "/xrpc/com.atproto.repo.createRecord",
        serde_json::json!({
            "repo": did.as_str(),
            "collection": "com.example.record",
            "rkey": "3jqfcqzm4fc2j",
            "record": { "$type": "com.example.record", "text": "first" },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{written}");
    assert_eq!(
        written["uri"],
        format!("at://{did}/com.example.record/3jqfcqzm4fc2j")
    );
    let first = written["cid"].as_str().expect("a cid").to_owned();

    // Writing the same key again is a put, and the swap has to name what is
    // there rather than what the caller first wrote.
    let (status, refused) = post(
        &router,
        "/xrpc/com.atproto.repo.putRecord",
        serde_json::json!({
            "repo": did.as_str(),
            "collection": "com.example.record",
            "rkey": "3jqfcqzm4fc2j",
            "record": { "$type": "com.example.record", "text": "second" },
            "swapRecord": null,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    assert_eq!(refused["error"], "InvalidSwap");

    let (status, replaced) = post(
        &router,
        "/xrpc/com.atproto.repo.putRecord",
        serde_json::json!({
            "repo": did.as_str(),
            "collection": "com.example.record",
            "rkey": "3jqfcqzm4fc2j",
            "record": { "$type": "com.example.record", "text": "second" },
            "swapRecord": first,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{replaced}");
    assert_ne!(replaced["cid"], first);

    let (status, body) = get(
        &router,
        "/xrpc/com.atproto.repo.getRecord\
         ?repo=alice.pds.example.com&collection=com.example.record&rkey=3jqfcqzm4fc2j",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["value"]["text"], "second");

    let (status, removed) = post(
        &router,
        "/xrpc/com.atproto.repo.deleteRecord",
        serde_json::json!({
            "repo": did.as_str(),
            "collection": "com.example.record",
            "rkey": "3jqfcqzm4fc2j",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{removed}");
    assert!(removed["commit"]["rev"].is_string());

    let (status, _) = get(
        &router,
        "/xrpc/com.atproto.repo.getRecord\
         ?repo=alice.pds.example.com&collection=com.example.record&rkey=3jqfcqzm4fc2j",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_set_of_writes_lands_under_one_commit_and_answers_in_order() {
    let (router, _manager, _data) = served();
    let did = account();

    let (status, applied) = post(
        &router,
        "/xrpc/com.atproto.repo.applyWrites",
        serde_json::json!({
            "repo": did.as_str(),
            "writes": [
                {
                    "$type": "com.atproto.repo.applyWrites#create",
                    "collection": "com.example.record",
                    "rkey": "3jqfcqzm4fa2j",
                    "value": { "$type": "com.example.record", "text": "first" },
                },
                {
                    "$type": "com.atproto.repo.applyWrites#create",
                    "collection": "com.example.record",
                    "rkey": "3jqfcqzm4fb2j",
                    "value": { "$type": "com.example.record", "text": "second" },
                },
            ],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{applied}");
    let results = applied["results"].as_array().expect("results");
    assert_eq!(results.len(), 2);
    assert_eq!(
        results[0]["$type"],
        "com.atproto.repo.applyWrites#createResult"
    );

    // Both went in under one revision, which is the point of the method.
    let (_, page) = get(
        &router,
        "/xrpc/com.atproto.repo.listRecords\
         ?repo=alice.pds.example.com&collection=com.example.record",
    )
    .await;
    assert_eq!(page["records"].as_array().expect("records").len(), 2);

    // A delete beside an update answers with the shape each one is owed.
    let (status, applied) = post(
        &router,
        "/xrpc/com.atproto.repo.applyWrites",
        serde_json::json!({
            "repo": did.as_str(),
            "writes": [
                {
                    "$type": "com.atproto.repo.applyWrites#update",
                    "collection": "com.example.record",
                    "rkey": "3jqfcqzm4fa2j",
                    "value": { "$type": "com.example.record", "text": "again" },
                },
                {
                    "$type": "com.atproto.repo.applyWrites#delete",
                    "collection": "com.example.record",
                    "rkey": "3jqfcqzm4fb2j",
                },
            ],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{applied}");
    let results = applied["results"].as_array().expect("results");
    assert_eq!(
        results[0]["$type"],
        "com.atproto.repo.applyWrites#updateResult"
    );
    assert_eq!(
        results[1]["$type"],
        "com.atproto.repo.applyWrites#deleteResult"
    );
    assert!(results[1].get("uri").is_none());
}

#[tokio::test]
async fn a_caller_may_only_write_to_the_repository_it_signed_in_as() {
    let (router, _manager, _data) = served();

    let (status, refused) = post(
        &router,
        "/xrpc/com.atproto.repo.createRecord",
        serde_json::json!({
            "repo": "did:plc:ewvi7nxzyoun6zhxrhs64oiz",
            "collection": "com.example.record",
            "record": { "$type": "com.example.record", "text": "nobody's" },
        }),
    )
    .await;
    // Nothing on this server answers to it, so it never reaches the check.
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    assert_eq!(refused["error"], "RepoNotFound");
}

#[tokio::test]
async fn an_account_past_its_write_budget_is_told_when_to_come_back() {
    let (router, limits, _data) = budgeted();
    let did = account();

    // Spent here rather than over five thousand requests, against the same
    // budget the handler reaches.
    while limits.writing(&did, limit::CREATE).is_none() {}

    let mut request = Request::builder()
        .method("POST")
        .uri("/xrpc/com.atproto.repo.createRecord")
        .header("content-type", "application/json")
        .header(
            "authorization",
            format!("Bearer {}", tokens().access(&did, Scope::Access)),
        )
        .body(Body::from(
            serde_json::json!({
                "repo": did.as_str(),
                "collection": "com.example.record",
                "record": { "$type": "com.example.record", "text": "one too many" },
            })
            .to_string(),
        ))
        .expect("a request");
    let peer: SocketAddr = "203.0.113.1:9000".parse().expect("an address");
    request.extensions_mut().insert(ConnectInfo(peer));

    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("the router answers");
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    // Refused with the one header that tells a client what to do about it.
    assert!(response.headers().contains_key("retry-after"));
}

#[tokio::test(flavor = "multi_thread")]
async fn every_write_an_account_takes_at_once_lands_in_order() {
    let (_router, manager, _data) = served();
    let did = account();

    // Well past what the retry behind the lock would allow, so this fails if
    // an account's writes ever stop being taken one at a time.
    let writing: Vec<_> = (0..32)
        .map(|n| {
            let (manager, did) = (Arc::clone(&manager), did.clone());
            tokio::spawn(async move {
                manager
                    .write(
                        &did,
                        vec![record(&format!("3jqfcqzm4h{n:02}j"), "mine").into()],
                        None,
                    )
                    .await
            })
        })
        .collect();
    let mut revs: Vec<String> = Vec::new();
    for write in writing {
        let written = write
            .await
            .expect("a task")
            .expect("it lands")
            .expect("a write");
        revs.push(written.rev.as_str().to_owned());
    }
    // Every one got a revision of its own, and they were minted in order.
    let mut sorted = revs.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), 32);

    for round in 0..10 {
        let (one, other) = (Arc::clone(&manager), Arc::clone(&manager));
        let (left, right) = (did.clone(), did.clone());
        let first = tokio::spawn(async move {
            one.write(
                &left,
                vec![record(&format!("3jqfcqzm4f{round}2j"), "mine").into()],
                None,
            )
            .await
        });
        let second = tokio::spawn(async move {
            other
                .write(
                    &right,
                    vec![record(&format!("3jqfcqzm4g{round}2j"), "theirs").into()],
                    None,
                )
                .await
        });
        first.await.expect("a task").expect("one lands");
        second.await.expect("a task").expect("the other lands");
    }

    let held = manager
        .records(
            &did,
            &"com.example.record".parse().expect("an NSID"),
            100,
            None,
            false,
        )
        .await
        .expect("reads");
    assert_eq!(held.len(), 52);
}

#[tokio::test]
async fn taking_out_a_key_holding_nothing_is_what_the_caller_wanted() {
    let (router, _manager, _data) = served();
    let did = account();

    let (status, removed) = post(
        &router,
        "/xrpc/com.atproto.repo.deleteRecord",
        serde_json::json!({
            "repo": did.as_str(),
            "collection": "com.example.record",
            "rkey": "3jqfcqzm4fc2j",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{removed}");
    assert_eq!(removed.get("commit"), None);

    let (status, written) = post(
        &router,
        "/xrpc/com.atproto.repo.createRecord",
        serde_json::json!({
            "repo": did.as_str(),
            "collection": "com.example.record",
            "rkey": "3jqfcqzm4fc2j",
            "record": { "$type": "com.example.record", "text": "first" },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{written}");

    let (status, removed) = post(
        &router,
        "/xrpc/com.atproto.repo.deleteRecord",
        serde_json::json!({
            "repo": did.as_str(),
            "collection": "com.example.record",
            "rkey": "3jqfcqzm4fc2j",
            "swapRecord": null,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{removed}");
    assert!(removed["commit"]["rev"].is_string());
}

#[tokio::test(flavor = "multi_thread")]
async fn deletes_racing_for_one_key_all_answer() {
    let (router, _manager, _data) = served();
    let did = account();

    for round in 0..20 {
        let rkey = format!("3jqfcqzm4f{round:02}j");
        let (status, _) = post(
            &router,
            "/xrpc/com.atproto.repo.createRecord",
            serde_json::json!({
                "repo": did.as_str(),
                "collection": "com.example.record",
                "rkey": rkey,
                "record": { "$type": "com.example.record", "text": "first" },
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // Only one of these takes the record out; the rest find the key empty
        // by the time they look, which is what the caller asked for either way.
        let racing: Vec<_> = (0..8)
            .map(|_| {
                let (router, rkey, did) = (router.clone(), rkey.clone(), did.clone());
                tokio::spawn(async move {
                    post(
                        &router,
                        "/xrpc/com.atproto.repo.deleteRecord",
                        serde_json::json!({
                            "repo": did.as_str(),
                            "collection": "com.example.record",
                            "rkey": rkey,
                        }),
                    )
                    .await
                })
            })
            .collect();

        for attempt in racing {
            let (status, body) = attempt.await.expect("a task");
            assert_eq!(status, StatusCode::OK, "round {round}: {body}");
        }
    }
}

#[tokio::test]
async fn a_delete_that_finds_nothing_still_reads_what_it_was_sent() {
    let (router, _manager, _data) = served();

    // The swap is parsed before the key is looked at, so the same request is
    // refused the same way whatever happens to be there.
    let (status, refused) = post(
        &router,
        "/xrpc/com.atproto.repo.deleteRecord",
        serde_json::json!({
            "repo": account().as_str(),
            "collection": "com.example.record",
            "rkey": "3jqfcqzm4fc2j",
            "swapCommit": "not a cid",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    assert_eq!(refused["error"], "InvalidSwap");
}

#[tokio::test]
async fn a_record_is_given_the_type_of_the_collection_it_goes_in() {
    let (router, _manager, _data) = served();
    let did = account();

    // Left out, so it is filled in: the other server does the same, and a
    // record that disagreed with it would land under a CID nothing expects.
    let (status, written) = post(
        &router,
        "/xrpc/com.atproto.repo.createRecord",
        serde_json::json!({
            "repo": did.as_str(),
            "collection": "com.example.record",
            "rkey": "3jqfcqzm4fc2j",
            "record": { "text": "first" },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{written}");

    let (status, held) = get(
        &router,
        "/xrpc/com.atproto.repo.getRecord\
         ?repo=alice.pds.example.com&collection=com.example.record&rkey=3jqfcqzm4fc2j",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(held["value"]["$type"], "com.example.record");

    let (status, refused) = post(
        &router,
        "/xrpc/com.atproto.repo.createRecord",
        serde_json::json!({
            "repo": did.as_str(),
            "collection": "com.example.record",
            "rkey": "3jqfcqzm4fd2j",
            "record": { "$type": "com.example.other", "text": "second" },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    assert!(
        refused["message"]
            .as_str()
            .expect("a message")
            .contains("expected com.example.record"),
        "{refused}"
    );
}

#[tokio::test]
async fn a_batch_asking_for_nothing_is_answered_with_nothing() {
    let (router, _manager, _data) = served();

    let (status, applied) = post(
        &router,
        "/xrpc/com.atproto.repo.applyWrites",
        serde_json::json!({ "repo": account().as_str(), "writes": [] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{applied}");
    assert_eq!(applied["results"].as_array().expect("results").len(), 0);
    assert_eq!(applied.get("commit"), None);
}

#[tokio::test]
async fn a_delete_that_finds_nothing_is_not_asked_what_it_swapped() {
    let (router, _manager, _data) = served();
    let did = account();

    // Nothing was there to have swapped, so a client retrying a delete whose
    // answer it never saw is told the same thing the first one would have.
    for swap in [
        serde_json::json!({ "swapRecord": "bafyreidfcltdzyzp4dmvoeohhrhi6z2lhsbhgorpuoqqzvpxrbfuspqsoq" }),
        serde_json::json!({ "swapCommit": "bafyreidfcltdzyzp4dmvoeohhrhi6z2lhsbhgorpuoqqzvpxrbfuspqsoq" }),
    ] {
        let mut input = serde_json::json!({
            "repo": did.as_str(),
            "collection": "com.example.record",
            "rkey": "3jqfcqzm4fc2j",
        });
        for (name, value) in swap.as_object().expect("an object") {
            input[name] = value.clone();
        }

        let (status, removed) = post(&router, "/xrpc/com.atproto.repo.deleteRecord", input).await;
        assert_eq!(status, StatusCode::OK, "{removed}");
        assert_eq!(removed.get("commit"), None);
    }
}

#[tokio::test]
async fn a_caller_is_refused_a_repository_that_is_not_the_one_it_signed_in_as() {
    let (router, _manager, _data) = served();

    let (status, refused) = post(
        &router,
        "/xrpc/com.atproto.repo.createRecord",
        serde_json::json!({
            "repo": somebody_else().as_str(),
            "collection": "com.example.record",
            "record": { "$type": "com.example.record", "text": "not mine" },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refused}");
    assert_eq!(refused["error"], "Forbidden");
}

#[tokio::test]
async fn a_record_is_given_the_collection_it_is_written_to_and_may_not_disagree() {
    let (router, manager, _data) = served();

    // Left out, so the server fills it in; `docs/porting.md` has what the key
    // being there settles besides the lexicon.
    let (status, written) = post(
        &router,
        "/xrpc/com.atproto.repo.createRecord",
        serde_json::json!({
            "repo": account().as_str(),
            "collection": "com.example.record",
            "rkey": "3jqfcqzm4fa2j",
            "record": { "text": "no type of its own" },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{written}");

    let held = manager
        .record(
            &account(),
            &"com.example.record".parse().expect("an NSID"),
            &"3jqfcqzm4fa2j".parse().expect("a record key"),
        )
        .await
        .expect("reads")
        .expect("a record");
    let Ipld::Map(fields) = manapds::repo::decode(&held.value).expect("decodes") else {
        panic!("a record is a map");
    };
    assert_eq!(
        fields.get("$type"),
        Some(&Ipld::String("com.example.record".to_owned()))
    );

    // Named as something else, which is the caller contradicting themselves.
    let (status, refused) = post(
        &router,
        "/xrpc/com.atproto.repo.createRecord",
        serde_json::json!({
            "repo": account().as_str(),
            "collection": "com.example.record",
            "rkey": "3jqfcqzm4fb2j",
            "record": { "$type": "com.example.other", "text": "mismatched" },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
}
