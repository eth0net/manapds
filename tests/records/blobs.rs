//! Uploading a blob, holding it with a record, and sweeping it when none does.

use super::*;

/// How many files a directory holds.
fn files(directory: &std::path::Path) -> usize {
    std::fs::read_dir(directory)
        .expect("a directory")
        .filter(|entry| entry.as_ref().expect("an entry").path().is_file())
        .count()
}

/// Puts every file in a directory this many hours into the past, which is the
/// only way a test reaches a window measured in them.
fn aged(directory: &std::path::Path, hours: i64) {
    let when = std::time::SystemTime::from(
        jiff::Timestamp::now() - jiff::SignedDuration::from_hours(hours),
    );
    for entry in std::fs::read_dir(directory).expect("a directory") {
        std::fs::File::options()
            .write(true)
            .open(entry.expect("an entry").path())
            .expect("a file")
            .set_times(std::fs::FileTimes::new().set_modified(when))
            .expect("the time is set");
    }
}

#[tokio::test]
async fn a_blob_is_taken_in_and_handed_back_as_it_was_sent() {
    let (router, _manager, _data) = served();
    let did = account();

    let mut request = Request::builder()
        .method("POST")
        .uri("/xrpc/com.atproto.repo.uploadBlob")
        .header("content-type", "image/png; charset=binary")
        .header(
            "authorization",
            format!("Bearer {}", tokens().access(&did, Scope::Access)),
        )
        .body(Body::from(vec![1u8, 2, 3, 4]))
        .expect("a request");
    let peer: SocketAddr = "203.0.113.1:9000".parse().expect("an address");
    request.extensions_mut().insert(ConnectInfo(peer));
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("the router answers");
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("a body");
    let uploaded: Value = serde_json::from_slice(&body).expect("json");

    // The answer is the shape a record refers to a blob by, rather than a
    // bare CID: a client writes it straight into the record it is making.
    assert_eq!(uploaded["blob"]["$type"], "blob");
    // The charset says nothing about the bytes, and an appview matches the
    // type against its lexicon.
    assert_eq!(uploaded["blob"]["mimeType"], "image/png");
    assert_eq!(uploaded["blob"]["size"], 4);
    let cid = uploaded["blob"]["ref"]["$link"]
        .as_str()
        .expect("a link")
        .to_owned();

    // An upload holds nothing until a record names it, and holds nothing to
    // serve either.
    let unclaimed = get(
        &router,
        &format!("/xrpc/com.atproto.sync.getBlob?did={did}&cid={cid}"),
    )
    .await;
    assert_eq!(unclaimed.0, StatusCode::BAD_REQUEST);
    let (status, written) = holding(&router, "3jqfcqzm4fa2j", &uploaded["blob"]).await;
    assert_eq!(status, StatusCode::OK, "{written}");

    let mut request = Request::builder()
        .method("GET")
        .uri(format!(
            "/xrpc/com.atproto.sync.getBlob?did={did}&cid={cid}"
        ))
        .body(Body::empty())
        .expect("a request");
    request.extensions_mut().insert(ConnectInfo(peer));
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("the router answers");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .expect("a type")
            .to_str()
            .expect("text"),
        "image/png"
    );
    let served = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("a body");
    assert_eq!(served.to_vec(), vec![1u8, 2, 3, 4]);
}

#[tokio::test]
async fn an_upload_past_the_limit_is_refused_in_the_shape_a_client_reads() {
    let (router, _manager, _data) = served();

    // Past the configured ceiling, which is the one body this server reads
    // whole and so the one refusal that has to be built rather than inherited.
    let mut request = Request::builder()
        .method("POST")
        .uri("/xrpc/com.atproto.repo.uploadBlob")
        .header("content-type", "image/png")
        .header(
            "authorization",
            format!("Bearer {}", tokens().access(&account(), Scope::Access)),
        )
        .body(Body::from(vec![0u8; 6 * 1024 * 1024]))
        .expect("a request");
    request.extensions_mut().insert(ConnectInfo(
        "203.0.113.1:9000"
            .parse::<SocketAddr>()
            .expect("an address"),
    ));

    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("the router answers");
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("a body");
    let refused: Value = serde_json::from_slice(&body).expect("the XRPC error shape");
    assert_eq!(refused["error"], "PayloadTooLarge");
}

#[tokio::test]
async fn a_blob_is_kept_while_a_record_names_it_and_dropped_when_none_does() {
    let (router, _manager, _data) = served();
    let blob = uploaded(&router, vec![1u8, 2, 3, 4]).await;
    let cid: manapds::repo::Cid = blob["ref"]["$link"]
        .as_str()
        .expect("a link")
        .parse()
        .expect("a CID");
    let (status, written) = holding(&router, "3jqfcqzm4fa2j", &blob).await;
    assert_eq!(status, StatusCode::OK, "{written}");

    // A second record naming it too, so taking the first out leaves it alone.
    let (status, written) = holding(&router, "3jqfcqzm4fb2j", &blob).await;
    assert_eq!(status, StatusCode::OK, "{written}");

    let (status, _) = post(
        &router,
        "/xrpc/com.atproto.repo.deleteRecord",
        serde_json::json!({
            "repo": account().as_str(),
            "collection": "com.example.record",
            "rkey": "3jqfcqzm4fa2j",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = get(
        &router,
        &format!("/xrpc/com.atproto.sync.getBlob?did={}&cid={cid}", account()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "still held by the other record");

    // The last record naming it goes, and so does the blob.
    let (status, _) = post(
        &router,
        "/xrpc/com.atproto.repo.deleteRecord",
        serde_json::json!({
            "repo": account().as_str(),
            "collection": "com.example.record",
            "rkey": "3jqfcqzm4fb2j",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, gone) = get(
        &router,
        &format!("/xrpc/com.atproto.sync.getBlob?did={}&cid={cid}", account()),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{gone}");
}

#[tokio::test]
async fn a_record_naming_a_blob_nobody_uploaded_is_refused() {
    let (router, _manager, _data) = served();

    let (status, refused) = holding(
        &router,
        "3jqfcqzm4fa2j",
        &serde_json::json!({
            "$type": "blob",
            "ref": { "$link": "bafkreidfcltdzyzp4dmvoeohhrhi6z2lhsbhgorpuoqqzvpxrbfuspqsoq" },
            "mimeType": "image/png",
            "size": 4,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    assert_eq!(refused["error"], "BlobNotFound");

    // And nothing was written, since the blob is checked under the commit.
    let (status, _) = get(
        &router,
        "/xrpc/com.atproto.repo.getRecord\
         ?repo=alice.pds.example.com&collection=com.example.record&rkey=3jqfcqzm4fa2j",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_record_that_lies_about_a_blob_is_refused() {
    let (router, _manager, _data) = served();
    let mut blob = uploaded(&router, vec![1u8, 2, 3, 4]).await;
    blob["size"] = serde_json::json!(999);

    let (status, refused) = holding(&router, "3jqfcqzm4fa2j", &blob).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    assert_eq!(refused["error"], "InvalidSize");
}

#[tokio::test]
async fn a_batch_that_writes_one_key_twice_leaves_no_blob_behind() {
    let (router, manager, _data) = served();
    let blob = uploaded(&router, vec![1u8, 2, 3, 4]).await;
    let cid: manapds::repo::Cid = blob["ref"]["$link"]
        .as_str()
        .expect("a link")
        .parse()
        .expect("a CID");

    // Written and taken out again under one commit, so the record that named
    // the blob is gone by the time the commit lands.
    let (status, applied) = post(
        &router,
        "/xrpc/com.atproto.repo.applyWrites",
        serde_json::json!({
            "repo": account().as_str(),
            "writes": [
                {
                    "$type": "com.atproto.repo.applyWrites#create",
                    "collection": "com.example.record",
                    "rkey": "3jqfcqzm4fa2j",
                    "value": { "$type": "com.example.record", "image": blob },
                },
                {
                    "$type": "com.atproto.repo.applyWrites#delete",
                    "collection": "com.example.record",
                    "rkey": "3jqfcqzm4fa2j",
                },
            ],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{applied}");

    // Nothing names it, so nothing serves it — and nothing is left that only a
    // sweep could reach, since claiming it cleared what the sweep looks for.
    let (status, gone) = get(
        &router,
        &format!("/xrpc/com.atproto.sync.getBlob?did={}&cid={cid}", account()),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{gone}");
    assert_eq!(
        manager.sweep_blobs(&account()).await.expect("sweeps"),
        0,
        "the sweep cannot reach a claimed blob, so it must not be left one"
    );
}

#[tokio::test]
async fn uploading_a_blob_twice_leaves_one_file_the_sweep_takes() {
    let (router, manager, data) = served();
    uploaded(&router, vec![1u8, 2, 3, 4]).await;
    uploaded(&router, vec![1u8, 2, 3, 4]).await;

    let uploads = data
        .path()
        .join("blocks")
        .join("tempt")
        .join(account().as_str());
    assert_eq!(files(&uploads), 2, "each upload writes a file of its own");

    // Both are young, and a sweep that took the one the row let go of would
    // be one upload away from taking a blob somebody is still writing around.
    assert_eq!(manager.sweep_blobs(&account()).await.expect("sweeps"), 0);
    assert_eq!(files(&uploads), 2);

    aged(&uploads, 48);
    assert_eq!(manager.sweep_blobs(&account()).await.expect("sweeps"), 1);
    assert_eq!(files(&uploads), 1, "the row still names one of them");
}

#[tokio::test]
async fn a_served_file_no_row_holds_is_reconciled_once_the_window_is_past() {
    let (router, manager, data) = served();
    let blob = uploaded(&router, vec![1u8, 2, 3, 4]).await;
    let (status, written) = holding(&router, "3jqfcqzm4fa2j", &blob).await;
    assert_eq!(status, StatusCode::OK, "{written}");

    // What a process that died between dropping a row and unlinking the file
    // behind it leaves.
    let stored = data.path().join("blocks").join(account().as_str());
    let orphan = stored.join(store::blobs::cid_for(b"orphan").to_string());
    std::fs::write(&orphan, b"orphan").expect("a file");

    assert_eq!(manager.reconcile().await.expect("reconciles"), 0);
    assert!(orphan.is_file(), "nothing inside the window is reclaimed");

    aged(&stored, 48);
    assert_eq!(manager.reconcile().await.expect("reconciles"), 1);
    assert!(!orphan.exists());
    assert_eq!(files(&stored), 1, "the blob a record names is still served");
}

#[tokio::test]
async fn a_second_record_naming_a_blob_is_taken_at_what_the_first_settled() {
    let (router, _manager, _data) = served();
    let blob = uploaded(&router, vec![1u8, 2, 3, 4]).await;

    let (status, written) = holding(&router, "3jqfcqzm4fa2j", &blob).await;
    assert_eq!(status, StatusCode::OK, "{written}");

    // The size and the type are checked where the blob stops being an upload,
    // so a second record carrying a hand-written reference is not asked again.
    let mut loose = blob;
    loose["mimeType"] = serde_json::json!("image/jpeg");
    let (status, written) = holding(&router, "3jqfcqzm4fb2j", &loose).await;
    assert_eq!(status, StatusCode::OK, "{written}");
}

#[tokio::test]
async fn a_record_holding_something_that_claims_to_be_a_blob_is_refused() {
    let (router, manager, _data) = served();

    // Each of these is blob-shaped and is not a blob reference. Taking the
    // record would leave it pointing at bytes nothing is keeping, so a sweep
    // would later take them out from under it.
    for bad in [
        serde_json::json!({
            "$type": "blob",
            "ref": { "$link": "bafkreidfcltdzyzp4dmvoeohhrhi6z2lhsbhgorpuoqqzvpxrbfuspqsoq" },
            "mimeType": "image/png",
            "size": -1,
        }),
        serde_json::json!({
            "cid": "bafkreidfcltdzyzp4dmvoeohhrhi6z2lhsbhgorpuoqqzvpxrbfuspqsoq",
            "mimeType": "image/png",
            "$type": "blob",
        }),
        serde_json::json!({
            "$type": "blob",
            "ref": { "$link": "bafkreidfcltdzyzp4dmvoeohhrhi6z2lhsbhgorpuoqqzvpxrbfuspqsoq" },
            "mimeType": "notamimetype",
            "size": 4,
        }),
    ] {
        let (status, refused) = holding(&router, "3jqfcqzm4fa2j", &bad).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    }

    // And nothing was written under any of them.
    assert_eq!(
        manager
            .records(
                &account(),
                &"com.example.record".parse().expect("an NSID"),
                10,
                None,
                false
            )
            .await
            .expect("reads")
            .len(),
        0
    );
}

#[tokio::test]
async fn a_batch_that_does_not_commit_serves_none_of_its_blobs() {
    let (router, _manager, _data) = served();
    let blob = uploaded(&router, vec![1u8, 2, 3, 4]).await;
    let cid = blob["ref"]["$link"].as_str().expect("a link").to_owned();

    // The second write names a blob nobody uploaded, so nothing commits — and
    // the first write's blob must not be left readable by that.
    let (status, refused) = post(
        &router,
        "/xrpc/com.atproto.repo.applyWrites",
        serde_json::json!({
            "repo": account().as_str(),
            "writes": [
                {
                    "$type": "com.atproto.repo.applyWrites#create",
                    "collection": "com.example.record",
                    "rkey": "3jqfcqzm4fa2j",
                    "value": { "$type": "com.example.record", "image": blob },
                },
                {
                    "$type": "com.atproto.repo.applyWrites#create",
                    "collection": "com.example.record",
                    "rkey": "3jqfcqzm4fb2j",
                    "value": {
                        "$type": "com.example.record",
                        "image": {
                            "$type": "blob",
                            "ref": { "$link": "bafkreidfcltdzyzp4dmvoeohhrhi6z2lhsbhgorpuoqqzvpxrbfuspqsoq" },
                            "mimeType": "image/png",
                            "size": 4,
                        },
                    },
                },
            ],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");

    let (status, served) = get(
        &router,
        &format!("/xrpc/com.atproto.sync.getBlob?did={}&cid={cid}", account()),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{served}");
}
