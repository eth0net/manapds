//! What listBlobs and listMissingBlobs answer, and who may ask.

use super::*;

/// One query, answered, signed in as the account.
async fn authorized(router: &NormalizePath<Router>, path: &str) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method("GET")
        .uri(path)
        .header(
            "authorization",
            format!("Bearer {}", tokens().access(&account(), Scope::Access)),
        )
        .body(Body::empty())
        .expect("a request");
    let peer: SocketAddr = "203.0.113.1:9000".parse().expect("an address");
    request.extensions_mut().insert(ConnectInfo(peer));

    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("the router answers");
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 256 * 1024)
        .await
        .expect("a body");
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

#[tokio::test]
async fn blobs_are_listed_in_cid_order_once_a_record_names_them() {
    let (router, _manager, _data) = served();
    let first = uploaded(&router, vec![1u8, 2, 3, 4]).await;
    let second = uploaded(&router, vec![5u8, 6, 7, 8]).await;
    let loose = uploaded(&router, vec![9u8, 10, 11, 12]).await;

    let (status, written) = holding(&router, "3jqfcqzm4fa2j", &first).await;
    assert_eq!(status, StatusCode::OK, "{written}");
    let rev = written["commit"]["rev"].as_str().expect("a rev").to_owned();
    let (status, written) = holding(&router, "3jqfcqzm4fb2j", &second).await;
    assert_eq!(status, StatusCode::OK, "{written}");

    let mut named = vec![link(&first), link(&second)];
    named.sort();

    let (status, page) = get(
        &router,
        &format!("/xrpc/com.atproto.sync.listBlobs?did={}", account()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(page["cids"], serde_json::json!(named));
    assert!(
        !page["cids"]
            .as_array()
            .expect("cids")
            .contains(&Value::String(link(&loose))),
        "an upload no record has claimed is not listed"
    );
    assert_eq!(page["cursor"], Value::Null);

    let (status, page) = get(
        &router,
        &format!("/xrpc/com.atproto.sync.listBlobs?did={}&limit=1", account()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(page["cids"], serde_json::json!([named[0]]));
    assert_eq!(page["cursor"], named[0]);

    let (status, page) = get(
        &router,
        &format!(
            "/xrpc/com.atproto.sync.listBlobs?did={}&limit=1&cursor={}",
            account(),
            named[0]
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(page["cids"], serde_json::json!([named[1]]));

    // Only what a record written after that revision names.
    let (status, page) = get(
        &router,
        &format!(
            "/xrpc/com.atproto.sync.listBlobs?did={}&since={rev}",
            account()
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(page["cids"], serde_json::json!([link(&second)]));

    // Both bounds at once, which is the only shape where their order matters:
    // a page that bound them the other way round would answer for neither.
    let early = "2222222222222";
    let (status, page) = get(
        &router,
        &format!(
            "/xrpc/com.atproto.sync.listBlobs?did={}&since={early}&limit=1",
            account()
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(page["cids"], serde_json::json!([named[0]]));

    let (status, page) = get(
        &router,
        &format!(
            "/xrpc/com.atproto.sync.listBlobs?did={}&since={early}&cursor={}",
            account(),
            named[0]
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(page["cids"], serde_json::json!([named[1]]));
}

#[tokio::test]
async fn blobs_are_listed_for_a_did_and_for_nothing_else() {
    let (router, _manager, _data) = served();

    let (status, refused) = get(
        &router,
        "/xrpc/com.atproto.sync.listBlobs?did=alice.pds.example.com",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");

    let (status, refused) = get(
        &router,
        "/xrpc/com.atproto.sync.listBlobs?did=did:plc:ewvi7nxzyoun6zhxrhs64oiz",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    assert_eq!(refused["error"], "RepoNotFound");
}

#[tokio::test]
async fn a_blob_a_record_names_and_nothing_uploaded_is_listed_as_missing() {
    let (router, _manager, data) = served();
    let first = uploaded(&router, vec![1u8, 2, 3, 4]).await;
    let second = uploaded(&router, vec![5u8, 6, 7, 8]).await;
    for (rkey, blob) in [
        ("3jqfcqzm4fa2j", &first),
        ("3jqfcqzm4fb2j", &first),
        ("3jqfcqzm4fc2j", &second),
    ] {
        let (status, written) = holding(&router, rkey, blob).await;
        assert_eq!(status, StatusCode::OK, "{written}");
    }

    let (status, page) = authorized(&router, "/xrpc/com.atproto.repo.listMissingBlobs").await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(page["blobs"], serde_json::json!([]));

    // A repository whose records arrived without the blobs they name, which
    // is the only way this server reaches that state.
    rusqlite::Connection::open(store::Directory::new(data.path()).actor_store(&account()))
        .expect("opens")
        .execute(r#"delete from "blob""#, [])
        .expect("deletes");

    let at = |rkey| format!("at://{}/com.example.record/{rkey}", account());
    // Two records name the first blob, and the earlier key is the one named.
    let mut expected = [
        (link(&first), at("3jqfcqzm4fa2j")),
        (link(&second), at("3jqfcqzm4fc2j")),
    ];
    expected.sort();

    let (status, page) = authorized(&router, "/xrpc/com.atproto.repo.listMissingBlobs").await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(
        page["blobs"],
        serde_json::json!([
            { "cid": expected[0].0, "recordUri": expected[0].1 },
            { "cid": expected[1].0, "recordUri": expected[1].1 },
        ])
    );
    assert_eq!(page["cursor"], Value::Null);

    let (status, page) =
        authorized(&router, "/xrpc/com.atproto.repo.listMissingBlobs?limit=1").await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(
        page["blobs"],
        serde_json::json!([{ "cid": expected[0].0, "recordUri": expected[0].1 }])
    );
    assert_eq!(page["cursor"], expected[0].0);

    let (status, page) = authorized(
        &router,
        &format!(
            "/xrpc/com.atproto.repo.listMissingBlobs?limit=1&cursor={}",
            expected[0].0
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(
        page["blobs"],
        serde_json::json!([{ "cid": expected[1].0, "recordUri": expected[1].1 }])
    );
}

#[tokio::test]
async fn the_blobs_an_account_is_missing_are_asked_for_with_its_own_session() {
    let (router, _manager, _data) = served();

    let (status, refused) = get(&router, "/xrpc/com.atproto.repo.listMissingBlobs").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{refused}");
}
