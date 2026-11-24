//! End-to-end PostgreSQL + Axum HTTP isolation, RBAC, lifecycle, cache, and
//! security-header integration tests for `bp-ent-httplib`.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use bp_ent_core::testkit::TestDb;
use bp_ent_core::{audit, AuthKind, Role};
use bp_ent_httplib::{migrator, standalone_router};
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

async fn send(
    app: &axum::Router,
    method: Method,
    uri: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, axum::http::HeaderMap, String) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(tok) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {tok}"));
    }
    let req = match body {
        Some(v) => builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(v.to_string()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    (status, headers, String::from_utf8_lossy(&bytes).into_owned())
}

fn assert_private_no_store(headers: &axum::http::HeaderMap) {
    assert_eq!(
        headers
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("private, no-store")
    );
    assert_eq!(
        headers.get(header::VARY).and_then(|v| v.to_str().ok()),
        Some("Authorization")
    );
    assert_eq!(
        headers
            .get(header::X_CONTENT_TYPE_OPTIONS)
            .and_then(|v| v.to_str().ok()),
        Some("nosniff")
    );
}

#[tokio::test]
async fn cross_tenant_httplib_and_librarian_isolation() {
    let Some(db) = TestDb::new([migrator()]).await else {
        return;
    };

    let tenant_a = db.tenant("acme").await;
    let tenant_b = db.tenant("globex").await;

    let lib_a = db.user_with(tenant_a, Role::Librarian, AuthKind::UserToken).await;
    let eng_a = db.user_with(tenant_a, Role::Engineer, AuthKind::UserToken).await;
    let lib_b = db.user_with(tenant_b, Role::Librarian, AuthKind::UserToken).await;

    let tok_lib_a = db.token(&lib_a, AuthKind::UserToken).await;
    let tok_eng_a = db.token(&eng_a, AuthKind::UserToken).await;
    let tok_lib_b = db.token(&lib_b, AuthKind::UserToken).await;

    let app = standalone_router(db.app_ctx());

    // 1. Unauthenticated request fails closed (401) and still carries no-store headers.
    let (status, headers, _) = send(&app, Method::GET, "/v1/librarian/parts", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_private_no_store(&headers);

    // 2. Create a part with IPC-7351 QFN-16 spec in Tenant A.
    let (status, headers, body) = send(
        &app,
        Method::POST,
        "/v1/librarian/parts",
        Some(&tok_lib_a),
        Some(json!({
            "partNumber": "BP-MCU-0001",
            "mpn": "RP2350A",
            "manufacturer": "Raspberry Pi",
            "category": "Microcontrollers",
            "value": "Dual Cortex-M33",
            "packageName": "QFN-60",
            "preferredByFab": true,
            "fabStockQty": 4200,
            "unitPriceUsd": 0.85,
            "datasheetUrl": "https://datasheets.raspberrypi.com/rp2350/rp2350-datasheet.pdf",
            "description": "Dual-core MCU",
            "ipcSpec": {
                "family": "QFN",
                "pinCount": 16,
                "pitchMm": 0.5,
                "bodyWidthMm": 4.0,
                "bodyLengthMm": 4.0,
                "padWidthMm": 0.28,
                "padLengthMm": 0.75,
                "thermalPadMm": 2.1
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create part failed: {body}");
    assert_private_no_store(&headers);
    let created: Value = serde_json::from_str(&body).unwrap();
    let part_a_id = created["id"].as_str().unwrap().to_string();
    let cat_a_id = created["categoryId"].as_str().unwrap().to_string();
    assert_eq!(created["lifecycle"], "Draft");

    // 3. Reject SSRF datasheet URLs on creation.
    let (status, _, _) = send(
        &app,
        Method::POST,
        "/v1/librarian/parts",
        Some(&tok_lib_a),
        Some(json!({
            "partNumber": "BP-BAD-0001",
            "mpn": "EVIL1",
            "manufacturer": "Evil",
            "category": "Misc",
            "datasheetUrl": "https://169.254.169.254/latest/meta-data/"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    // 4. Draft / In Review parts MUST NOT appear on default KiCad HTTP Library endpoints.
    let (status, _, body) = send(
        &app,
        Method::GET,
        &format!("/v1/httplib/acme/parts/category/{cat_a_id}.json"),
        Some(&tok_eng_a),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(serde_json::from_str::<Value>(&body).unwrap().as_array().unwrap().len(), 0);

    let (status, _, _) = send(
        &app,
        Method::GET,
        &format!("/v1/httplib/acme/parts/{part_a_id}.json"),
        Some(&tok_eng_a),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Engineer with PartsWrite may preview drafts via ?include=draft.
    let (status, _, _) = send(
        &app,
        Method::GET,
        &format!("/v1/httplib/acme/parts/{part_a_id}.json?include=draft"),
        Some(&tok_eng_a),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // 5. Lifecycle RBAC: Engineer cannot Release directly, can submit In Review, Librarian Releases.
    let (status, _, _) = send(
        &app,
        Method::POST,
        &format!("/v1/librarian/parts/{part_a_id}/lifecycle"),
        Some(&tok_eng_a),
        Some(json!({ "lifecycle": "Released" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _, _) = send(
        &app,
        Method::POST,
        &format!("/v1/librarian/parts/{part_a_id}/lifecycle"),
        Some(&tok_eng_a),
        Some(json!({ "lifecycle": "In Review" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Still hidden from default KiCad endpoints while In Review.
    let (status, _, _) = send(
        &app,
        Method::GET,
        &format!("/v1/httplib/acme/parts/{part_a_id}.json"),
        Some(&tok_eng_a),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _, body) = send(
        &app,
        Method::POST,
        &format!("/v1/librarian/parts/{part_a_id}/lifecycle"),
        Some(&tok_lib_a),
        Some(json!({ "lifecycle": "Released" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "release failed: {body}");

    // 6. LIKE wildcard escaping and 100-char query length cap.
    let (status, _, body) = send(
        &app,
        Method::GET,
        "/v1/librarian/parts?q=%25_%25",
        Some(&tok_lib_a),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(serde_json::from_str::<Value>(&body).unwrap().as_array().unwrap().len(), 0);

    let too_long = "a".repeat(101);
    let (status, _, _) = send(
        &app,
        Method::GET,
        &format!("/v1/librarian/parts?q={too_long}"),
        Some(&tok_lib_a),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    // 7. Upsert Where-Used and verify it appears on part detail.
    let (status, _, _) = send(
        &app,
        Method::PUT,
        &format!("/v1/librarian/parts/{part_a_id}/where-used"),
        Some(&tok_eng_a),
        Some(json!({
            "boardId": "motor-ctrl",
            "boardName": "BLDC Motor Controller",
            "revisionTag": "rev-c",
            "refdesList": ["U1", "U2"]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _, body) = send(
        &app,
        Method::GET,
        &format!("/v1/librarian/parts/{part_a_id}"),
        Some(&tok_lib_a),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let fetched: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(fetched["whereUsed"][0]["boardId"], "motor-ctrl");

    // 8. Mint scoped `parts:read` device token for KiCad HTTP Library.
    let (status, headers, body) = send(
        &app,
        Method::POST,
        "/v1/httplib/acme/tokens",
        Some(&tok_lib_a),
        Some(json!({ "label": "kicad-bench" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "mint token failed: {body}");
    assert_private_no_store(&headers);
    let tok_resp: Value = serde_json::from_str(&body).unwrap();
    let device_token_id = tok_resp["tokenId"].as_str().unwrap().to_string();
    let device_tok = tok_resp["token"].as_str().unwrap().to_string();
    assert!(device_tok.starts_with("bpe_d_"));

    // 9. Device token can read Released kicad_httplib endpoints and SVG previews, with strict headers,
    //    and cannot use ?include=draft.
    let (status, _, _) = send(
        &app,
        Method::GET,
        &format!("/v1/httplib/acme/parts/{part_a_id}.json?include=draft"),
        Some(&device_tok),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, headers, body) = send(
        &app,
        Method::GET,
        "/v1/httplib/acme/categories.json",
        Some(&device_tok),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_private_no_store(&headers);
    let cats: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(cats[0]["id"], cat_a_id);

    let (status, headers, body) = send(
        &app,
        Method::GET,
        &format!("/v1/httplib/acme/parts/category/{cat_a_id}.json"),
        Some(&device_tok),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_private_no_store(&headers);
    let summaries: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(summaries[0]["id"], part_a_id);

    let (status, headers, body) = send(
        &app,
        Method::GET,
        &format!("/v1/httplib/acme/parts/{part_a_id}.json"),
        Some(&device_tok),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_private_no_store(&headers);
    let detail: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(detail["fields"]["MPN"]["value"], "RP2350A");

    let (status, headers, svg) = send(
        &app,
        Method::GET,
        &format!("/v1/httplib/acme/artifacts/{part_a_id}/footprint_svg"),
        Some(&device_tok),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_private_no_store(&headers);
    assert_eq!(
        headers
            .get(header::CONTENT_SECURITY_POLICY)
            .and_then(|v| v.to_str().ok()),
        Some("default-src 'none'; sandbox")
    );
    assert!(svg.starts_with("<svg "));

    // Device token cannot mint tokens or mutate librarian parts.
    let (status, _, _) = send(
        &app,
        Method::POST,
        "/v1/httplib/acme/tokens",
        Some(&device_tok),
        Some(json!({ "label": "nested" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _, _) = send(
        &app,
        Method::POST,
        "/v1/librarian/parts",
        Some(&device_tok),
        Some(json!({
            "partNumber": "BP-NO-0001",
            "mpn": "X",
            "manufacturer": "Y",
            "category": "Z"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // 8. Cross-tenant isolation: Tenant B gets 404 (not 403!) on Tenant A's httplib slug,
    //    and 404 when querying Tenant A's part UUID even under Tenant B's own slug!
    for path in [
        "/v1/httplib/acme/categories.json".to_string(),
        format!("/v1/httplib/acme/parts/{part_a_id}.json"),
        format!("/v1/httplib/globex/parts/{part_a_id}.json"),
        format!("/v1/librarian/parts/{part_a_id}"),
        format!("/v1/librarian/parts/{}", Uuid::new_v4()),
    ] {
        let (status, headers, _) = send(&app, Method::GET, &path, Some(&tok_lib_b), None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "expected 404 for {path}");
        assert_private_no_store(&headers);
    }

    let (status, _, body) =
        send(&app, Method::GET, "/v1/librarian/parts", Some(&tok_lib_b), None).await;
    assert_eq!(status, StatusCode::OK);
    let b_parts: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(b_parts.as_array().unwrap().len(), 0);

    // 9. Open-in-KiCad deep-link endpoint.
    let (status, _, body) = send(
        &app,
        Method::GET,
        &format!("/v1/librarian/parts/{part_a_id}/open-in-kicad?target=boat_vm&vm_id=vm-1"),
        Some(&tok_eng_a),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let deep: Value = serde_json::from_str(&body).unwrap();
    assert!(deep["deepLink"]
        .as_str()
        .unwrap()
        .starts_with("backplane://open-kicad?"));

    // 10. Clone & mark Obsolete: Obsolete parts are hidden from KiCad even with ?include=draft.
    let (status, _, body) = send(
        &app,
        Method::POST,
        &format!("/v1/librarian/parts/{part_a_id}/clone"),
        Some(&tok_lib_a),
        Some(json!({ "partNumber": "BP-MCU-OBS" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let obs_id = serde_json::from_str::<Value>(&body).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    let (status, _, _) = send(
        &app,
        Method::POST,
        &format!("/v1/librarian/parts/{obs_id}/lifecycle"),
        Some(&tok_lib_a),
        Some(json!({ "lifecycle": "Obsolete" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _, _) = send(
        &app,
        Method::GET,
        &format!("/v1/httplib/acme/parts/{obs_id}.json?include=draft"),
        Some(&tok_eng_a),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // 11. List and revoke device tokens; revoked token fails with 401.
    let (status, _, body) = send(
        &app,
        Method::GET,
        "/v1/httplib/acme/tokens",
        Some(&tok_lib_a),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let tokens: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(tokens.as_array().unwrap().len(), 1);
    assert_eq!(tokens[0]["id"], device_token_id);
    assert!(tokens[0].get("token").is_none());

    let (status, _, _) = send(
        &app,
        Method::DELETE,
        &format!("/v1/httplib/acme/tokens/{device_token_id}"),
        Some(&tok_lib_a),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _, _) = send(
        &app,
        Method::GET,
        "/v1/httplib/acme/categories.json",
        Some(&device_tok),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // 12. Audit chain integrity check for Tenant A.
    let mut tx = db.app_ctx().db.tenant_tx(tenant_a).await.unwrap();
    let count = audit::verify_chain(&mut tx, tenant_a).await.unwrap();
    tx.commit().await.unwrap();
    assert!(count >= 6, "expected audit events recorded, got {count}");

    db.cleanup().await;
}
