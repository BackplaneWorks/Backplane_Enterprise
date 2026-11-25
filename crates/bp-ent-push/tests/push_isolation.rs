//! Strict per-user & cross-tenant isolation, token revocation, free-account
//! access, rate limiting, and dead-token retirement tests for `bp-ent-push`.

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use bp_ent_core::auth;
use bp_ent_core::rbac::Scopes;
use bp_ent_core::testkit::TestDb;
use bp_ent_core::{AuthKind, Permission, Role};
use bp_ent_push::apns::{ApnsDelivery, ApnsRequest, ApnsSender};
use bp_ent_push::{migrator, router_with_sender};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tower::ServiceExt;

#[derive(Clone)]
struct RecordedCall {
    token: String,
    topic: String,
    env: String,
    push_type: String,
    payload: Value,
}

#[derive(Default)]
struct MockApns {
    calls: Mutex<Vec<RecordedCall>>,
    next_response: Mutex<Option<ApnsDelivery>>,
}

impl MockApns {
    fn set_next(&self, d: ApnsDelivery) {
        *self.next_response.lock().unwrap() = Some(d);
    }

    fn take_calls(&self) -> Vec<RecordedCall> {
        std::mem::take(&mut *self.calls.lock().unwrap())
    }
}

#[async_trait]
impl ApnsSender for MockApns {
    fn mode(&self) -> &'static str {
        "mock"
    }

    async fn send(&self, req: ApnsRequest) -> ApnsDelivery {
        self.calls.lock().unwrap().push(RecordedCall {
            token: req.token.expose().clone(),
            topic: req.topic,
            env: req.env,
            push_type: req.push_type,
            payload: req.payload,
        });
        if let Some(d) = self.next_response.lock().unwrap().take() {
            return d;
        }
        ApnsDelivery {
            status: 200,
            apns_id: Some("mock-apns-id-1".into()),
            reason: None,
            dead: false,
        }
    }
}

async fn call(
    app: &Router,
    method: Method,
    path: &str,
    token: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let b = Request::builder()
        .method(method)
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {token}"));
    let req = match body {
        Some(v) => b
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(v.to_string()))
            .unwrap(),
        None => b.body(Body::empty()).unwrap(),
    };
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

#[tokio::test]
async fn push_enforces_strict_per_user_isolation_and_no_subscription_gate() {
    let Some(db) = TestDb::new([migrator()]).await else {
        return;
    };
    let mock = Arc::new(MockApns::default());
    let app = router_with_sender(db.app_ctx(), mock.clone(), 5);

    let tenant_a = db.tenant("acme-free").await;
    let tenant_b = db.tenant("other-org").await;

    // Free account users (no Stripe customer or subscription exists anywhere).
    let alice = db.user(tenant_a, Role::Engineer).await;
    let admin_a = db.user(tenant_a, Role::OrgAdmin).await;
    let bob_b = db.user(tenant_b, Role::OrgAdmin).await;

    let tok_alice = db.token(&alice, AuthKind::UserToken).await;
    let tok_admin_a = db.token(&admin_a, AuthKind::UserToken).await;
    let tok_bob_b = db.token(&bob_b, AuthKind::UserToken).await;

    // Narrow device token (e.g. KiCad httplib) must be rejected.
    let mut tx = db.app_ctx().db.tenant_tx(tenant_a).await.unwrap();
    let (_, dev_tok) = auth::issue_token(
        &mut tx,
        tenant_a,
        alice.user_id,
        AuthKind::DeviceToken,
        "kicad",
        &Scopes::Only(vec![Permission::PartsRead]),
        Duration::from_secs(600),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let (st, _) = call(&app, Method::GET, "/v1/push/devices", dev_tok.expose(), None).await;
    assert_eq!(st, StatusCode::FORBIDDEN);

    // Scoped UserToken (not Scopes::All) must also be rejected.
    let mut tx = db.app_ctx().db.tenant_tx(tenant_a).await.unwrap();
    let (_, scoped_tok) = auth::issue_token(
        &mut tx,
        tenant_a,
        alice.user_id,
        AuthKind::UserToken,
        "scoped",
        &Scopes::Only(vec![Permission::PartsRead]),
        Duration::from_secs(600),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let (st, _) = call(&app, Method::GET, "/v1/push/devices", scoped_tok.expose(), None).await;
    assert_eq!(st, StatusCode::FORBIDDEN);

    // Non-hex or too-short iOS APNs token must be rejected.
    let (st, _) = call(
        &app,
        Method::POST,
        "/v1/push/devices",
        &tok_alice,
        Some(json!({"token": "not-a-hex-token", "platform": "ios", "bundle": "dev.backplane.mobile"})),
    )
    .await;
    assert!(st.is_client_error(), "expected 4xx for non-hex token, got {st}");

    // 1. Alice registers her iPhone (free Engineer account, zero Stripe setup).
    let alice_apns_token = "aa11bb22cc33dd44ee55ff6600112233445566778899aabbccddeeff00112233";
    let (st, reg) = call(
        &app,
        Method::POST,
        "/v1/push/devices",
        &tok_alice,
        Some(json!({
            "token": alice_apns_token,
            "platform": "ios",
            "bundle": "dev.backplane.mobile",
            "env": "sandbox",
            "kind": "alert",
            "deviceName": "Alice iPhone"
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{reg}");
    let device_id = reg["id"].as_str().unwrap().to_string();
    let handle = reg["handle"].as_str().unwrap().to_string();
    assert_eq!(handle.len(), 12);

    // Raw token is never stored plaintext in Postgres or returned in GET /v1/push/devices.
    let raw_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM push_devices WHERE encode(token_enc, 'escape') LIKE '%aa11bb22%'",
    )
    .fetch_one(db.admin_pool())
    .await
    .unwrap();
    assert_eq!(raw_count, 0, "raw APNs token was stored unencrypted");

    let (st, list_alice) = call(&app, Method::GET, "/v1/push/devices", &tok_alice, None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(list_alice.as_array().unwrap().len(), 1);
    assert!(!list_alice.to_string().contains(alice_apns_token));

    // 2. Same-tenant OrgAdmin (different user!) CANNOT see, delete, or push to Alice's device.
    let (st, list_admin) = call(&app, Method::GET, "/v1/push/devices", &tok_admin_a, None).await;
    assert_eq!(st, StatusCode::OK);
    assert!(list_admin.as_array().unwrap().is_empty());

    let (st, push_admin) = call(
        &app,
        Method::POST,
        "/v1/push/send",
        &tok_admin_a,
        Some(json!({
            "targetHandle": handle,
            "payload": {"aps": {"alert": {"title": "Hijack", "body": "Nope"}}}
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(push_admin["sent"], 0);
    assert!(mock.take_calls().is_empty());

    let (st, _) = call(
        &app,
        Method::DELETE,
        &format!("/v1/push/devices/{device_id}"),
        &tok_admin_a,
        None,
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND);

    // 3. Different-tenant OrgAdmin CANNOT see, delete, or push to Alice's device.
    let (st, list_bob) = call(&app, Method::GET, "/v1/push/devices", &tok_bob_b, None).await;
    assert_eq!(st, StatusCode::OK);
    assert!(list_bob.as_array().unwrap().is_empty());

    let (st, push_bob) = call(
        &app,
        Method::POST,
        "/v1/push/send",
        &tok_bob_b,
        Some(json!({
            "targetHandle": handle,
            "payload": {"aps": {"alert": {"title": "CrossTenant", "body": "Nope"}}}
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(push_bob["sent"], 0);
    assert!(mock.take_calls().is_empty());

    let (st, _) = call(
        &app,
        Method::DELETE,
        &format!("/v1/push/devices/{device_id}"),
        &tok_bob_b,
        None,
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND);

    // 4. Alice pushes to her own device -> delivered.
    let (st, push_ok) = call(
        &app,
        Method::POST,
        "/v1/push/send",
        &tok_alice,
        Some(json!({
            "pushType": "alert",
            "priority": 10,
            "collapseId": "push-1",
            "payload": {"aps": {"alert": {"title": "Bub", "body": "Build ready"}, "badge": 1}}
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{push_ok}");
    assert_eq!(push_ok["sent"], 1);
    let calls = mock.take_calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].token, alice_apns_token);
    assert_eq!(calls[0].topic, "dev.backplane.mobile");
    assert_eq!(calls[0].env, "sandbox");
    assert_eq!(calls[0].push_type, "alert");
    assert_eq!(calls[0].payload["aps"]["alert"]["body"], "Build ready");

    // 5. Revoked token for Alice is immediately rejected everywhere.
    let p_alice = auth::verify_bearer(&db.app_ctx(), &tok_alice).await.unwrap();
    let mut tx = db.app_ctx().db.tenant_tx(tenant_a).await.unwrap();
    assert!(auth::revoke_token(&mut tx, tenant_a, p_alice.token_id)
        .await
        .unwrap());
    tx.commit().await.unwrap();

    for (m, path, body) in [
        (Method::GET, "/v1/push/devices", None),
        (
            Method::POST,
            "/v1/push/devices",
            Some(json!({"token": alice_apns_token, "platform": "ios", "bundle": "dev.backplane.mobile"})),
        ),
        (
            Method::POST,
            "/v1/push/send",
            Some(json!({"payload": {"aps": {"alert": "x"}}})),
        ),
    ] {
        let (st, _) = call(&app, m, path, &tok_alice, body).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
    }

    // 6. Fresh token for Alice: rate limit (5/min in test) + 410 retirement.
    let tok_alice2 = db.token(&alice, AuthKind::UserToken).await;
    mock.set_next(ApnsDelivery {
        status: 410,
        apns_id: None,
        reason: Some("Unregistered".into()),
        dead: true,
    });
    let (st, retired) = call(
        &app,
        Method::POST,
        "/v1/push/send",
        &tok_alice2,
        Some(json!({"payload": {"aps": {"alert": "bye"}}})),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(retired["retired"], 1);

    let (st, list_after) = call(&app, Method::GET, "/v1/push/devices", &tok_alice2, None).await;
    assert_eq!(st, StatusCode::OK);
    assert!(list_after.as_array().unwrap().is_empty());

    // Exhaust remaining rate limit (limit is 5/min; 2 calls already made above).
    for _ in 0..3 {
        let (st, _) = call(
            &app,
            Method::POST,
            "/v1/push/send",
            &tok_alice2,
            Some(json!({"payload": {"aps": {"alert": "ping"}}})),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
    }
    let (st, _) = call(
        &app,
        Method::POST,
        "/v1/push/send",
        &tok_alice2,
        Some(json!({"payload": {"aps": {"alert": "over"}}})),
    )
    .await;
    assert_eq!(st, StatusCode::TOO_MANY_REQUESTS);

    db.cleanup().await;
}

#[tokio::test]
async fn push_enforces_20_device_cap_per_user() {
    let Some(db) = TestDb::new([migrator()]).await else {
        return;
    };
    let mock = Arc::new(MockApns::default());
    let app = router_with_sender(db.app_ctx(), mock, 100);
    let tenant = db.tenant("cap-org").await;
    let user = db.user(tenant, Role::Engineer).await;
    let tok = db.token(&user, AuthKind::UserToken).await;

    for i in 0..20u8 {
        let token = format!("{i:02x}{}", "aa".repeat(31));
        let (st, _) = call(
            &app,
            Method::POST,
            "/v1/push/devices",
            &tok,
            Some(json!({"token": token, "platform": "ios", "bundle": "dev.backplane.mobile"})),
        )
        .await;
        assert_eq!(st, StatusCode::OK, "device {i} failed");
    }

    let token_21 = format!("ff{}", "bb".repeat(31));
    let (st, _) = call(
        &app,
        Method::POST,
        "/v1/push/devices",
        &tok,
        Some(json!({"token": token_21, "platform": "ios", "bundle": "dev.backplane.mobile"})),
    )
    .await;
    assert!(st.is_client_error(), "21st device must be rejected, got {st}");

    db.cleanup().await;
}

#[tokio::test]
async fn reregistering_token_moves_device_between_users_and_stops_old_owner_pushes() {
    let Some(db) = TestDb::new([migrator()]).await else {
        return;
    };
    let mock = Arc::new(MockApns::default());
    let app = router_with_sender(db.app_ctx(), mock.clone(), 50);
    let tenant = db.tenant("move-org").await;
    let user_a = db.user(tenant, Role::Engineer).await;
    let user_b = db.user(tenant, Role::Engineer).await;
    let tok_a = db.token(&user_a, AuthKind::UserToken).await;
    let tok_b = db.token(&user_b, AuthKind::UserToken).await;

    let shared_apns_token = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    let (st, _) = call(
        &app,
        Method::POST,
        "/v1/push/devices",
        &tok_a,
        Some(json!({"token": shared_apns_token, "platform": "ios", "bundle": "dev.backplane.mobile"})),
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    // Re-registering the same physical device token under User B moves ownership to User B.
    let (st, _) = call(
        &app,
        Method::POST,
        "/v1/push/devices",
        &tok_b,
        Some(json!({"token": shared_apns_token, "platform": "ios", "bundle": "dev.backplane.mobile"})),
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    let (st, list_a) = call(&app, Method::GET, "/v1/push/devices", &tok_a, None).await;
    assert_eq!(st, StatusCode::OK);
    assert!(list_a.as_array().unwrap().is_empty(), "old owner must no longer see the device");

    let (st, send_a) = call(
        &app,
        Method::POST,
        "/v1/push/send",
        &tok_a,
        Some(json!({"payload": {"aps": {"alert": "for-a"}}})),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(send_a["sent"], 0);
    assert!(mock.take_calls().is_empty());

    let (st, send_b) = call(
        &app,
        Method::POST,
        "/v1/push/send",
        &tok_b,
        Some(json!({"payload": {"aps": {"alert": "for-b"}}})),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(send_b["sent"], 1);
    assert_eq!(mock.take_calls().len(), 1);

    db.cleanup().await;
}
