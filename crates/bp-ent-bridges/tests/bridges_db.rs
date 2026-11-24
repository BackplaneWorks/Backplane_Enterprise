//! End-to-end DB + RLS + Axum router security & functional tests for `bp-ent-bridges`.

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use bp_ent_bridges::model::BridgeEvent;
use bp_ent_bridges::outbound::{dispatch_event_with, OutboundTransport};
use bp_ent_bridges::routes::{router_with_svc, BridgesSvc};
use bp_ent_bridges::signatures::{sign_bp_hmac, sign_slack_v0, StaticJwksProvider};
use bp_ent_core::testkit::{TestDb, TEST_ORIGIN};
use bp_ent_core::{audit, AuthKind, Result, Role};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use sqlx::Row;
use std::sync::{Arc, Mutex};
use time::OffsetDateTime;
use tower::ServiceExt;

async fn setup() -> Option<TestDb> {
    TestDb::new([bp_ent_bridges::migrator()]).await
}

fn authed_req(method: Method, uri: &str, token: &str, body: Option<Value>) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .header("origin", TEST_ORIGIN);
    if let Some(json_body) = body {
        b = b.header("content-type", "application/json");
        b.body(Body::from(json_body.to_string())).unwrap()
    } else {
        b.body(Body::empty()).unwrap()
    }
}

async fn read_json(resp: axum::response::Response) -> (StatusCode, Value) {
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let val = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, val)
}

type RecordedSend = (String, Vec<(String, String)>, Vec<u8>);

#[derive(Default)]
struct RecordingTransport {
    sent: Mutex<Vec<RecordedSend>>,
}

#[async_trait::async_trait]
impl OutboundTransport for RecordingTransport {
    async fn send(
        &self,
        url: &str,
        payload: &bp_ent_bridges::adapters::OutboundHttpPayload,
    ) -> Result<u16> {
        self.sent
            .lock()
            .unwrap()
            .push((url.to_string(), payload.headers.clone(), payload.body.clone()));
        Ok(200)
    }
}

#[tokio::test]
async fn bridge_lifecycle_envelope_encryption_and_cross_tenant_isolation() {
    let Some(db) = setup().await else { return };
    let t_a = db.tenant("acme-bridges").await;
    let t_b = db.tenant("beta-bridges").await;

    let admin_a = db.user_with(t_a, Role::OrgAdmin, AuthKind::UserToken).await;
    let eng_a = db.user_with(t_a, Role::Engineer, AuthKind::UserToken).await;
    let admin_b = db.user_with(t_b, Role::OrgAdmin, AuthKind::UserToken).await;

    let tok_admin_a = db.token(&admin_a, AuthKind::UserToken).await;
    let tok_eng_a = db.token(&eng_a, AuthKind::UserToken).await;
    let tok_admin_b = db.token(&admin_b, AuthKind::UserToken).await;

    let app = bp_ent_bridges::router(db.app_ctx());

    // Non-admin engineer cannot create or list bridges.
    let (st, _) = read_json(
        app.clone()
            .oneshot(authed_req(Method::GET, "/v1/bridges", &tok_eng_a, None))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);

    // SSRF target URLs must be rejected at creation time.
    for bad_url in [
        "http://hooks.example.com/in",
        "https://169.254.169.254/latest/meta-data/",
        "https://127.0.0.1/hook",
        "https://localhost/hook",
    ] {
        let (st, _) = read_json(
            app.clone()
                .oneshot(authed_req(
                    Method::POST,
                    "/v1/bridges",
                    &tok_admin_a,
                    Some(json!({
                        "name": "bad",
                        "kind": "webhook",
                        "direction": "outbound",
                        "targetUrl": bad_url,
                        "subscribedEvents": ["room.post"]
                    })),
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "bad url: {bad_url}");
    }

    // Elevated peer scopes must be rejected.
    let (st, _) = read_json(
        app.clone()
            .oneshot(authed_req(
                Method::POST,
                "/v1/bridges",
                &tok_admin_a,
                Some(json!({
                    "name": "overprivileged-bot",
                    "kind": "a2a",
                    "direction": "bidirectional",
                    "targetUrl": "https://bot.example.com/hook",
                    "subscribedEvents": ["room.post"],
                    "peerEnabled": true,
                    "peerScopes": ["parts:read"]
                })),
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY);

    // Create a valid Dots/Grok bidirectional webhook bridge in tenant A.
    let (st, created) = read_json(
        app.clone()
            .oneshot(authed_req(
                Method::POST,
                "/v1/bridges",
                &tok_admin_a,
                Some(json!({
                    "name": "Grok + Dots Ops",
                    "kind": "webhook",
                    "direction": "bidirectional",
                    "targetUrl": "https://bots.example.com/dots-grok",
                    "subscribedEvents": ["room.post", "order.status_changed"],
                    "rateLimitRpm": 30,
                    "peerEnabled": true,
                    "peerScopes": ["boards:read", "boards:comment"]
                })),
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let bridge_id = created["bridge"]["id"].as_str().unwrap().to_string();
    let public_id = created["bridge"]["publicId"].as_str().unwrap().to_string();
    let inbound_secret = created["inboundSecretOnce"].as_str().unwrap().to_string();
    let outbound_secret = created["outboundSecretOnce"].as_str().unwrap().to_string();
    assert!(inbound_secret.starts_with("bps_"));
    assert!(outbound_secret.starts_with("bpo_"));

    // Verify plaintext secrets are NOT stored in PostgreSQL (envelope-encrypted).
    let raw_row = sqlx::query("SELECT inbound_secret_sealed, outbound_secret_sealed FROM bridges WHERE id = $1::uuid")
        .bind(&bridge_id)
        .fetch_one(db.admin_pool())
        .await
        .unwrap();
    let in_blob: Vec<u8> = raw_row.get("inbound_secret_sealed");
    let out_blob: Vec<u8> = raw_row.get("outbound_secret_sealed");
    assert_eq!(&in_blob[..4], b"BPE1");
    assert_eq!(&out_blob[..4], b"BPE1");
    assert!(!in_blob.windows(inbound_secret.len()).any(|w| w == inbound_secret.as_bytes()));
    assert!(!out_blob.windows(outbound_secret.len()).any(|w| w == outbound_secret.as_bytes()));

    // List bridges never leaks raw secret.
    let (st, list_val) = read_json(
        app.clone()
            .oneshot(authed_req(Method::GET, "/v1/bridges", &tok_admin_a, None))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(list_val.as_array().unwrap().len(), 1);
    assert!(!list_val.to_string().contains(&inbound_secret));

    // Tenant B gets empty list and 404 on Tenant A's bridge ID.
    let (st, b_list) = read_json(
        app.clone()
            .oneshot(authed_req(Method::GET, "/v1/bridges", &tok_admin_b, None))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(b_list.as_array().unwrap().len(), 0);

    let (st, _) = read_json(
        app.clone()
            .oneshot(authed_req(
                Method::GET,
                &format!("/v1/bridges/{bridge_id}"),
                &tok_admin_b,
                None,
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND);

    // Cross-tenant forged public_id (tenant B's hex + tenant A's bridge hex) fails 401.
    let forged_pub_id = format!("bpb_{}_{}", t_b.0.simple(), bridge_id.replace('-', ""));
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let body_bytes = br#"{"eventId":"d1","text":"hi"}"#;
    let sig = sign_bp_hmac(inbound_secret.as_bytes(), body_bytes, now);
    let (st, _) = read_json(
        app.clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("/v1/bridges/{forged_pub_id}/inbound"))
                    .header("content-type", "application/json")
                    .header("x-bp-signature", &sig)
                    .header("x-bp-delivery", "d1")
                    .body(Body::from(body_bytes.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);

    // Valid inbound webhook succeeds -> 202 + quarantined message + replay dedupe -> 409.
    let inbound_body = br##"{"eventId":"del-100","actor":"grok-bot","channel":"#rev4","text":"<b>Check</b> <script>x</script> C12"}"##;
    let inbound_sig = sign_bp_hmac(inbound_secret.as_bytes(), inbound_body, now);
    let (st, acc) = read_json(
        app.clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("/v1/bridges/{public_id}/inbound"))
                    .header("content-type", "application/json")
                    .header("x-bp-signature", &inbound_sig)
                    .header("x-bp-delivery", "del-100")
                    .body(Body::from(inbound_body.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::ACCEPTED);
    assert_eq!(acc["trustLevel"], "untrusted_external");

    // Exact replay of del-100 -> idempotent 200 OK {"status": "duplicate"} (no second message stored).
    let (st, dup) = read_json(
        app.clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("/v1/bridges/{public_id}/inbound"))
                    .header("content-type", "application/json")
                    .header("x-bp-signature", &inbound_sig)
                    .header("x-bp-delivery", "del-100")
                    .body(Body::from(inbound_body.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(dup["status"], "duplicate");
    assert_eq!(dup["deliveryId"], "del-100");
    let msg_count: i64 = sqlx::query_scalar("SELECT count(*) FROM bridge_messages WHERE bridge_id = $1::uuid")
        .bind(&bridge_id)
        .fetch_one(db.admin_pool())
        .await
        .unwrap();
    assert_eq!(msg_count, 1);

    // Outbound event dispatch delivers signed JSON via OutboundTransport.
    let transport = RecordingTransport::default();
    let deliveries = dispatch_event_with(
        &db.app_ctx(),
        &transport,
        t_a,
        &BridgeEvent::OrderStatusChanged {
            order_ref: "BP-23456789AB".into(),
            from_status: "ordered".into(),
            to_status: "shipped".into(),
            updated_at: "2026-11-23T17:10:00Z".into(),
        },
    )
    .await
    .unwrap();
    assert_eq!(deliveries.len(), 1);
    assert_eq!(deliveries[0].status, "delivered");
    {
        let sent = transport.sent.lock().unwrap();
        assert_eq!(sent[0].0, "https://bots.example.com/dots-grok");
        assert!(sent[0].1.iter().any(|(k, _)| k == "x-bp-signature"));
    }

    // A2A Scoped External Peer: tools/list, boards.post_comment, forbidden tool, action.propose -> approval gate!
    let rpc_list = br#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#;
    let (st, list_res) = read_json(
        app.clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("/v1/bridges/{public_id}/a2a"))
                    .header("content-type", "application/json")
                    .header("x-bp-signature", sign_bp_hmac(inbound_secret.as_bytes(), rpc_list, now))
                    .header("x-bp-delivery", "a2a-1")
                    .body(Body::from(rpc_list.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let tools = list_res["result"]["tools"].as_array().unwrap();
    assert!(tools.iter().any(|t| t["name"] == "boards.post_comment"));
    assert!(!tools.iter().any(|t| t["name"].as_str().unwrap().contains("httplib")));

    // Attempt forbidden tool `httplib.get_part` -> 403 Forbidden.
    let rpc_bad = br#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"httplib.get_part","arguments":{}}}"#;
    let (st, _) = read_json(
        app.clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("/v1/bridges/{public_id}/a2a"))
                    .header("content-type", "application/json")
                    .header("x-bp-signature", sign_bp_hmac(inbound_secret.as_bytes(), rpc_bad, now))
                    .header("x-bp-delivery", "a2a-2")
                    .body(Body::from(rpc_bad.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);

    // Propose an action -> goes into `approval_requests` as pending_approval.
    let rpc_prop = br#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"action.propose","arguments":{"subject":"board:rev4","summary":"Update R12 value"}}}"#;
    let (st, prop_res) = read_json(
        app.clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("/v1/bridges/{public_id}/a2a"))
                    .header("content-type", "application/json")
                    .header("x-bp-signature", sign_bp_hmac(inbound_secret.as_bytes(), rpc_prop, now))
                    .header("x-bp-delivery", "a2a-3")
                    .body(Body::from(rpc_prop.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(prop_res["result"]["status"], "pending_approval");
    assert!(prop_res["result"]["approvalRequestId"].as_str().is_some());

    // Rotate secret -> invalidates old secret.
    let (st, rot) = read_json(
        app.clone()
            .oneshot(authed_req(
                Method::POST,
                &format!("/v1/bridges/{bridge_id}/rotate-secret"),
                &tok_admin_a,
                None,
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let new_in = rot["inboundSecretOnce"].as_str().unwrap();
    assert_ne!(new_in, inbound_secret);

    // Verify per-tenant audit hash chain is completely intact.
    let mut tx = db.app_ctx().db.tenant_tx(t_a).await.unwrap();
    let count = audit::verify_chain(&mut tx, t_a).await.unwrap();
    assert!(count >= 5);
    tx.commit().await.unwrap();

    db.cleanup().await;
}

#[tokio::test]
async fn native_slack_and_discord_inbound_challenges_through_router() {
    let Some(db) = setup().await else { return };
    let t = db.tenant("native-adapters").await;
    let admin = db.user_with(t, Role::OrgAdmin, AuthKind::UserToken).await;
    let tok = db.token(&admin, AuthKind::UserToken).await;

    let svc = BridgesSvc::with_jwks(db.app_ctx(), Arc::new(StaticJwksProvider::default()));
    let app = router_with_svc(svc);
    let now = OffsetDateTime::now_utc().unix_timestamp();

    // 1. Slack url_verification
    let slack_sec = "slack_signing_secret_live_test";
    let (st, slack_created) = read_json(
        app.clone()
            .oneshot(authed_req(
                Method::POST,
                "/v1/bridges",
                &tok,
                Some(json!({
                    "name": "Slack HW",
                    "kind": "slack",
                    "direction": "inbound",
                    "inboundSigningSecret": slack_sec,
                    "adapterConfig": { "slackChannel": "#hw" }
                })),
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let slack_pub = slack_created["bridge"]["publicId"].as_str().unwrap();
    let slack_body = br#"{"type":"url_verification","challenge":"chk_slack_1"}"#;
    let slack_sig = sign_slack_v0(slack_sec.as_bytes(), now, slack_body);
    let (st, slack_resp) = read_json(
        app.clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("/v1/bridges/{slack_pub}/inbound"))
                    .header("content-type", "application/json")
                    .header("x-slack-request-timestamp", now.to_string())
                    .header("x-slack-signature", slack_sig)
                    .body(Body::from(slack_body.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(slack_resp["challenge"], "chk_slack_1");

    // 2. Discord Ed25519 PING
    let sk = SigningKey::from_bytes(&[9u8; 32]);
    let pk_hex = hex::encode(sk.verifying_key().to_bytes());
    let (st, disc_created) = read_json(
        app.clone()
            .oneshot(authed_req(
                Method::POST,
                "/v1/bridges",
                &tok,
                Some(json!({
                    "name": "Discord HW",
                    "kind": "discord",
                    "direction": "inbound",
                    "adapterConfig": { "discordPublicKeyHex": pk_hex }
                })),
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let disc_pub = disc_created["bridge"]["publicId"].as_str().unwrap();
    let disc_body = br#"{"type":1}"#;
    let ts_str = now.to_string();
    let mut msg = ts_str.as_bytes().to_vec();
    msg.extend_from_slice(disc_body);
    let disc_sig = hex::encode(sk.sign(&msg).to_bytes());
    let (st, disc_resp) = read_json(
        app.clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("/v1/bridges/{disc_pub}/inbound"))
                    .header("content-type", "application/json")
                    .header("x-signature-ed25519", disc_sig)
                    .header("x-signature-timestamp", ts_str)
                    .body(Body::from(disc_body.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(disc_resp["type"], 1);

    db.cleanup().await;
}

#[tokio::test]
async fn unauthenticated_flood_cannot_burn_quota_or_bloat_audit_log() {
    let Some(db) = setup().await else { return };
    let t = db.tenant("flood-guard").await;
    let admin = db.user_with(t, Role::OrgAdmin, AuthKind::UserToken).await;
    let tok = db.token(&admin, AuthKind::UserToken).await;

    let app = bp_ent_bridges::router(db.app_ctx());
    let now = OffsetDateTime::now_utc().unix_timestamp();

    let (st, created) = read_json(
        app.clone()
            .oneshot(authed_req(
                Method::POST,
                "/v1/bridges",
                &tok,
                Some(json!({
                    "name": "Tight Quota Bot",
                    "kind": "webhook",
                    "direction": "inbound",
                    "rateLimitRpm": 2
                })),
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let public_id = created["bridge"]["publicId"].as_str().unwrap().to_string();
    let secret = created["inboundSecretOnce"].as_str().unwrap().to_string();

    // Send 5 forged/invalid-signature requests to the public inbound URL.
    for i in 0..5 {
        let body = format!(r#"{{"eventId":"forged-{i}","text":"spam"}}"#);
        let (st, _) = read_json(
            app.clone()
                .oneshot(
                    Request::builder()
                        .method(Method::POST)
                        .uri(format!("/v1/bridges/{public_id}/inbound"))
                        .header("content-type", "application/json")
                        .header("x-bp-signature", format!("t={now},v1={}", "00".repeat(32)))
                        .header("x-bp-delivery", format!("forged-{i}"))
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
    }

    // Rejection audit entry must be throttled to at most 1 per bridge per minute.
    let rejected_audits: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_log WHERE tenant_id = $1 AND action = 'bridge.inbound.rejected'",
    )
    .bind(t.0)
    .fetch_one(db.admin_pool())
    .await
    .unwrap();
    assert_eq!(rejected_audits, 1);

    // Verified quota (rateLimitRpm = 2) must still be completely intact!
    for i in 0..2 {
        let body = format!(r#"{{"eventId":"valid-{i}","text":"legit"}}"#);
        let sig = sign_bp_hmac(secret.as_bytes(), body.as_bytes(), now);
        let (st, _) = read_json(
            app.clone()
                .oneshot(
                    Request::builder()
                        .method(Method::POST)
                        .uri(format!("/v1/bridges/{public_id}/inbound"))
                        .header("content-type", "application/json")
                        .header("x-bp-signature", sig)
                        .header("x-bp-delivery", format!("valid-{i}"))
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::ACCEPTED);
    }

    // 3rd valid delivery in the same minute hits 429 Too Many Requests.
    let body3 = br#"{"eventId":"valid-2","text":"over-quota"}"#;
    let sig3 = sign_bp_hmac(secret.as_bytes(), body3, now);
    let (st, _) = read_json(
        app.clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("/v1/bridges/{public_id}/inbound"))
                    .header("content-type", "application/json")
                    .header("x-bp-signature", sig3)
                    .header("x-bp-delivery", "valid-2")
                    .body(Body::from(body3.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::TOO_MANY_REQUESTS);

    db.cleanup().await;
}
