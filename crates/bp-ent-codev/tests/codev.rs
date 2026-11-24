//! Board co-development over HTTP against a real Postgres (as `bp_app`).

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use bp_ent_core::testkit::TestDb;
use bp_ent_core::{AuthKind, Principal, Role, TenantId};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

struct H {
    db: TestDb,
    app: Router,
}

async fn harness() -> Option<H> {
    let db = TestDb::new([bp_ent_codev::migrator()]).await?;
    let app = bp_ent_codev::router(db.app_ctx());
    Some(H { db, app })
}

macro_rules! harness {
    () => {
        match harness().await {
            Some(h) => h,
            None => return,
        }
    };
}

impl H {
    /// A user with an API token (desktop app / CI style).
    async fn user(&self, t: TenantId, role: Role) -> (Principal, String) {
        let p = self.db.user(t, role).await;
        let tok = self.db.token(&p, AuthKind::UserToken).await;
        (p, tok)
    }

    async fn raw(&self, method: Method, path: &str, token: &str, ctype: &str, body: Vec<u8>) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
        let req = Request::builder().method(method).uri(path).header(header::AUTHORIZATION, format!("Bearer {token}")).header(header::CONTENT_TYPE, ctype).body(Body::from(body)).unwrap();
        let resp = self.app.clone().oneshot(req).await.unwrap();
        let (parts, body) = resp.into_parts();
        (parts.status, parts.headers, body.collect().await.unwrap().to_bytes().to_vec())
    }

    async fn call(&self, method: Method, path: &str, token: &str, body: Option<Value>) -> (StatusCode, Value) {
        let (s, _, b) = self.raw(method, path, token, "application/json", body.map(|b| b.to_string().into_bytes()).unwrap_or_default()).await;
        (s, serde_json::from_slice(&b).unwrap_or(Value::Null))
    }

    async fn board(&self, token: &str, slug: &str) -> String {
        let (s, b) = self.call(Method::POST, "/v1/boards", token, Some(json!({ "name": slug, "slug": slug, "widthMm": 80.0, "heightMm": 50.0, "layerCount": 4 }))).await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        b["id"].as_str().unwrap().to_string()
    }

    async fn revision(&self, token: &str, board: &str, tag: &str, body: Value) -> String {
        let mut body = body;
        body["tag"] = json!(tag);
        let (s, r) = self.call(Method::POST, &format!("/v1/boards/{board}/revisions"), token, Some(body)).await;
        assert_eq!(s, StatusCode::CREATED, "{r}");
        r["id"].as_str().unwrap().to_string()
    }
}

fn part(refdes: &str, mpn: &str, x: f64) -> Value {
    json!({ "refdes": refdes, "mpn": mpn, "xMm": x, "yMm": 10.0, "widthMm": 2.0, "heightMm": 1.0, "layer": "F.Cu", "packageName": "0603" })
}

#[tokio::test]
async fn revisions_diffs_comments_and_ecos() {
    let h = harness!();
    let t = h.db.tenant("acme").await;
    let (_, eng) = h.user(t, Role::Engineer).await;
    let board = h.board(&eng, "motor-ctl").await;

    let r1 = h.revision(&eng, &board, "v1.0", json!({ "commitSha": "ABC123", "summary": "first", "components": [part("R1", "RC0603-10K", 5.0), part("U1", "DRV8301", 20.0)],
        "bom": [{ "mpn": "RC0603-10K", "quantity": 1, "refdes": ["R1"] }, { "mpn": "DRV8301", "quantity": 1, "refdes": ["U1"] }] })).await;
    let r2 = h.revision(&eng, &board, "v1.1", json!({ "components": [part("R1", "RC0603-10K", 7.5), part("U1", "DRV8305", 20.0), part("C1", "GRM188", 30.0)],
        "bom": [{ "mpn": "RC0603-10K", "quantity": 1, "refdes": ["R1"] }, { "mpn": "DRV8305", "quantity": 1, "refdes": ["U1"] }, { "mpn": "GRM188", "quantity": 1, "refdes": ["C1"] }] })).await;
    // Same tag twice is refused.
    let (s, _) = h.call(Method::POST, &format!("/v1/boards/{board}/revisions"), &eng, Some(json!({ "tag": "v1.1" }))).await;
    assert_eq!(s, StatusCode::CONFLICT);

    let (s, b) = h.call(Method::GET, &format!("/v1/boards/{board}"), &eng, None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["revisions"].as_array().unwrap().len(), 2);
    assert_eq!((b["revisions"][0]["tag"].as_str(), b["revisions"][0]["commitSha"].as_str()), (Some("v1.1"), Some("")));
    assert_eq!(b["revisions"][1]["commitSha"], "abc123");
    assert_eq!(b["components"].as_array().unwrap().len(), 3);
    let diffs = b["diffs"].as_array().unwrap();
    let has = |scope: &str, target: &str, kind: &str| diffs.iter().any(|d| d["scope"] == scope && d["target"] == target && d["kind"] == kind);
    assert!(has("BOM", "DRV8305", "added") && has("BOM", "DRV8301", "removed") && has("BOM", "GRM188", "added"));
    assert!(has("PCB", "R1", "changed") && has("PCB", "U1", "changed") && has("PCB", "C1", "added"));
    let (_, d) = h.call(Method::GET, &format!("/v1/boards/{board}/diff?from={r2}&to={r1}"), &eng, None).await;
    assert!(d.as_array().unwrap().iter().any(|e| e["target"] == "C1" && e["kind"] == "removed"), "the diff is directional");

    // Where-used looks at each board's latest revision.
    let (_, w) = h.call(Method::GET, "/v1/boards/where-used?mpn=DRV8305", &eng, None).await;
    assert_eq!((w.as_array().unwrap().len(), w[0]["revisionTag"].as_str()), (1, Some("v1.1")));
    let (_, w) = h.call(Method::GET, "/v1/boards/where-used?mpn=DRV8301", &eng, None).await;
    assert_eq!(w, json!([]));

    // Pinned comment, then resolve.
    let (s, c) = h.call(Method::POST, &format!("/v1/boards/{board}/comments"), &eng, Some(json!({ "revisionId": r2, "layer": "F.Cu", "xMm": 20.1, "yMm": 10.2, "refdes": "U1", "body": "Thermal pad vias?" }))).await;
    assert_eq!(s, StatusCode::CREATED, "{c}");
    assert_eq!((c["refdes"].as_str(), c["resolved"].as_bool(), c["xMm"].as_f64()), (Some("U1"), Some(false), Some(20.1)));
    let cid = c["id"].as_str().unwrap();
    let (s, c) = h.call(Method::POST, &format!("/v1/boards/{board}/comments/{cid}/resolve"), &eng, None).await;
    assert_eq!((s, c["resolved"].as_bool()), (StatusCode::OK, Some(true)));
    for bad in [
        json!({ "revisionId": r2, "layer": "F.Cu", "xMm": 1.0, "yMm": 1.0, "body": "" }),
        json!({ "revisionId": r2, "layer": "<svg onload=x>", "xMm": 1.0, "yMm": 1.0, "body": "x" }),
        json!({ "revisionId": r2, "layer": "F.Cu", "xMm": 1e9, "yMm": 1.0, "body": "x" }),
        json!({ "revisionId": r2, "layer": "F.Cu", "xMm": 1.0, "yMm": 1.0, "body": "x", "refdes": "R1; DROP TABLE" }),
    ] {
        let (s, _) = h.call(Method::POST, &format!("/v1/boards/{board}/comments"), &eng, Some(bad.clone())).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{bad}");
    }

    // ECO: numbered per org; approval needs a second person in a browser.
    let (s, e) = h.call(Method::POST, &format!("/v1/boards/{board}/ecos"), &eng, Some(json!({ "title": "Swap gate driver", "rationale": "DRV8301 is NRND", "revisionId": r2 }))).await;
    assert_eq!((s, e["code"].as_str(), e["status"].as_str()), (StatusCode::CREATED, Some("ECO-0001"), Some("draft")));
    let eco = e["id"].as_str().unwrap();
    let tr = |tok: String, status: &'static str| {
        let h = &h;
        let path = format!("/v1/boards/{board}/ecos/{eco}/transition");
        async move { h.call(Method::POST, &path, &tok, Some(json!({ "status": status }))).await.0 }
    };
    assert_eq!(tr(eng.clone(), "approved").await, StatusCode::CONFLICT, "cannot skip review");
    assert_eq!(tr(eng.clone(), "in_review").await, StatusCode::OK);
    assert_eq!(tr(eng.clone(), "approved").await, StatusCode::FORBIDDEN, "the author cannot approve their own ECO");
    let (_, other_token) = h.user(t, Role::Engineer).await;
    assert_eq!(tr(other_token, "approved").await, StatusCode::FORBIDDEN, "an API token (agent) cannot approve");
    // A second engineer with a browser session can: exercise the rule directly.
    let reviewer = h.db.user(t, Role::Engineer).await;
    let session = h.db.token(&reviewer, AuthKind::Session).await;
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("/v1/boards/{board}/ecos/{eco}/transition"))
        .header(header::COOKIE, format!("__Host-bpe_session={session}"))
        .header(header::ORIGIN, bp_ent_core::testkit::TEST_ORIGIN)
        .header("x-bp-csrf", "1")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(json!({ "status": "approved" }).to_string()))
        .unwrap();
    assert_eq!(h.app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);
    assert_eq!(tr(eng.clone(), "implemented").await, StatusCode::OK);
    let (_, e2) = h.call(Method::POST, &format!("/v1/boards/{board}/ecos"), &eng, Some(json!({ "title": "Second" }))).await;
    assert_eq!(e2["code"], "ECO-0002");

    let actions: Vec<String> = sqlx::query_scalar("SELECT action FROM audit_log WHERE tenant_id = $1").bind(t.0).fetch_all(h.db.admin_pool()).await.unwrap();
    for want in ["board.created", "board.revision_pushed", "board.comment_added", "board.comment_resolved", "eco.created", "eco.status_changed"] {
        assert!(actions.iter().any(|a| a == want), "{want} missing");
    }
}

#[tokio::test]
async fn artifacts_are_sealed_at_rest_and_served_inertly() {
    let h = harness!();
    let t = h.db.tenant("acme").await;
    let (_, eng) = h.user(t, Role::Engineer).await;
    let board = h.board(&eng, "psu").await;
    let rev = h.revision(&eng, &board, "a", json!({})).await;
    let svg = br#"<svg xmlns="http://www.w3.org/2000/svg"><script>alert(document.cookie)</script><path d="M0 0 TOP-SECRET-TRACE"/></svg>"#.to_vec();
    let url = format!("/v1/boards/{board}/revisions/{rev}/artifacts/pcb_svg?name=F.Cu");

    let (s, _, _) = h.raw(Method::PUT, &url, &eng, "image/svg+xml", svg.clone()).await;
    assert_eq!(s, StatusCode::OK);
    // Stored encrypted with the tenant key, not as readable board data.
    let stored: Vec<u8> = sqlx::query_scalar("SELECT data FROM board_artifacts").fetch_one(h.db.admin_pool()).await.unwrap();
    assert_eq!(&stored[..4], b"BPE1");
    assert!(!stored.windows(16).any(|w| w == b"TOP-SECRET-TRACE"));

    let (s, headers, body) = h.raw(Method::GET, &url, &eng, "", vec![]).await;
    assert_eq!((s, body == svg), (StatusCode::OK, true));
    assert_eq!(headers[header::CONTENT_TYPE], "image/svg+xml");
    let csp = headers[header::CONTENT_SECURITY_POLICY].to_str().unwrap();
    assert!(csp.contains("default-src 'none'") && csp.contains("sandbox"), "an uploaded SVG must not be able to run script: {csp}");
    assert_eq!(headers[header::CACHE_CONTROL], "private, no-store");

    // Replace keeps one row; unknown kinds and traversal-looking names are refused.
    let (s, _, _) = h.raw(Method::PUT, &url, &eng, "image/svg+xml", b"<svg/>".to_vec()).await;
    assert_eq!(s, StatusCode::OK);
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM board_artifacts").fetch_one(h.db.admin_pool()).await.unwrap();
    assert_eq!(n, 1);
    for bad in ["artifacts/exe", "artifacts/pcb_svg?name=../../etc", "artifacts/pcb_svg?name=a%20b"] {
        let (s, _, _) = h.raw(Method::PUT, &format!("/v1/boards/{board}/revisions/{rev}/{bad}"), &eng, "x", b"x".to_vec()).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{bad}");
    }
    let (s, _, _) = h.raw(Method::PUT, &url, &eng, "x", vec![0u8; bp_ent_codev::MAX_ARTIFACT_BYTES + 1]).await;
    assert!(s == StatusCode::PAYLOAD_TOO_LARGE || s == StatusCode::UNPROCESSABLE_ENTITY, "{s}");
    let (s, a) = h.call(Method::GET, &format!("/v1/boards/{board}/revisions/{rev}/artifacts"), &eng, None).await;
    assert_eq!((s, a[0]["name"].as_str(), a[0]["sizeBytes"].as_i64()), (StatusCode::OK, Some("F.Cu"), Some(6)));
}

#[tokio::test]
async fn released_revisions_change_only_through_the_approval_gate() {
    let h = harness!();
    let t = h.db.tenant("acme").await;
    let (_, eng) = h.user(t, Role::Engineer).await;
    let admin = h.db.user(t, Role::OrgAdmin).await;
    let board = h.board(&eng, "bms").await;
    let rev = h.revision(&eng, &board, "rel-1", json!({})).await;
    let url = format!("/v1/boards/{board}/revisions/{rev}/artifacts/gerbers_zip");
    assert_eq!(h.raw(Method::PUT, &url, &eng, "application/zip", b"PK-v1".to_vec()).await.0, StatusCode::OK);
    let (s, _) = h.call(Method::POST, &format!("/v1/boards/{board}/revisions/{rev}/release"), &eng, None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(h.call(Method::POST, &format!("/v1/boards/{board}/revisions/{rev}/release"), &eng, None).await.0, StatusCode::CONFLICT);

    // Overwriting the released fabrication output: held for approval, data untouched.
    let (s, _, body) = h.raw(Method::PUT, &url, &eng, "application/zip", b"PK-v2-tampered".to_vec()).await;
    assert_eq!(s, StatusCode::ACCEPTED);
    let pending: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(pending["status"], "pending_approval");
    assert_eq!(h.raw(Method::GET, &url, &eng, "", vec![]).await.2, b"PK-v1");

    // An admin approves in the browser; the same upload then goes through once.
    let ctx = h.db.app_ctx();
    let id = uuid::Uuid::parse_str(pending["requestId"].as_str().unwrap()).unwrap();
    let mut tx = ctx.db.tenant_tx(t).await.unwrap();
    bp_ent_core::policy::decide(&mut tx, &admin, id, true, None).await.unwrap();
    tx.commit().await.unwrap();
    // Different bytes than the ones approved do not ride on that approval.
    assert_eq!(h.raw(Method::PUT, &url, &eng, "application/zip", b"PK-something-else".to_vec()).await.0, StatusCode::ACCEPTED);
    assert_eq!(h.raw(Method::PUT, &url, &eng, "application/zip", b"PK-v2-tampered".to_vec()).await.0, StatusCode::OK);
    assert_eq!(h.raw(Method::GET, &url, &eng, "", vec![]).await.2, b"PK-v2-tampered");
}

#[tokio::test]
async fn roles_and_tenants_are_kept_apart() {
    let h = harness!();
    let (a, b) = (h.db.tenant("acme").await, h.db.tenant("globex").await);
    let (_, eng_a) = h.user(a, Role::Engineer).await;
    let (_, eng_b) = h.user(b, Role::Engineer).await;
    let (_, buyer) = h.user(a, Role::Purchasing).await;
    let (_, reviewer) = h.user(a, Role::ExternalReviewer).await;
    let secret = h.board(&eng_a, "secret-board").await;
    let shared = h.board(&eng_a, "shared-board").await;
    let rev = h.revision(&eng_a, &secret, "x", json!({ "bom": [{ "mpn": "SECRET-ASIC", "quantity": 1 }] })).await;
    let shared_rev = h.revision(&eng_a, &shared, "x", json!({ "bom": [{ "mpn": "SECRET-ASIC", "quantity": 2 }] })).await;
    h.raw(Method::PUT, &format!("/v1/boards/{secret}/revisions/{rev}/artifacts/pcb_svg"), &eng_a, "x", b"<svg/>".to_vec()).await;

    // Another tenant: nothing exists.
    assert_eq!(h.call(Method::GET, "/v1/boards", &eng_b, None).await.1, json!([]));
    for (m, path) in [
        (Method::GET, format!("/v1/boards/{secret}")),
        (Method::GET, format!("/v1/boards/{secret}/revisions/{rev}/bom")),
        (Method::GET, format!("/v1/boards/{secret}/revisions/{rev}/artifacts/pcb_svg")),
        (Method::GET, format!("/v1/boards/{secret}/comments")),
        (Method::POST, format!("/v1/boards/{secret}/revisions/{rev}/release")),
    ] {
        assert_eq!(h.call(m.clone(), &path, &eng_b, None).await.0, StatusCode::NOT_FOUND, "{m} {path}");
    }
    let (s, _) = h.call(Method::POST, &format!("/v1/boards/{secret}/comments"), &eng_b, Some(json!({ "revisionId": rev, "layer": "F.Cu", "xMm": 1.0, "yMm": 1.0, "body": "hi" }))).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(h.call(Method::GET, "/v1/boards/where-used?mpn=SECRET-ASIC", &eng_b, None).await.1, json!([]));
    // A board in tenant b cannot take a revision id from tenant a either.
    let board_b = h.board(&eng_b, "theirs").await;
    let (s, _) = h.call(Method::POST, &format!("/v1/boards/{board_b}/comments"), &eng_b, Some(json!({ "revisionId": rev, "layer": "F.Cu", "xMm": 1.0, "yMm": 1.0, "body": "hi" }))).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // Purchasing reads and comments but cannot push or share.
    assert_eq!(h.call(Method::GET, &format!("/v1/boards/{secret}"), &buyer, None).await.0, StatusCode::OK);
    assert_eq!(h.call(Method::POST, "/v1/boards", &buyer, Some(json!({ "name": "x", "slug": "x" }))).await.0, StatusCode::FORBIDDEN);
    assert_eq!(h.call(Method::POST, &format!("/v1/boards/{secret}/revisions"), &buyer, Some(json!({ "tag": "evil" }))).await.0, StatusCode::FORBIDDEN);
    assert_eq!(h.call(Method::PATCH, &format!("/v1/boards/{secret}"), &buyer, Some(json!({ "externalAccess": true }))).await.0, StatusCode::FORBIDDEN);

    // External reviewer: nothing until a board is shared, then only that board.
    assert_eq!(h.call(Method::GET, "/v1/boards", &reviewer, None).await.1, json!([]));
    assert_eq!(h.call(Method::GET, &format!("/v1/boards/{shared}"), &reviewer, None).await.0, StatusCode::NOT_FOUND);
    let (s, _) = h.call(Method::PATCH, &format!("/v1/boards/{shared}"), &eng_a, Some(json!({ "externalAccess": true }))).await;
    assert_eq!(s, StatusCode::OK);
    let (_, list) = h.call(Method::GET, "/v1/boards", &reviewer, None).await;
    assert_eq!((list.as_array().unwrap().len(), list[0]["slug"].as_str()), (1, Some("shared-board")));
    assert_eq!(h.call(Method::GET, &format!("/v1/boards/{secret}"), &reviewer, None).await.0, StatusCode::NOT_FOUND);
    assert_eq!(h.call(Method::GET, &format!("/v1/boards/{secret}/revisions/{rev}/artifacts/pcb_svg"), &reviewer, None).await.0, StatusCode::NOT_FOUND);
    let (_, w) = h.call(Method::GET, "/v1/boards/where-used?mpn=SECRET-ASIC", &reviewer, None).await;
    assert_eq!(w.as_array().unwrap().len(), 1, "where-used must not reveal the unshared board");
    // They can comment on the shared board, and resolve only their own comment.
    let (s, mine) = h.call(Method::POST, &format!("/v1/boards/{shared}/comments"), &reviewer, Some(json!({ "revisionId": shared_rev, "layer": "B.Cu", "xMm": 1.0, "yMm": 1.0, "body": "DFM: tombstoning risk" }))).await;
    assert_eq!(s, StatusCode::CREATED);
    let (_, theirs) = h.call(Method::POST, &format!("/v1/boards/{shared}/comments"), &eng_a, Some(json!({ "revisionId": shared_rev, "layer": "B.Cu", "xMm": 2.0, "yMm": 1.0, "body": "internal" }))).await;
    assert_eq!(h.call(Method::POST, &format!("/v1/boards/{shared}/comments/{}/resolve", theirs["id"].as_str().unwrap()), &reviewer, None).await.0, StatusCode::FORBIDDEN);
    assert_eq!(h.call(Method::POST, &format!("/v1/boards/{shared}/comments/{}/resolve", mine["id"].as_str().unwrap()), &reviewer, None).await.0, StatusCode::OK);
    assert_eq!(h.call(Method::POST, &format!("/v1/boards/{shared}/ecos"), &reviewer, Some(json!({ "title": "x" }))).await.0, StatusCode::FORBIDDEN);
    assert_eq!(h.call(Method::POST, &format!("/v1/boards/{shared}/revisions"), &reviewer, Some(json!({ "tag": "evil" }))).await.0, StatusCode::FORBIDDEN);

    let shared_events: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE action = 'board.shared_externally'").fetch_one(h.db.admin_pool()).await.unwrap();
    assert_eq!(shared_events, 1);
}
