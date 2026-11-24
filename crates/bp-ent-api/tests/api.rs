//! HTTP-level tests of the API against a real Postgres (as `bp_app`).
//! Needs BP_TEST_ADMIN_DATABASE_URL; see `bp_ent_core::testkit`.

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use bp_ent_api::routes::sso::{self, Identity, Idp, PendingLogin};
use bp_ent_api::state::{ApiConfig, ApiState};
use bp_ent_core::testkit::{TestDb, TEST_ORIGIN};
use bp_ent_core::{AuthKind, Principal, Role, TenantId};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::Row;
use std::net::SocketAddr;
use tower::ServiceExt;
use uuid::Uuid;

const COOKIE: &str = "__Host-bpe_session";

struct Harness {
    db: TestDb,
    app: Router,
}

async fn harness() -> Option<Harness> {
    let db = TestDb::new(bp_ent_api::migrators().into_iter().skip(1)).await?;
    let st = ApiState::new(db.app_ctx(), ApiConfig::for_tests());
    let app = bp_ent_api::app(st, bp_ent_api::Mounts::default()).layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 4000))));
    Some(Harness { db, app })
}

macro_rules! harness {
    () => {
        match harness().await {
            Some(h) => h,
            None => return,
        }
    };
}

enum Cred<'a> {
    None,
    Cookie(&'a str),
    Bearer(&'a str),
}

impl Harness {
    async fn call(&self, method: Method, path: &str, cred: Cred<'_>, body: Option<Value>) -> (StatusCode, Value, axum::http::HeaderMap) {
        let mut req = Request::builder().method(method.clone()).uri(path);
        match cred {
            Cred::Cookie(t) => {
                req = req.header(header::COOKIE, format!("{COOKIE}={t}"));
                if method != Method::GET {
                    req = req.header(header::ORIGIN, TEST_ORIGIN).header("x-bp-csrf", "1");
                }
            }
            Cred::Bearer(t) => req = req.header(header::AUTHORIZATION, format!("Bearer {t}")),
            Cred::None => {}
        }
        let req = match body {
            Some(b) => req.header(header::CONTENT_TYPE, "application/json").body(Body::from(b.to_string())).unwrap(),
            None => req.body(Body::empty()).unwrap(),
        };
        let resp = self.app.clone().oneshot(req).await.unwrap();
        let (parts, body) = resp.into_parts();
        let bytes = body.collect().await.unwrap().to_bytes();
        let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (parts.status, json, parts.headers)
    }

    /// A user with a real browser session.
    async fn session(&self, tenant: TenantId, role: Role) -> (Principal, String) {
        let p = self.db.user(tenant, role).await;
        let t = self.db.token(&p, AuthKind::Session).await;
        (p, t)
    }
}

#[tokio::test]
async fn unauthenticated_requests_are_refused_and_headers_are_strict() {
    let h = harness!();
    for path in ["/v1/me", "/v1/admin/users", "/v1/admin/audit", "/v1/admin/keys", "/v1/policy"] {
        let (s, body, headers) = h.call(Method::GET, path, Cred::None, None).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{path}");
        assert_eq!(body["error"]["code"], "unauthorized");
        assert_eq!(headers["cache-control"], "private, no-store");
        assert_eq!(headers["x-content-type-options"], "nosniff");
        assert_eq!(headers["x-frame-options"], "DENY");
        assert!(headers["strict-transport-security"].to_str().unwrap().contains("max-age="));
        assert!(headers["content-security-policy"].to_str().unwrap().contains("default-src 'none'"));
        assert!(headers.get("access-control-allow-origin").is_none(), "same-origin deployment sends no CORS headers");
    }
    let (s, _, _) = h.call(Method::GET, "/healthz", Cred::None, None).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _, _) = h.call(Method::GET, "/readyz", Cred::None, None).await;
    assert_eq!(s, StatusCode::OK);
    let (s, body, _) = h.call(Method::GET, "/v1/nope", Cred::None, None).await;
    assert_eq!((s, body["error"]["code"].as_str()), (StatusCode::NOT_FOUND, Some("not_found")));
}

#[tokio::test]
async fn me_reports_role_and_effective_permissions() {
    let h = harness!();
    let t = h.db.tenant("acme").await;
    let (p, cookie) = h.session(t, Role::Librarian).await;
    let (s, me, _) = h.call(Method::GET, "/v1/me", Cred::Cookie(&cookie), None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(me["tenantSlug"], "acme");
    assert_eq!(me["role"], "librarian");
    assert_eq!(me["authKind"], "session");
    assert_eq!(me["userId"], p.user_id.to_string());
    let perms: Vec<&str> = me["permissions"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
    assert!(perms.contains(&"parts_release"));
    assert!(!perms.contains(&"admin_manage"));
    assert!(!perms.contains(&"orders_approve"));
}

#[tokio::test]
async fn cookie_auth_enforces_csrf_and_sessions_are_cookie_only() {
    let h = harness!();
    let t = h.db.tenant("acme").await;
    let (_, cookie) = h.session(t, Role::OrgAdmin).await;
    let post = |origin: Option<&'static str>, csrf: bool| {
        let mut r = Request::builder().method(Method::POST).uri("/v1/admin/keys/rotate").header(header::COOKIE, format!("{COOKIE}={cookie}"));
        if let Some(o) = origin {
            r = r.header(header::ORIGIN, o);
        }
        if csrf {
            r = r.header("x-bp-csrf", "1");
        }
        r.body(Body::empty()).unwrap()
    };
    let status = |r: Request<Body>| {
        let app = h.app.clone();
        async move { app.oneshot(r).await.unwrap().status() }
    };
    assert_eq!(status(post(Some("https://evil.example"), true)).await, StatusCode::FORBIDDEN);
    assert_eq!(status(post(Some(TEST_ORIGIN), false)).await, StatusCode::FORBIDDEN);
    assert_eq!(status(post(None, true)).await, StatusCode::FORBIDDEN);
    assert_eq!(status(post(Some(TEST_ORIGIN), true)).await, StatusCode::OK);

    // The session token is not an API key.
    let (s, _, _) = h.call(Method::GET, "/v1/me", Cred::Bearer(&cookie), None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn admin_routes_are_closed_to_other_roles_and_other_tenants() {
    let h = harness!();
    let (a, b) = (h.db.tenant("acme").await, h.db.tenant("globex").await);
    let (_, admin_a) = h.session(a, Role::OrgAdmin).await;
    let (victim, _) = h.session(b, Role::Engineer).await;

    for role in [Role::Engineer, Role::Librarian, Role::Purchasing, Role::ExternalReviewer] {
        let (_, c) = h.session(a, role).await;
        for path in ["/v1/admin/users", "/v1/admin/idp", "/v1/admin/llm-policy", "/v1/admin/audit", "/v1/admin/keys", "/v1/admin/tokens", "/v1/admin/org", "/v1/admin/approval-gates"] {
            let (s, _, _) = h.call(Method::GET, path, Cred::Cookie(&c), None).await;
            assert_eq!(s, StatusCode::FORBIDDEN, "{role:?} {path}");
        }
        let (s, _, _) = h.call(Method::POST, "/v1/admin/users", Cred::Cookie(&c), Some(json!({ "email": "x@acme.test", "role": "org_admin" }))).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{role:?} invite");
    }

    // Acme's admin sees only acme's users and cannot touch globex's.
    let (s, users, _) = h.call(Method::GET, "/v1/admin/users", Cred::Cookie(&admin_a), None).await;
    assert_eq!(s, StatusCode::OK);
    let ids: Vec<&str> = users.as_array().unwrap().iter().map(|u| u["id"].as_str().unwrap()).collect();
    assert!(!ids.contains(&victim.user_id.to_string().as_str()));
    let path = format!("/v1/admin/users/{}/role", victim.user_id);
    let (s, _, _) = h.call(Method::PATCH, &path, Cred::Cookie(&admin_a), Some(json!({ "role": "org_admin" }))).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "another tenant's user does not exist from here");
    let (s, _, _) = h.call(Method::DELETE, &format!("/v1/admin/users/{}", victim.user_id), Cred::Cookie(&admin_a), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let role: String = sqlx::query_scalar("SELECT role FROM users WHERE id = $1").bind(victim.user_id.0).fetch_one(h.db.admin_pool()).await.unwrap();
    assert_eq!(role, "engineer");
}

#[tokio::test]
async fn admin_changes_need_a_browser_session_not_a_token() {
    let h = harness!();
    let t = h.db.tenant("acme").await;
    let admin = h.db.user(t, Role::OrgAdmin).await;
    let token = h.db.token(&admin, AuthKind::UserToken).await;
    let target = h.db.user(t, Role::Engineer).await;

    // Reading with an API token is fine.
    let (s, _, _) = h.call(Method::GET, "/v1/admin/users", Cred::Bearer(&token), None).await;
    assert_eq!(s, StatusCode::OK);
    // Changing anything is not: an agent with an admin's token cannot escalate.
    let calls: Vec<(Method, String, Value)> = vec![
        (Method::PATCH, format!("/v1/admin/users/{}/role", target.user_id), json!({ "role": "org_admin" })),
        (Method::POST, "/v1/admin/users".into(), json!({ "email": "n@acme.test", "role": "engineer" })),
        (Method::PUT, "/v1/admin/llm-policy".into(), json!({ "providers": [], "zdrRequired": false })),
        (Method::PATCH, "/v1/admin/approval-gates/place_order".into(), json!({ "enabled": false })),
        (Method::POST, "/v1/admin/keys/rotate".into(), json!({})),
        (Method::POST, "/v1/me/tokens".into(), json!({ "name": "more" })),
    ];
    for (m, path, body) in calls {
        let (s, _, _) = h.call(m.clone(), &path, Cred::Bearer(&token), Some(body)).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{m} {path}");
    }
}

#[tokio::test]
async fn user_management_protects_the_last_admin_and_revokes_on_change() {
    let h = harness!();
    let t = h.db.tenant("acme").await;
    let (admin, cookie) = h.session(t, Role::OrgAdmin).await;

    // Invite, duplicate, bad e-mail.
    let (s, u, _) = h.call(Method::POST, "/v1/admin/users", Cred::Cookie(&cookie), Some(json!({ "email": "New.Person@Acme.Test", "displayName": "New", "role": "purchasing" }))).await;
    assert_eq!(s, StatusCode::CREATED);
    assert_eq!((u["email"].as_str(), u["status"].as_str()), (Some("new.person@acme.test"), Some("invited")));
    let (s, _, _) = h.call(Method::POST, "/v1/admin/users", Cred::Cookie(&cookie), Some(json!({ "email": "new.person@acme.test", "role": "engineer" }))).await;
    assert_eq!(s, StatusCode::CONFLICT);
    let (s, _, _) = h.call(Method::POST, "/v1/admin/users", Cred::Cookie(&cookie), Some(json!({ "email": "not-an-email", "role": "engineer" }))).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);

    // The only admin cannot demote, suspend or delete themselves.
    let me = admin.user_id;
    let (s, _, _) = h.call(Method::PATCH, &format!("/v1/admin/users/{me}/role"), Cred::Cookie(&cookie), Some(json!({ "role": "engineer" }))).await;
    assert_eq!(s, StatusCode::CONFLICT);
    let (s, _, _) = h.call(Method::PATCH, &format!("/v1/admin/users/{me}/status"), Cred::Cookie(&cookie), Some(json!({ "status": "suspended" }))).await;
    assert_eq!(s, StatusCode::CONFLICT);
    let (s, _, _) = h.call(Method::DELETE, &format!("/v1/admin/users/{me}"), Cred::Cookie(&cookie), None).await;
    assert_eq!(s, StatusCode::CONFLICT);

    // Role change ends the user's API tokens; suspension ends everything.
    let eng = h.db.user(t, Role::Engineer).await;
    let eng_token = h.db.token(&eng, AuthKind::UserToken).await;
    let eng_cookie = h.db.token(&eng, AuthKind::Session).await;
    assert_eq!(h.call(Method::GET, "/v1/me", Cred::Bearer(&eng_token), None).await.0, StatusCode::OK);
    let (s, _, _) = h.call(Method::PATCH, &format!("/v1/admin/users/{}/role", eng.user_id), Cred::Cookie(&cookie), Some(json!({ "role": "librarian" }))).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(h.call(Method::GET, "/v1/me", Cred::Bearer(&eng_token), None).await.0, StatusCode::UNAUTHORIZED);
    let (s, me_now, _) = h.call(Method::GET, "/v1/me", Cred::Cookie(&eng_cookie), None).await;
    assert_eq!((s, me_now["role"].as_str()), (StatusCode::OK, Some("librarian")), "the session sees the new role at once");
    let (s, _, _) = h.call(Method::PATCH, &format!("/v1/admin/users/{}/status", eng.user_id), Cred::Cookie(&cookie), Some(json!({ "status": "suspended" }))).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(h.call(Method::GET, "/v1/me", Cred::Cookie(&eng_cookie), None).await.0, StatusCode::UNAUTHORIZED);

    // All of it is in the audit log, with a valid chain.
    let (s, v, _) = h.call(Method::GET, "/v1/admin/audit/verify", Cred::Cookie(&cookie), None).await;
    assert_eq!((s, v["ok"].as_bool()), (StatusCode::OK, Some(true)));
    let (_, log, _) = h.call(Method::GET, "/v1/admin/audit?limit=50", Cred::Cookie(&cookie), None).await;
    let actions: Vec<&str> = log.as_array().unwrap().iter().map(|e| e["action"].as_str().unwrap()).collect();
    for want in ["user.invited", "user.role_changed", "user.status_changed"] {
        assert!(actions.contains(&want), "{want} not in {actions:?}");
    }
    assert_eq!(log[0]["actorEmail"], admin.email);
    assert_eq!(log[0]["entryHash"].as_str().unwrap().len(), 64);
}

#[tokio::test]
async fn idp_config_validates_pins_and_never_returns_the_secret() {
    let h = harness!();
    let t = h.db.tenant("acme").await;
    let (_, cookie) = h.session(t, Role::OrgAdmin).await;
    let post = |body: Value| h.call(Method::POST, "/v1/admin/idp", Cred::Cookie(&cookie), Some(body));

    // Rejected configurations.
    for bad in [
        json!({ "provider": "google", "displayName": "G", "clientId": "c", "clientSecret": "s" }), // no Workspace pin
        json!({ "provider": "microsoft", "displayName": "M", "clientId": "c", "clientSecret": "s", "directoryId": "common" }),
        json!({ "provider": "oidc", "displayName": "O", "clientId": "c", "clientSecret": "s", "issuer": "http://idp.example", "allowedDomains": ["acme.test"] }),
        json!({ "provider": "oidc", "displayName": "O", "clientId": "c", "clientSecret": "s", "issuer": "https://169.254.169.254", "allowedDomains": ["acme.test"] }),
        json!({ "provider": "oidc", "displayName": "O", "clientId": "c", "clientSecret": "s", "issuer": "https://idp.example" }), // no domain restriction
        json!({ "provider": "google", "displayName": "G", "clientId": "c", "directoryId": "acme.test" }), // no secret
        json!({ "provider": "google", "displayName": "G", "clientId": "c", "clientSecret": "s", "directoryId": "acme.test", "defaultRole": "org_admin", "autoProvision": true }),
        json!({ "provider": "password", "displayName": "P" }),
    ] {
        let (s, _, _) = post(bad.clone()).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{bad}");
    }

    let (s, idp, _) = post(json!({ "provider": "google", "displayName": "Google Workspace", "clientId": "cid", "clientSecret": "super-secret-value", "directoryId": "Acme.Test", "allowedDomains": ["acme.test"] })).await;
    assert_eq!(s, StatusCode::CREATED, "{idp}");
    assert_eq!(idp["issuer"], "https://accounts.google.com");
    assert_eq!(idp["directoryId"], "acme.test");
    assert_eq!(idp["hasClientSecret"], true);
    assert_eq!(idp["redirectUri"], format!("{TEST_ORIGIN}/v1/auth/callback"));
    assert!(!idp.to_string().contains("super-secret-value"));
    let (_, list, _) = h.call(Method::GET, "/v1/admin/idp", Cred::Cookie(&cookie), None).await;
    assert!(!list.to_string().contains("super-secret-value"));

    // At rest it is an envelope blob, not the secret.
    let stored: Vec<u8> = sqlx::query_scalar("SELECT client_secret_enc FROM identity_providers").fetch_one(h.db.admin_pool()).await.unwrap();
    assert_eq!(&stored[..4], b"BPE1");
    assert!(!stored.windows(18).any(|w| w == b"super-secret-value"));
    let ctx = h.db.app_ctx();
    let id = Uuid::parse_str(idp["id"].as_str().unwrap()).unwrap();
    assert_eq!(ctx.cipher.open_str(t, &sso::client_secret_aad(id), &stored).await.unwrap(), "super-secret-value");

    // Public provider list shows only what a login page needs.
    let (s, providers, _) = h.call(Method::GET, "/v1/auth/providers?org=acme", Cred::None, None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(providers.as_array().unwrap().len(), 1);
    assert!(providers[0].get("clientId").is_none());
    let (_, none, _) = h.call(Method::GET, "/v1/auth/providers?org=does-not-exist", Cred::None, None).await;
    assert_eq!(none, json!([]));

    // The only provider cannot be deleted.
    let (s, _, _) = h.call(Method::DELETE, &format!("/v1/admin/idp/{id}"), Cred::Cookie(&cookie), None).await;
    assert_eq!(s, StatusCode::CONFLICT);
}

fn test_idp(id: Uuid, auto: bool) -> Idp {
    Idp {
        id,
        kind: "oidc".into(),
        issuer: Some("https://idp.example".into()),
        client_id: Some("cid".into()),
        client_secret_enc: None,
        directory_id: None,
        allowed_domains: vec!["acme.test".into()],
        trust_email: false,
        saml_entity_id: None,
        saml_sso_url: None,
        saml_cert_pem: None,
        auto_provision: auto,
        default_role: "engineer".into(),
    }
}

async fn insert_idp(h: &Harness, t: TenantId, auto: bool) -> Idp {
    let id = Uuid::new_v4();
    let mut tx = h.db.app_ctx().db.tenant_tx(t).await.unwrap();
    sqlx::query("INSERT INTO identity_providers (id, tenant_id, kind, display_name, issuer, client_id, allowed_domains, auto_provision) VALUES ($1, $2, 'oidc', 'IdP', 'https://idp.example', 'cid', '{acme.test}', $3)")
        .bind(id)
        .bind(t.0)
        .bind(auto)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    test_idp(id, auto)
}

fn who(sub: &str, email: &str) -> Identity {
    Identity { subject: sub.into(), email: email.into(), name: "Ann".into() }
}

fn pending(t: TenantId, idp: &Idp, desktop: Option<(String, String)>) -> PendingLogin {
    PendingLogin { tenant: t, idp_id: idp.id, pkce_verifier: String::new(), nonce: String::new(), return_to: "/boards".into(), desktop }
}

fn session_cookie(headers: &axum::http::HeaderMap) -> Option<String> {
    headers.get_all(header::SET_COOKIE).iter().filter_map(|v| v.to_str().ok()).find(|v| v.starts_with(COOKIE) && !v.contains("Max-Age=0")).map(|v| v.to_string())
}

#[tokio::test]
async fn login_maps_identities_to_members_only() {
    let h = harness!();
    let ctx = h.db.app_ctx();
    let t = h.db.tenant("acme").await;
    let idp = insert_idp(&h, t, false).await;

    // Unknown person, no auto-provisioning: refused, and the refusal is audited.
    let res = sso::complete_login(&ctx, &pending(t, &idp, None), &idp, &who("sub-x", "stranger@acme.test")).await;
    assert!(matches!(res, Err(bp_ent_core::Error::Forbidden)));

    // Invited member: first login links the IdP subject and opens a session.
    let mut tx = ctx.db.tenant_tx(t).await.unwrap();
    sqlx::query("INSERT INTO users (id, tenant_id, email, role, status) VALUES ($1, $2, 'ann@acme.test', 'org_admin', 'invited')").bind(Uuid::new_v4()).bind(t.0).execute(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
    let resp = sso::complete_login(&ctx, &pending(t, &idp, None), &idp, &who("sub-ann", "ann@acme.test")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(resp.headers()[header::LOCATION], format!("{TEST_ORIGIN}/boards"));
    let set = session_cookie(resp.headers()).expect("session cookie");
    for attr in ["HttpOnly", "Secure", "SameSite=Lax", "Path=/"] {
        assert!(set.contains(attr), "{attr} missing in {set}");
    }
    let token = set.split(';').next().unwrap().split_once('=').unwrap().1.to_string();
    let (s, me, _) = h.call(Method::GET, "/v1/me", Cred::Cookie(&token), None).await;
    assert_eq!((s, me["email"].as_str(), me["role"].as_str()), (StatusCode::OK, Some("ann@acme.test"), Some("org_admin")));

    // Same address, different IdP subject (someone else now holds that
    // mailbox at the IdP): not allowed to take the account over.
    let res = sso::complete_login(&ctx, &pending(t, &idp, None), &idp, &who("sub-impostor", "ann@acme.test")).await;
    assert!(matches!(res, Err(bp_ent_core::Error::Forbidden)));
    // Same subject, address changed at the IdP: still Ann.
    assert!(sso::complete_login(&ctx, &pending(t, &idp, None), &idp, &who("sub-ann", "ann.renamed@acme.test")).await.is_ok());

    // Suspended members cannot log in.
    sqlx::query("UPDATE users SET status = 'suspended' WHERE email = 'ann@acme.test'").execute(h.db.admin_pool()).await.unwrap();
    assert!(sso::complete_login(&ctx, &pending(t, &idp, None), &idp, &who("sub-ann", "ann@acme.test")).await.is_err());

    // Logout revokes the session server-side.
    sqlx::query("UPDATE users SET status = 'active' WHERE email = 'ann@acme.test'").execute(h.db.admin_pool()).await.unwrap();
    let (s, _, headers) = h.call(Method::POST, "/v1/auth/logout", Cred::Cookie(&token), None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert!(headers[header::SET_COOKIE].to_str().unwrap().contains("Max-Age=0"));
    assert_eq!(h.call(Method::GET, "/v1/me", Cred::Cookie(&token), None).await.0, StatusCode::UNAUTHORIZED);

    let actions: Vec<String> = sqlx::query_scalar("SELECT action FROM audit_log WHERE tenant_id = $1 ORDER BY seq").bind(t.0).fetch_all(h.db.admin_pool()).await.unwrap();
    for want in ["auth.login_refused", "auth.login", "auth.logout"] {
        assert!(actions.iter().any(|a| a == want), "{want} not in {actions:?}");
    }
}

#[tokio::test]
async fn auto_provisioning_creates_non_admin_members() {
    let h = harness!();
    let ctx = h.db.app_ctx();
    let t = h.db.tenant("acme").await;
    let idp = insert_idp(&h, t, true).await;
    sso::complete_login(&ctx, &pending(t, &idp, None), &idp, &who("sub-new", "new@acme.test")).await.unwrap();
    let row = sqlx::query("SELECT role, status FROM users WHERE email = 'new@acme.test'").fetch_one(h.db.admin_pool()).await.unwrap();
    assert_eq!((row.get::<String, _>("role").as_str(), row.get::<String, _>("status").as_str()), ("engineer", "active"));
    // The schema itself refuses an admin default.
    assert!(sqlx::query("UPDATE identity_providers SET default_role = 'org_admin'").execute(h.db.admin_pool()).await.is_err());
}

#[tokio::test]
async fn desktop_sign_in_needs_the_code_and_the_verifier_once() {
    let h = harness!();
    let ctx = h.db.app_ctx();
    let t = h.db.tenant("acme").await;
    let idp = insert_idp(&h, t, true).await;
    let verifier = "desktop-verifier-0123456789-abcdefghijklmnopqrstuvwxyz";
    let challenge = bp_ent_api::oidc::pkce_challenge(verifier);

    let login = |desktop| {
        let (ctx, idp) = (ctx.clone(), idp.clone());
        async move { sso::complete_login(&ctx, &pending(t, &idp, desktop), &idp, &who("sub-d", "dev@acme.test")).await.unwrap() }
    };
    let code_of = |resp: axum::response::Response| {
        assert!(session_cookie(resp.headers()).is_none(), "desktop flow sets no browser session");
        let loc = resp.headers()[header::LOCATION].to_str().unwrap().to_string();
        assert!(loc.starts_with("http://127.0.0.1:49152/cb?code="), "{loc}");
        url::Url::parse(&loc).unwrap().query_pairs().find(|(k, _)| k == "code").unwrap().1.to_string()
    };
    let desktop = Some(("http://127.0.0.1:49152/cb".to_string(), challenge.clone()));

    // Wrong verifier: refused, and the code is burned.
    let code = code_of(login(desktop.clone()).await);
    let (s, _, _) = h.call(Method::POST, "/v1/auth/desktop/token", Cred::None, Some(json!({ "code": code, "codeVerifier": "wrong" }))).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _, _) = h.call(Method::POST, "/v1/auth/desktop/token", Cred::None, Some(json!({ "code": code, "codeVerifier": verifier }))).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "a code is single-use even after a failed attempt");

    // Right verifier: an API token, usable as a bearer; the code cannot be replayed.
    let code = code_of(login(desktop.clone()).await);
    let (s, out, _) = h.call(Method::POST, "/v1/auth/desktop/token", Cred::None, Some(json!({ "code": code, "codeVerifier": verifier, "deviceName": "Ann's laptop" }))).await;
    assert_eq!(s, StatusCode::OK, "{out}");
    let token = out["token"].as_str().unwrap();
    let (s, me, _) = h.call(Method::GET, "/v1/me", Cred::Bearer(token), None).await;
    assert_eq!((s, me["authKind"].as_str(), me["email"].as_str()), (StatusCode::OK, Some("user_token"), Some("dev@acme.test")));
    let (s, _, _) = h.call(Method::POST, "/v1/auth/desktop/token", Cred::None, Some(json!({ "code": code, "codeVerifier": verifier }))).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // A code minted for acme does nothing when relabelled as another tenant.
    let other = h.db.tenant("globex").await;
    let code = code_of(login(desktop).await);
    let forged = code.replacen(&t.0.simple().to_string(), &other.0.simple().to_string(), 1);
    let (s, _, _) = h.call(Method::POST, "/v1/auth/desktop/token", Cred::None, Some(json!({ "code": forged, "codeVerifier": verifier }))).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn login_start_rejects_unknown_orgs_and_bad_desktop_targets() {
    let h = harness!();
    let t = h.db.tenant("acme").await;
    insert_idp(&h, t, false).await;
    let start = |body: Value| h.call(Method::POST, "/v1/auth/oauth/start", Cred::None, Some(body));
    assert_eq!(start(json!({ "orgSlug": "nope", "provider": "oidc" })).await.0, StatusCode::NOT_FOUND);
    assert_eq!(start(json!({ "orgSlug": "acme", "provider": "google" })).await.0, StatusCode::NOT_FOUND);
    let (s, _, _) = start(json!({ "orgSlug": "acme", "provider": "oidc", "desktopRedirect": "https://evil.example/cb", "desktopChallenge": "a".repeat(43) })).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    // The callback refuses a state it did not issue / a browser that did not start the flow.
    let state = format!("{}.{}", t.0.simple(), "x".repeat(43));
    let (s, _, headers) = h.call(Method::GET, &format!("/v1/auth/callback?code=abc&state={state}"), Cred::None, None).await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    assert_eq!(headers[header::LOCATION], format!("{TEST_ORIGIN}/login?error=failed"));
    assert!(session_cookie(&headers).is_none());
}

#[tokio::test]
async fn tokens_can_be_minted_scoped_listed_and_revoked() {
    let h = harness!();
    let t = h.db.tenant("acme").await;
    let (_, cookie) = h.session(t, Role::Engineer).await;

    // A scope the role does not have is refused outright.
    let (s, _, _) = h.call(Method::POST, "/v1/me/tokens", Cred::Cookie(&cookie), Some(json!({ "name": "x", "scopes": ["admin:manage"] }))).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _, _) = h.call(Method::POST, "/v1/me/tokens", Cred::Cookie(&cookie), Some(json!({ "name": "x", "ttlDays": 9999 }))).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);

    let (s, out, _) = h.call(Method::POST, "/v1/me/tokens", Cred::Cookie(&cookie), Some(json!({ "name": "ci", "scopes": ["parts:read"], "ttlDays": 7 }))).await;
    assert_eq!(s, StatusCode::CREATED);
    let token = out["token"].as_str().unwrap().to_string();
    let (_, me, _) = h.call(Method::GET, "/v1/me", Cred::Bearer(&token), None).await;
    assert_eq!(me["permissions"], json!(["parts_read"]));

    let (_, list, _) = h.call(Method::GET, "/v1/me/tokens", Cred::Cookie(&cookie), None).await;
    assert_eq!(list.as_array().unwrap().len(), 2, "the session and the new token");
    assert!(!list.to_string().contains(&token), "token values are never listed");

    let id = out["tokenId"].as_str().unwrap();
    assert_eq!(h.call(Method::DELETE, &format!("/v1/me/tokens/{id}"), Cred::Cookie(&cookie), None).await.0, StatusCode::NO_CONTENT);
    assert_eq!(h.call(Method::GET, "/v1/me", Cred::Bearer(&token), None).await.0, StatusCode::UNAUTHORIZED);

    // Someone else's token id is "not found".
    let (other, _) = h.session(t, Role::Engineer).await;
    let other_token_id: Uuid = sqlx::query_scalar("SELECT id FROM auth_tokens WHERE user_id = $1").bind(other.user_id.0).fetch_one(h.db.admin_pool()).await.unwrap();
    assert_eq!(h.call(Method::DELETE, &format!("/v1/me/tokens/{other_token_id}"), Cred::Cookie(&cookie), None).await.0, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn llm_policy_with_optional_zdr_is_enforced_and_audited() {
    let h = harness!();
    let t = h.db.tenant("acme").await;
    let (_, admin) = h.session(t, Role::OrgAdmin).await;
    let (_, eng) = h.session(t, Role::Engineer).await;
    let (_, reviewer) = h.session(t, Role::ExternalReviewer).await;
    let ask = |c: &'static str, body: Value| {
        let cookie = match c {
            "eng" => eng.clone(),
            _ => reviewer.clone(),
        };
        let h = &h;
        async move { h.call(Method::POST, "/v1/llm/authorize", Cred::Cookie(&cookie), Some(body)).await }
    };

    // Default policy: mainstream providers allowed, ZDR off.
    let (s, d, _) = ask("eng", json!({ "provider": "openai", "model": "gpt-x" })).await;
    assert_eq!((s, d["decision"].as_str()), (StatusCode::OK, Some("allow")));
    assert_eq!(ask("reviewer", json!({ "provider": "openai", "model": "gpt-x" })).await.0, StatusCode::FORBIDDEN);

    // Admin turns on ZDR-only with one ZDR provider and a model allowlist.
    let policy = json!({ "providers": [
        { "provider": "anthropic", "models": ["claude-*"], "zdr": true },
        { "provider": "openai", "models": ["*"], "zdr": false }
    ], "zdrRequired": true, "allowExternalMcp": false, "monthlyBudgetCents": 50000 });
    let (s, saved, _) = h.call(Method::PUT, "/v1/admin/llm-policy", Cred::Cookie(&admin), Some(policy.clone())).await;
    assert_eq!(s, StatusCode::OK, "{saved}");
    let (_, got, _) = h.call(Method::GET, "/v1/admin/llm-policy", Cred::Cookie(&admin), None).await;
    assert_eq!(got["zdrRequired"], true);

    let (_, d, _) = ask("eng", json!({ "provider": "openai", "model": "gpt-x" })).await;
    assert_eq!((d["decision"].as_str(), d["reason"].as_str()), (Some("deny"), Some("zdr_required")));
    let (_, d, _) = ask("eng", json!({ "provider": "anthropic", "model": "claude-opus" })).await;
    assert_eq!(d["decision"], "allow");
    let (_, d, _) = ask("eng", json!({ "provider": "anthropic", "model": "other" })).await;
    assert_eq!(d["reason"], "model_not_allowed");
    let (_, d, _) = ask("eng", json!({ "provider": "google", "model": "g" })).await;
    assert_eq!(d["reason"], "provider_not_allowed");

    // A policy that would lock everyone out, or has unknown fields, is refused.
    let (s, _, _) = h.call(Method::PUT, "/v1/admin/llm-policy", Cred::Cookie(&admin), Some(json!({ "providers": [{ "provider": "openai", "models": ["*"] }], "zdrRequired": true }))).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    let (s, _, _) = h.call(Method::PUT, "/v1/admin/llm-policy", Cred::Cookie(&admin), Some(json!({ "providers": [], "zdrOnly": true }))).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);

    let actions: Vec<String> = sqlx::query_scalar("SELECT action FROM audit_log WHERE tenant_id = $1").bind(t.0).fetch_all(h.db.admin_pool()).await.unwrap();
    assert!(actions.iter().any(|a| a == "llm_policy.updated"));
    assert_eq!(actions.iter().filter(|a| *a == "llm.denied").count(), 3);
}

#[tokio::test]
async fn approval_queue_over_http() {
    let h = harness!();
    let ctx = h.db.app_ctx();
    let t = h.db.tenant("acme").await;
    let (_, admin) = h.session(t, Role::OrgAdmin).await;
    let (buyer_p, buyer) = h.session(t, Role::Purchasing).await;
    let (_, eng) = h.session(t, Role::Engineer).await;
    let agent = h.db.user_with(t, Role::Engineer, AuthKind::UserToken).await;

    let gate = || bp_ent_core::policy::GateKind::PlaceOrder { amount_cents: 250_000 };
    let summary = json!({ "vendor": "fab", "totalCents": 250_000 });
    let mut tx = ctx.db.tenant_tx(t).await.unwrap();
    let a = bp_ent_core::policy::require_approval(&mut tx, &agent, gate(), "order:42", summary.clone()).await.unwrap();
    tx.commit().await.unwrap();
    let bp_ent_core::policy::Approval::Pending { request_id } = a else { panic!("{a:?}") };

    // Engineers are not approvers of anything: no queue for them.
    assert_eq!(h.call(Method::GET, "/v1/admin/approvals", Cred::Cookie(&eng), None).await.0, StatusCode::FORBIDDEN);
    // Purchasing sees the order request and may decide it.
    let (s, q, _) = h.call(Method::GET, "/v1/admin/approvals", Cred::Cookie(&buyer), None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(q.as_array().unwrap().len(), 1);
    assert_eq!((q[0]["gateKind"].as_str(), q[0]["requestedVia"].as_str(), q[0]["canDecide"].as_bool()), (Some("place_order"), Some("token"), Some(true)));
    assert_eq!(q[0]["summary"]["totalCents"], 250_000);

    // Engineer cannot decide; a token cannot decide; purchasing in a browser can.
    let path = format!("/v1/admin/approvals/{request_id}/decide");
    assert_eq!(h.call(Method::POST, &path, Cred::Cookie(&eng), Some(json!({ "decision": "approved" }))).await.0, StatusCode::FORBIDDEN);
    let buyer_token = h.db.token(&buyer_p, AuthKind::UserToken).await;
    assert_eq!(h.call(Method::POST, &path, Cred::Bearer(&buyer_token), Some(json!({ "decision": "approved" }))).await.0, StatusCode::FORBIDDEN);
    let (s, out, _) = h.call(Method::POST, &path, Cred::Cookie(&buyer), Some(json!({ "decision": "approved", "reason": "ok" }))).await;
    assert_eq!((s, out["status"].as_str()), (StatusCode::OK, Some("approved")));
    assert_eq!(h.call(Method::POST, &path, Cred::Cookie(&buyer), Some(json!({ "decision": "rejected" }))).await.0, StatusCode::CONFLICT);

    // The agent's retry now proceeds, once.
    let mut tx = ctx.db.tenant_tx(t).await.unwrap();
    let a = bp_ent_core::policy::require_approval(&mut tx, &agent, gate(), "order:42", summary).await.unwrap();
    tx.commit().await.unwrap();
    assert!(a.may_proceed());

    // Gate settings: admin lowers the bar to "only above $5,000".
    let (s, g, _) = h.call(Method::PATCH, "/v1/admin/approval-gates/place_order", Cred::Cookie(&admin), Some(json!({ "thresholdCents": 500_000 }))).await;
    assert_eq!(s, StatusCode::OK, "{g}");
    let po = g["gates"].as_array().unwrap().iter().find(|x| x["id"] == "place_order").unwrap();
    assert_eq!((po["thresholdCents"].as_i64(), po["enabled"].as_bool()), (Some(500_000), Some(true)));
    assert_eq!(h.call(Method::PATCH, "/v1/admin/approval-gates/nope", Cred::Cookie(&admin), Some(json!({ "enabled": false }))).await.0, StatusCode::NOT_FOUND);
    assert_eq!(h.call(Method::PATCH, "/v1/admin/approval-gates/place_order", Cred::Cookie(&admin), Some(json!({ "approvers": [] }))).await.0, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn key_rotation_over_http() {
    let h = harness!();
    let t = h.db.tenant("acme").await;
    let (_, admin) = h.session(t, Role::OrgAdmin).await;
    let ctx = h.db.app_ctx();
    let old = ctx.cipher.seal(t, b"x", b"before").await.unwrap();
    let (s, k, _) = h.call(Method::GET, "/v1/admin/keys", Cred::Cookie(&admin), None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!((k["activeVersion"].as_i64(), k["provider"].as_str()), (Some(1), Some("local_kek")));
    let (s, k, _) = h.call(Method::POST, "/v1/admin/keys/rotate", Cred::Cookie(&admin), None).await;
    assert_eq!((s, k["activeVersion"].as_i64()), (StatusCode::OK, Some(2)));
    assert_eq!(k["versions"].as_array().unwrap().len(), 2);
    assert!(!k.to_string().contains("wrappedDek\""), "only a fingerprint of the wrapped key is exposed");
    assert_eq!(ctx.cipher.open(t, b"x", &old).await.unwrap(), b"before");
}

#[tokio::test]
async fn purge_removes_expired_login_state() {
    let h = harness!();
    let ctx = h.db.app_ctx();
    let t = h.db.tenant("acme").await;
    let idp = insert_idp(&h, t, false).await;
    let mut tx = ctx.db.tenant_tx(t).await.unwrap();
    sqlx::query("INSERT INTO login_states (tenant_id, state_hash, idp_id, pkce_verifier_enc, nonce, expires_at) VALUES ($1, '\\x01', $2, '\\x00', 'n', now() - interval '1 hour')")
        .bind(t.0)
        .bind(idp.id)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(bp_ent_api::jobs::purge_once(&ctx).await.unwrap(), 1);
}
