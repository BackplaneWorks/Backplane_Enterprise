//! Attacks on the shared kernel (`bp-ent-core`): credentials, envelope
//! encryption, RBAC, CSRF, SSRF guard and the audit chain. Each test states
//! the attack it tries.

use bp_ent_core::rbac::Scopes;
use bp_ent_core::testkit::{TestDb, TEST_ORIGIN};
use bp_ent_core::{audit, auth, http as bphttp, AuthKind, Error, Permission, Role, Secret, TenantId};
use http::{HeaderMap, HeaderValue, Method};

fn headers(pairs: &[(&'static str, String)]) -> HeaderMap {
    let mut h = HeaderMap::new();
    for (k, v) in pairs {
        h.append(*k, HeaderValue::from_str(v).unwrap());
    }
    h
}

// ------------------------------------------------------------ credentials

/// Attack: take a valid token and rewrite the tenant it claims, hoping to be
/// authenticated into another tenant; guess tokens; reuse revoked ones.
#[tokio::test]
async fn token_cannot_be_replayed_into_another_tenant() {
    let Some(db) = TestDb::new([]).await else { return };
    let ctx = db.app_ctx();
    let (a, b) = (db.tenant("acme").await, db.tenant("globex").await);
    let alice = db.user(a, Role::OrgAdmin).await;
    db.user(b, Role::OrgAdmin).await;
    let token = db.token(&alice, AuthKind::UserToken).await;

    let p = auth::verify_bearer(&ctx, &token).await.expect("valid token verifies");
    assert_eq!((p.tenant_id, p.user_id), (a, alice.user_id));

    // Same secret, tenant claim swapped to B.
    let forged = token.replace(&a.0.simple().to_string(), &b.0.simple().to_string());
    assert_ne!(forged, token);
    assert!(matches!(auth::verify_bearer(&ctx, &forged).await, Err(Error::Unauthorized)));

    // Same token presented as a different kind.
    let as_session = token.replacen("bpe_u_", "bpe_s_", 1);
    assert!(matches!(auth::verify_bearer(&ctx, &as_session).await, Err(Error::Unauthorized)));

    // One flipped character, garbage, empty.
    let mut flipped = token.clone().into_bytes();
    let last = flipped.len() - 1;
    flipped[last] = if flipped[last] == b'A' { b'B' } else { b'A' };
    for bad in [String::from_utf8(flipped).unwrap(), "bpe_u_zz_zz".into(), String::new(), "Bearer".into()] {
        assert!(matches!(auth::verify_bearer(&ctx, &bad).await, Err(Error::Unauthorized)), "{bad}");
    }

    // The raw token is not in the database, only its hash.
    let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_tokens WHERE encode(token_hash, 'escape') LIKE '%bpe_%' OR name LIKE '%bpe_%'")
        .fetch_one(db.admin_pool())
        .await
        .unwrap();
    assert_eq!(stored, 0, "a raw token was stored");

    // Revocation is immediate.
    let mut tx = ctx.db.tenant_tx(a).await.unwrap();
    assert!(auth::revoke_token(&mut tx, a, p.token_id).await.unwrap());
    tx.commit().await.unwrap();
    assert!(matches!(auth::verify_bearer(&ctx, &token).await, Err(Error::Unauthorized)));
    db.cleanup().await;
}

/// Attack: keep using a credential after the user or the whole organisation
/// was suspended.
#[tokio::test]
async fn suspended_user_or_tenant_loses_access_at_once() {
    let Some(db) = TestDb::new([]).await else { return };
    let ctx = db.app_ctx();
    let a = db.tenant("acme").await;
    let alice = db.user(a, Role::Engineer).await;
    let bob = db.user(a, Role::Engineer).await;
    let (ta, tb) = (db.token(&alice, AuthKind::UserToken).await, db.token(&bob, AuthKind::UserToken).await);

    sqlx::query("UPDATE users SET status = 'suspended' WHERE id = $1").bind(alice.user_id.0).execute(db.admin_pool()).await.unwrap();
    assert!(matches!(auth::verify_bearer(&ctx, &ta).await, Err(Error::Unauthorized)));
    assert!(auth::verify_bearer(&ctx, &tb).await.is_ok());

    sqlx::query("UPDATE tenants SET status = 'suspended' WHERE id = $1").bind(a.0).execute(db.admin_pool()).await.unwrap();
    assert!(matches!(auth::verify_bearer(&ctx, &tb).await, Err(Error::Unauthorized)));
    db.cleanup().await;
}

/// Attack: (1) use a stolen session cookie value as an API key; (2) use an
/// API token as a cookie; (3) cross-site request forgery against a session.
#[tokio::test]
async fn session_cookies_and_api_tokens_are_not_interchangeable_and_csrf_is_enforced() {
    let Some(db) = TestDb::new([]).await else { return };
    let ctx = db.app_ctx();
    let a = db.tenant("acme").await;
    let alice = db.user(a, Role::OrgAdmin).await;
    let session = db.token(&alice, AuthKind::Session).await;
    let api = db.token(&alice, AuthKind::UserToken).await;
    let cookie_name = ctx.config.session_cookie_name();
    assert!(cookie_name.starts_with("__Host-"), "secure deployments must use a __Host- cookie");

    let bearer = |t: &str| headers(&[("authorization", format!("Bearer {t}"))]);
    let cookie = |t: &str, extra: &[(&'static str, String)]| {
        let mut v = vec![("cookie", format!("{cookie_name}={t}"))];
        v.extend_from_slice(extra);
        headers(&v)
    };
    let origin = ("origin", TEST_ORIGIN.to_string());
    let csrf = ("x-bp-csrf", "1".to_string());

    assert!(bphttp::authenticate(&ctx, &Method::GET, &bearer(&api)).await.is_ok());
    assert!(bphttp::authenticate(&ctx, &Method::GET, &bearer(&session)).await.is_err(), "session token accepted as bearer");
    assert!(bphttp::authenticate(&ctx, &Method::GET, &cookie(&api, &[])).await.is_err(), "API token accepted as cookie");

    assert!(bphttp::authenticate(&ctx, &Method::GET, &cookie(&session, &[])).await.is_ok());
    assert!(bphttp::authenticate(&ctx, &Method::POST, &cookie(&session, &[origin.clone(), csrf.clone()])).await.is_ok());
    for (why, hs) in [
        ("no origin, no header", cookie(&session, &[])),
        ("header but no origin", cookie(&session, std::slice::from_ref(&csrf))),
        ("origin but no header", cookie(&session, std::slice::from_ref(&origin))),
        ("foreign origin", cookie(&session, &[("origin", "https://evil.test".to_string()), csrf.clone()])),
        ("look-alike origin", cookie(&session, &[("origin", format!("{TEST_ORIGIN}.evil.test")), csrf.clone()])),
    ] {
        for m in [Method::POST, Method::PUT, Method::PATCH, Method::DELETE] {
            assert!(matches!(bphttp::authenticate(&ctx, &m, &hs).await, Err(Error::Forbidden)), "{m} with {why} was accepted");
        }
    }
    // Cross-site WebSocket hijack: an upgrade without the portal origin.
    let ws = cookie(&session, &[("upgrade", "websocket".to_string()), ("origin", "https://evil.test".to_string())]);
    assert!(bphttp::authenticate(&ctx, &Method::GET, &ws).await.is_err());
    // No credentials at all.
    assert!(matches!(bphttp::authenticate(&ctx, &Method::GET, &HeaderMap::new()).await, Err(Error::Unauthorized)));
    db.cleanup().await;
}

// ------------------------------------------------------------ encryption

/// Attack: an attacker who can write the database copies tenant A's sealed
/// blob, or A's wrapped key row, into tenant B and asks the service to open it.
#[tokio::test]
async fn sealed_data_and_wrapped_keys_cannot_be_moved_between_tenants() {
    let Some(db) = TestDb::new([]).await else { return };
    let ctx = db.app_ctx();
    let (a, b) = (db.tenant("acme").await, db.tenant("globex").await);
    let secret = b"PO-4411: 250 boards, ship to 1 Infinite Loop";
    let blob = ctx.cipher.seal(a, b"orders|1|payload", secret).await.unwrap();
    assert!(!blob.windows(7).any(|w| w == b"PO-4411"), "plaintext visible in the sealed blob");
    assert_eq!(ctx.cipher.open(a, b"orders|1|payload", &blob).await.unwrap(), secret);

    // Blob moved to another tenant, another row, another column.
    assert!(ctx.cipher.open(b, b"orders|1|payload", &blob).await.is_err());
    assert!(ctx.cipher.open(a, b"orders|2|payload", &blob).await.is_err());
    assert!(ctx.cipher.open(a, b"orders|1|address", &blob).await.is_err());

    // Each tenant has its own key row, stored wrapped (never 32 raw bytes).
    ctx.cipher.seal(b, b"x", b"warm").await.unwrap();
    let rows: Vec<(uuid::Uuid, Vec<u8>)> = sqlx::query_as("SELECT tenant_id, wrapped_dek FROM tenant_keys ORDER BY tenant_id")
        .fetch_all(db.admin_pool())
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    assert_ne!(rows[0].1, rows[1].1);
    assert!(rows.iter().all(|r| r.1.len() > 32), "DEK stored unwrapped");

    // Key row of A planted as B's next key version: the wrap is bound to the
    // tenant, so the service must refuse it rather than encrypt B's data
    // under a key A's row holder knows.
    let a_wrapped = rows.iter().find(|r| r.0 == a.0).unwrap().1.clone();
    sqlx::query("INSERT INTO tenant_keys (tenant_id, version, kek_id, wrapped_dek) VALUES ($1, 2, 'local:test', $2)")
        .bind(b.0)
        .bind(&a_wrapped)
        .execute(db.admin_pool())
        .await
        .unwrap();
    // A fresh cipher (no cached keys) sees version 2 as current and must fail closed.
    let fresh = bp_ent_core::EnvelopeCipher::new(
        std::sync::Arc::new(bp_ent_core::crypto::LocalKek::new("local:test", bp_ent_core::crypto::KeyBytes::from_slice(&[0x42; 32]).unwrap())),
        std::sync::Arc::new(bp_ent_core::crypto::PgDekStore::new(ctx.db.clone())),
    );
    assert!(fresh.seal(b, b"x", b"data").await.is_err(), "service used a key row transplanted from another tenant");
    db.cleanup().await;
}

/// Attack: read another tenant's key rows through the service role.
#[tokio::test]
async fn key_rows_are_tenant_scoped() {
    let Some(db) = TestDb::new([]).await else { return };
    let ctx = db.app_ctx();
    let (a, b) = (db.tenant("acme").await, db.tenant("globex").await);
    ctx.cipher.seal(a, b"x", b"1").await.unwrap();
    ctx.cipher.seal(b, b"x", b"1").await.unwrap();
    let mut tx = ctx.db.tenant_tx(a).await.unwrap();
    let seen: Vec<uuid::Uuid> = sqlx::query_scalar("SELECT tenant_id FROM tenant_keys").fetch_all(&mut *tx).await.unwrap();
    assert_eq!(seen, vec![a.0]);
    // The service role has no DELETE on key rows (losing one loses the data).
    assert!(sqlx::query("DELETE FROM tenant_keys").execute(&mut *tx).await.is_err());
    db.cleanup().await;
}

// ------------------------------------------------------------------ RBAC

/// The role matrix, pinned. Changing what a role may do must be a deliberate
/// edit of this test, reviewed as a security change.
#[test]
fn role_matrix_is_pinned() {
    use Permission::*;
    let expect: [(Role, &[Permission]); 4] = [
        (Role::Engineer, &[PartsRead, PartsWrite, BoardsRead, BoardsComment, BoardsWrite, OrdersRead, OrdersWrite, VmUse, LlmUse]),
        (Role::Librarian, &[PartsRead, PartsWrite, PartsRelease, BoardsRead, BoardsComment, VmUse, LlmUse]),
        (Role::Purchasing, &[PartsRead, BoardsRead, BoardsComment, OrdersRead, OrdersWrite, OrdersApprove, MailManage]),
        (Role::ExternalReviewer, &[BoardsRead, BoardsComment]),
    ];
    for (role, perms) in expect {
        for p in Permission::ALL {
            assert_eq!(role.has(p), perms.contains(&p), "{role:?} / {p:?}");
        }
    }
    for p in Permission::ALL {
        assert!(Role::OrgAdmin.has(p));
    }
    // The guest role can never reach parts, orders, VMs, LLMs, mail, billing or admin.
    for p in [PartsRead, PartsWrite, PartsRelease, BoardsWrite, OrdersRead, OrdersWrite, OrdersApprove, MailManage, BillingManage, VmUse, VmManage, LlmUse, AdminManage, AuditRead] {
        assert!(!Role::ExternalReviewer.has(p), "external reviewer has {p:?}");
    }
    // Only admins approve their way into admin functions.
    for r in [Role::Engineer, Role::Librarian, Role::Purchasing, Role::ExternalReviewer] {
        for p in [AdminManage, AuditRead, VmManage, BillingManage] {
            assert!(!r.has(p), "{r:?} has {p:?}");
        }
    }
}

/// Attack: a narrow token (the KiCad library token) used for anything else,
/// even when its owner is an org admin; unknown scope strings.
#[tokio::test]
async fn token_scopes_narrow_and_never_widen_the_role() {
    let Some(db) = TestDb::new([]).await else { return };
    let ctx = db.app_ctx();
    let a = db.tenant("acme").await;
    let admin = db.user(a, Role::OrgAdmin).await;
    let guest = db.user(a, Role::ExternalReviewer).await;

    let issue = |who: bp_ent_core::Principal, scopes: Scopes| {
        let ctx = ctx.clone();
        async move {
            let mut tx = ctx.db.tenant_tx(a).await.unwrap();
            let (_, t) = auth::issue_token(&mut tx, a, who.user_id, AuthKind::DeviceToken, "kicad", &scopes, std::time::Duration::from_secs(600)).await.unwrap();
            tx.commit().await.unwrap();
            auth::verify_bearer(&ctx, t.expose()).await.unwrap()
        }
    };

    let narrow = issue(admin.clone(), Scopes::Only(vec![Permission::PartsRead])).await;
    assert!(narrow.can(Permission::PartsRead));
    for p in Permission::ALL.into_iter().filter(|p| *p != Permission::PartsRead) {
        assert!(!narrow.can(p), "parts:read token of an admin can {p:?}");
    }
    assert!(narrow.require_interactive().is_err(), "a token must not count as a person");

    // A scope the role does not have grants nothing.
    let wide = issue(guest.clone(), Scopes::Only(vec![Permission::AdminManage, Permission::PartsRead])).await;
    assert!(!wide.can(Permission::AdminManage) && !wide.can(Permission::PartsRead));

    // Unknown scope strings in the database grant nothing.
    assert_eq!(Scopes::parse(&["admin".into(), "parts:*".into(), "".into()]), Scopes::Only(vec![]));

    // Lifetime is capped.
    let mut tx = ctx.db.tenant_tx(a).await.unwrap();
    let too_long = std::time::Duration::from_secs(400 * 24 * 3600);
    assert!(auth::issue_token(&mut tx, a, admin.user_id, AuthKind::UserToken, "x", &Scopes::All, too_long).await.is_err());
    db.cleanup().await;
}

// ------------------------------------------------------------------ SSRF

/// Attack: make the server fetch internal addresses (cloud metadata, the
/// database, localhost) through a user-supplied URL.
#[test]
fn outbound_http_refuses_internal_destinations() {
    let http = bp_ent_core::SafeHttp::new(false).unwrap();
    for url in [
        "http://example.com/",                       // not https
        "https://169.254.169.254/latest/meta-data/", // AWS/GCP/Azure metadata
        "https://169.254.170.2/v2/credentials",      // ECS task credentials
        "https://[fd00:ec2::254]/",                  // AWS metadata over IPv6
        "https://127.0.0.1:5432/",
        "https://localhost/",
        "https://10.0.0.5/",
        "https://172.16.0.1/",
        "https://192.168.1.1/",
        "https://100.64.0.1/",                // CGNAT
        "https://0.0.0.0/",
        "https://[::1]/",
        "https://[::ffff:10.0.0.1]/",         // IPv4-mapped
        "https://[64:ff9b::a00:1]/",          // NAT64 of 10.0.0.1
        "https://2130706433/",                // 127.0.0.1 as a decimal
        "https://0x7f.0.0.1/",                // hex octet
        "https://user:pass@example.com/",     // embedded credentials
        "https://db.internal/",
        "https://printer.local/",
        "file:///etc/passwd",
        "gopher://127.0.0.1:6379/_FLUSHALL",
        "not a url",
    ] {
        assert!(http.check_url(url).is_err(), "{url} was allowed");
    }
    assert!(http.check_url("https://example.com/datasheet.pdf").is_ok());
    // The same ranges are refused after DNS resolution (rebinding).
    for ip in ["169.254.169.254", "127.0.0.1", "10.1.2.3", "::1", "fe80::1", "fc00::1", "::ffff:169.254.169.254"] {
        assert!(bp_ent_core::safehttp::is_blocked(ip.parse().unwrap(), false), "{ip}");
    }
    // Link-local (metadata) stays blocked even when a self-hoster allows private ranges.
    assert!(bp_ent_core::safehttp::is_blocked("169.254.169.254".parse().unwrap(), true));
    assert!(!bp_ent_core::safehttp::is_blocked("93.184.216.34".parse().unwrap(), false));
}

// ------------------------------------------------------------- audit log

/// Attack: an insider with database superuser rights edits or removes an
/// audit entry. The hash chain must show it.
#[tokio::test]
async fn audit_chain_detects_edits_and_deletions() {
    let Some(db) = TestDb::new([]).await else { return };
    let ctx = db.app_ctx();
    let (a, b) = (db.tenant("acme").await, db.tenant("globex").await);
    let admin = db.user(a, Role::OrgAdmin).await;

    let mut tx = ctx.db.tenant_tx(a).await.unwrap();
    let before = audit::verify_chain(&mut tx, a).await.unwrap();
    for i in 0..5 {
        audit::append(&mut tx, &admin, "order.approved", &format!("order:{i}"), serde_json::json!({ "n": i })).await.unwrap();
    }
    tx.commit().await.unwrap();
    let mut tx = ctx.db.tenant_tx(a).await.unwrap();
    assert_eq!(audit::verify_chain(&mut tx, a).await.unwrap(), before + 5);
    drop(tx);

    // Tenant B cannot see A's trail.
    let mut tx = ctx.db.tenant_tx(b).await.unwrap();
    let foreign: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE tenant_id = $1").bind(a.0).fetch_one(&mut *tx).await.unwrap();
    assert_eq!(foreign, 0);
    drop(tx);

    // Superuser switches the append-only triggers off and rewrites history.
    let admin_pool = db.admin_pool();
    sqlx::query("ALTER TABLE audit_log DISABLE TRIGGER USER").execute(admin_pool).await.unwrap();
    let seq: i64 = sqlx::query_scalar("SELECT max(seq) - 2 FROM audit_log WHERE tenant_id = $1").bind(a.0).fetch_one(admin_pool).await.unwrap();
    sqlx::query("UPDATE audit_log SET target = 'order:999' WHERE tenant_id = $1 AND seq = $2").bind(a.0).bind(seq).execute(admin_pool).await.unwrap();
    let mut tx = ctx.db.tenant_tx(a).await.unwrap();
    assert!(audit::verify_chain(&mut tx, a).await.is_err(), "edited entry not detected");
    drop(tx);

    // Put it back, then delete a middle entry instead.
    sqlx::query("UPDATE audit_log SET target = $3 WHERE tenant_id = $1 AND seq = $2").bind(a.0).bind(seq).bind(format!("order:{}", 2)).execute(admin_pool).await.unwrap();
    let mut tx = ctx.db.tenant_tx(a).await.unwrap();
    assert_eq!(audit::verify_chain(&mut tx, a).await.unwrap(), before + 5, "restored chain should verify");
    drop(tx);
    sqlx::query("DELETE FROM audit_log WHERE tenant_id = $1 AND seq = $2").bind(a.0).bind(seq).execute(admin_pool).await.unwrap();
    let mut tx = ctx.db.tenant_tx(a).await.unwrap();
    assert!(audit::verify_chain(&mut tx, a).await.is_err(), "deleted entry not detected");
    drop(tx);
    db.cleanup().await;
}

// ------------------------------------------------------- secrets in logs

/// Secrets and personal data must not reach a log line through `{:?}`.
#[tokio::test]
async fn secrets_and_emails_are_redacted_from_debug_output() {
    let s = Secret::new("bpe_u_supersecret".to_string());
    assert!(!format!("{s:?} {s}").contains("supersecret"));

    let Some(db) = TestDb::new([]).await else { return };
    let a: TenantId = db.tenant("acme").await;
    let p = db.user(a, Role::Engineer).await;
    let dbg = format!("{p:?}");
    assert!(!dbg.contains(&p.email) && !dbg.contains("example.test"), "principal Debug leaks the e-mail: {dbg}");
    db.cleanup().await;
}
