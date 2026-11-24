//! Integration tests against a real Postgres, connected as `bp_app`.
//! Run with BP_TEST_ADMIN_DATABASE_URL set (see `bp_ent_core::testkit`).

use bp_ent_core::policy::{self, Approval, GateKind};
use bp_ent_core::rbac::Scopes;
use bp_ent_core::testkit::TestDb;
use bp_ent_core::{audit, auth, AuthKind, Error, Permission, Role, TenantId};
use sqlx::Row;
use std::time::Duration;

macro_rules! db {
    () => {
        match TestDb::new([]).await {
            Some(db) => db,
            None => return,
        }
    };
}

async fn count_users(db: &TestDb, scope: TenantId) -> i64 {
    let mut tx = db.app_ctx().db.tenant_tx(scope).await.unwrap();
    sqlx::query_scalar("SELECT count(*) FROM users").fetch_one(&mut *tx).await.unwrap()
}

#[tokio::test]
async fn rls_hides_other_tenants_even_without_a_where_clause() {
    let db = db!();
    let (a, b) = (db.tenant("acme").await, db.tenant("globex").await);
    db.user(a, Role::Engineer).await;
    db.user(a, Role::Librarian).await;
    db.user(b, Role::Engineer).await;

    assert_eq!(count_users(&db, a).await, 2);
    assert_eq!(count_users(&db, b).await, 1);
    // A tenant id that does not exist sees nothing.
    assert_eq!(count_users(&db, TenantId::new()).await, 0);
    // The owner sees all three: the rows really are in one table.
    let all: i64 = sqlx::query_scalar("SELECT count(*) FROM users").fetch_one(db.admin_pool()).await.unwrap();
    assert_eq!(all, 3);
    db.cleanup().await;
}

#[tokio::test]
async fn rls_refuses_writes_into_another_tenant() {
    let db = db!();
    let (a, b) = (db.tenant("acme").await, db.tenant("globex").await);
    let victim = db.user(b, Role::Engineer).await;
    let ctx = db.app_ctx();

    // INSERT with someone else's tenant_id
    let mut tx = ctx.db.tenant_tx(a).await.unwrap();
    let res = sqlx::query("INSERT INTO users (id, tenant_id, email, role) VALUES ($1, $2, 'x@example.test', 'org_admin')")
        .bind(uuid::Uuid::new_v4())
        .bind(b.0)
        .execute(&mut *tx)
        .await;
    assert!(res.is_err(), "WITH CHECK must reject a foreign tenant_id");
    drop(tx);

    // UPDATE / DELETE of someone else's row match nothing
    let mut tx = ctx.db.tenant_tx(a).await.unwrap();
    let n = sqlx::query("UPDATE users SET role = 'org_admin' WHERE id = $1").bind(victim.user_id.0).execute(&mut *tx).await.unwrap().rows_affected();
    assert_eq!(n, 0);
    let n = sqlx::query("DELETE FROM users WHERE id = $1").bind(victim.user_id.0).execute(&mut *tx).await.unwrap().rows_affected();
    assert_eq!(n, 0);
    // Moving one's own row into another tenant is refused too.
    let me = db.user(a, Role::Engineer).await;
    let res = sqlx::query("UPDATE users SET tenant_id = $2 WHERE id = $1").bind(me.user_id.0).bind(b.0).execute(&mut *tx).await;
    assert!(res.is_err());
    db.cleanup().await;
}

#[tokio::test]
async fn tenant_setting_does_not_outlive_its_transaction() {
    let db = db!();
    let a = db.tenant("acme").await;
    db.user(a, Role::Engineer).await;
    let ctx = db.app_ctx();
    // Churn through the pool so later checkouts reuse connections that
    // served tenant `a`.
    for _ in 0..20 {
        assert_eq!(count_users(&db, a).await, 1);
    }
    for _ in 0..20 {
        // A transaction for a different tenant on a reused connection.
        assert_eq!(count_users(&db, TenantId::new()).await, 0);
    }
    // The directory is the only thing readable with no tenant set.
    assert_eq!(ctx.db.tenant_by_slug("ACME").await.unwrap(), Some(a));
    assert_eq!(ctx.db.tenant_by_slug("nope").await.unwrap(), None);
    assert_eq!(ctx.db.all_tenants().await.unwrap(), vec![a]);
    db.cleanup().await;
}

#[tokio::test]
async fn app_role_is_unprivileged() {
    let db = db!();
    let a = db.tenant("acme").await;
    let ctx = db.app_ctx();
    let mut tx = ctx.db.tenant_tx(a).await.unwrap();
    let row = sqlx::query("SELECT rolsuper, rolbypassrls, rolcreaterole, rolcreatedb FROM pg_roles WHERE rolname = current_user").fetch_one(&mut *tx).await.unwrap();
    for col in ["rolsuper", "rolbypassrls", "rolcreaterole", "rolcreatedb"] {
        assert!(!row.get::<bool, _>(col), "{col}");
    }
    for stmt in [
        "CREATE TABLE evil (x int)",
        "ALTER TABLE users DISABLE ROW LEVEL SECURITY",
        "DROP POLICY tenant_isolation ON users",
        "CREATE FUNCTION public.bp_tenant2() RETURNS uuid LANGUAGE sql AS 'SELECT NULL::uuid'",
        "TRUNCATE users",
        "SELECT * FROM _sqlx_migrations",
        "INSERT INTO tenant_directory (tenant_id, kind, value) VALUES (bp_tenant(), 'domain', 'victim.example')",
    ] {
        let mut sp = ctx.db.tenant_tx(a).await.unwrap();
        assert!(sqlx::query(stmt).execute(&mut *sp).await.is_err(), "bp_app must not be able to: {stmt}");
    }
    db.cleanup().await;
}

#[tokio::test]
async fn slugs_are_unique_and_validated() {
    let db = db!();
    let ctx = db.app_ctx();
    db.tenant("acme").await;
    assert!(matches!(bp_ent_core::db::create_tenant(&ctx.db, "Other", "acme").await, Err(Error::Conflict(_))));
    assert!(matches!(bp_ent_core::db::create_tenant(&ctx.db, "Bad", "no spaces").await, Err(Error::Invalid(_))));
    for reserved in ["admin", "API", "www", "login", "support"] {
        assert!(matches!(bp_ent_core::db::create_tenant(&ctx.db, "Squatter", reserved).await, Err(Error::Invalid(_))), "{reserved}");
    }
    db.cleanup().await;
}

#[tokio::test]
async fn audit_chain_appends_verifies_and_detects_tampering() {
    let db = db!();
    let (a, b) = (db.tenant("acme").await, db.tenant("globex").await);
    let ctx = db.app_ctx();
    let admin = db.user(a, Role::OrgAdmin).await;

    for i in 0..5 {
        let mut tx = ctx.db.tenant_tx(a).await.unwrap();
        audit::append(&mut tx, &admin, "part.released", &format!("part:{i}"), serde_json::json!({ "i": i })).await.unwrap();
        tx.commit().await.unwrap();
    }
    let mut tx = ctx.db.tenant_tx(a).await.unwrap();
    // 1 tenant.created + 5
    assert_eq!(audit::verify_chain(&mut tx, a).await.unwrap(), 6);
    let entries = audit::list(&mut tx, a, None, 100).await.unwrap();
    assert_eq!(entries.len(), 6);
    assert_eq!(entries[0].seq, 6);
    // Tenant b has its own chain and cannot see a's.
    let mut txb = ctx.db.tenant_tx(b).await.unwrap();
    assert_eq!(audit::verify_chain(&mut txb, b).await.unwrap(), 1);
    assert_eq!(audit::list(&mut txb, a, None, 100).await.unwrap().len(), 0);
    txb.rollback().await.unwrap();

    // The application role cannot rewrite history.
    for stmt in ["UPDATE audit_log SET action = 'x'", "DELETE FROM audit_log", "TRUNCATE audit_log"] {
        let mut t = ctx.db.tenant_tx(a).await.unwrap();
        assert!(sqlx::query(stmt).execute(&mut *t).await.is_err(), "{stmt}");
        t.rollback().await.unwrap();
    }
    // Not even the owner, while the trigger is in place.
    assert!(sqlx::query("UPDATE audit_log SET action = 'x' WHERE seq = 3").execute(db.admin_pool()).await.is_err());

    // Someone with DDL rights who disables the trigger is still caught by the chain.
    sqlx::query("ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_update").execute(db.admin_pool()).await.unwrap();
    sqlx::query("UPDATE audit_log SET target = 'part:999' WHERE tenant_id = $1 AND seq = 3").bind(a.0).execute(db.admin_pool()).await.unwrap();
    let mut tx = ctx.db.tenant_tx(a).await.unwrap();
    let err = audit::verify_chain(&mut tx, a).await.unwrap_err();
    assert!(err.to_string().contains("seq 3"), "{err}");
    tx.rollback().await.unwrap();
    sqlx::query("DELETE FROM audit_log WHERE tenant_id = $1 AND seq = 3").bind(a.0).execute(db.admin_pool()).await.unwrap();
    let mut tx = ctx.db.tenant_tx(a).await.unwrap();
    assert!(audit::verify_chain(&mut tx, a).await.is_err());
    tx.rollback().await.unwrap();
    db.cleanup().await;
}

#[tokio::test]
async fn concurrent_audit_appends_keep_one_unbroken_chain() {
    let db = db!();
    let a = db.tenant("acme").await;
    let ctx = db.app_ctx();
    let admin = db.user(a, Role::OrgAdmin).await;
    let mut tasks = Vec::new();
    for i in 0..24 {
        let (ctx, admin) = (ctx.clone(), admin.clone());
        tasks.push(tokio::spawn(async move {
            let mut tx = ctx.db.tenant_tx(a).await.unwrap();
            audit::append(&mut tx, &admin, "test.event", "x:1", serde_json::json!({ "i": i })).await.unwrap();
            tx.commit().await.unwrap();
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    let mut tx = ctx.db.tenant_tx(a).await.unwrap();
    assert_eq!(audit::verify_chain(&mut tx, a).await.unwrap(), 25);
    db.cleanup().await;
}

#[tokio::test]
async fn tokens_verify_only_for_their_tenant_and_only_while_valid() {
    let db = db!();
    let (a, b) = (db.tenant("acme").await, db.tenant("globex").await);
    let ctx = db.app_ctx();
    let user = db.user(a, Role::Engineer).await;
    let token = db.token(&user, AuthKind::UserToken).await;

    let p = auth::verify_bearer(&ctx, &token).await.unwrap();
    assert_eq!((p.tenant_id, p.user_id, p.role, p.auth), (a, user.user_id, Role::Engineer, AuthKind::UserToken));

    // Only the hash is stored.
    let stored: Vec<Vec<u8>> = sqlx::query_scalar("SELECT token_hash FROM auth_tokens").fetch_all(db.admin_pool()).await.unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].len(), 32);
    let dump: String = sqlx::query_scalar("SELECT string_agg(t::text, ' ') FROM auth_tokens t").fetch_one(db.admin_pool()).await.unwrap();
    assert!(!dump.contains(token.rsplit('_').next().unwrap()));

    // Same secret, tenant swapped to b: looked up inside b, finds nothing.
    let forged = token.replace(&a.0.simple().to_string(), &b.0.simple().to_string());
    assert!(matches!(auth::verify_bearer(&ctx, &forged).await, Err(Error::Unauthorized)));
    // Kind swapped (user token presented as a session).
    let as_session = token.replacen("bpe_u_", "bpe_s_", 1);
    assert!(matches!(auth::verify_bearer(&ctx, &as_session).await, Err(Error::Unauthorized)));
    // One character off.
    let mut wrong = token.clone();
    let last = wrong.pop().unwrap();
    wrong.push(if last == 'A' { 'B' } else { 'A' });
    assert!(matches!(auth::verify_bearer(&ctx, &wrong).await, Err(Error::Unauthorized)));
    assert!(matches!(auth::verify_bearer(&ctx, "garbage").await, Err(Error::Unauthorized)));

    // Suspended user: token stops working immediately.
    let mut tx = ctx.db.tenant_tx(a).await.unwrap();
    sqlx::query("UPDATE users SET status = 'suspended' WHERE id = $1").bind(user.user_id.0).execute(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
    assert!(auth::verify_bearer(&ctx, &token).await.is_err());
    let mut tx = ctx.db.tenant_tx(a).await.unwrap();
    sqlx::query("UPDATE users SET status = 'active' WHERE id = $1").bind(user.user_id.0).execute(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
    assert!(auth::verify_bearer(&ctx, &token).await.is_ok());

    // Revoked.
    let mut tx = ctx.db.tenant_tx(a).await.unwrap();
    assert!(auth::revoke_token(&mut tx, a, p.token_id).await.unwrap());
    tx.commit().await.unwrap();
    assert!(auth::verify_bearer(&ctx, &token).await.is_err());

    // Expired.
    let mut tx = ctx.db.tenant_tx(a).await.unwrap();
    let (id, short) = auth::issue_token(&mut tx, a, user.user_id, AuthKind::UserToken, "short", &Scopes::All, Duration::from_secs(60)).await.unwrap();
    sqlx::query("UPDATE auth_tokens SET expires_at = now() - interval '1 second' WHERE id = $1").bind(id).execute(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
    assert!(auth::verify_bearer(&ctx, short.expose()).await.is_err());

    // Scoped token: narrower than the role.
    let mut tx = ctx.db.tenant_tx(a).await.unwrap();
    let (_, scoped) = auth::issue_token(&mut tx, a, user.user_id, AuthKind::DeviceToken, "kicad", &Scopes::Only(vec![Permission::PartsRead]), Duration::from_secs(60)).await.unwrap();
    tx.commit().await.unwrap();
    let p = auth::verify_bearer(&ctx, scoped.expose()).await.unwrap();
    assert!(p.can(Permission::PartsRead));
    assert!(!p.can(Permission::PartsWrite));
    assert!(!p.can(Permission::BoardsRead));

    // Suspended tenant: nothing works.
    sqlx::query("UPDATE tenants SET status = 'suspended' WHERE id = $1").bind(a.0).execute(db.admin_pool()).await.unwrap();
    assert!(auth::verify_bearer(&ctx, scoped.expose()).await.is_err());
    db.cleanup().await;
}

#[tokio::test]
async fn envelope_keys_are_per_tenant_and_stored_wrapped() {
    let db = db!();
    let (a, b) = (db.tenant("acme").await, db.tenant("globex").await);
    let ctx = db.app_ctx();
    let blob = ctx.cipher.seal(a, b"orders|1|po", b"ship to 1 Infinite Loop").await.unwrap();
    assert_eq!(ctx.cipher.open(a, b"orders|1|po", &blob).await.unwrap(), b"ship to 1 Infinite Loop");
    ctx.cipher.seal(b, b"x", b"y").await.unwrap();
    assert!(ctx.cipher.open(b, b"orders|1|po", &blob).await.is_err());

    let rows = sqlx::query("SELECT tenant_id, kek_id, wrapped_dek FROM tenant_keys ORDER BY tenant_id").fetch_all(db.admin_pool()).await.unwrap();
    assert_eq!(rows.len(), 2);
    let (wa, wb): (Vec<u8>, Vec<u8>) = (rows[0].get("wrapped_dek"), rows[1].get("wrapped_dek"));
    assert_ne!(wa, wb);
    assert_eq!(wa.len(), 12 + 32 + 16, "nonce + wrapped key + tag, never a bare 32-byte key");
    assert_eq!(rows[0].get::<String, _>("kek_id"), "local:test");

    // Tenant b cannot read or replace a's key row.
    let mut tx = ctx.db.tenant_tx(b).await.unwrap();
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM tenant_keys WHERE tenant_id = $1").bind(a.0).fetch_one(&mut *tx).await.unwrap();
    assert_eq!(n, 0);
    assert!(sqlx::query("DELETE FROM tenant_keys").execute(&mut *tx).await.is_err(), "no DELETE grant on tenant_keys");
    drop(tx);

    // Rotation through the real store.
    assert_eq!(ctx.cipher.rotate_dek(a).await.unwrap(), 2);
    let newer = ctx.cipher.seal(a, b"k", b"v").await.unwrap();
    assert_eq!(bp_ent_core::EnvelopeCipher::blob_key_version(&newer), Some(2));
    assert_eq!(ctx.cipher.open(a, b"orders|1|po", &blob).await.unwrap(), b"ship to 1 Infinite Loop");
    db.cleanup().await;
}

#[tokio::test]
async fn approval_gate_needs_a_second_person_in_a_browser() {
    let db = db!();
    let (a, b) = (db.tenant("acme").await, db.tenant("globex").await);
    let ctx = db.app_ctx();
    let agent = db.user_with(a, Role::Engineer, AuthKind::UserToken).await;
    let buyer = db.user(a, Role::Purchasing).await;
    let engineer = db.user(a, Role::Engineer).await;
    let outsider = db.user(b, Role::OrgAdmin).await;
    let gate = || GateKind::PlaceOrder { amount_cents: 120_000 };
    let summary = serde_json::json!({ "vendor": "fab", "total_cents": 120_000 });

    let mut tx = ctx.db.tenant_tx(a).await.unwrap();
    let first = policy::require_approval(&mut tx, &agent, gate(), "order:1", summary.clone()).await.unwrap();
    let Approval::Pending { request_id } = first else { panic!("expected pending, got {first:?}") };
    // Asking again does not open a second request.
    assert_eq!(policy::require_approval(&mut tx, &agent, gate(), "order:1", summary.clone()).await.unwrap(), Approval::Pending { request_id });
    tx.commit().await.unwrap();

    // Who may NOT approve:
    let mut tx = ctx.db.tenant_tx(a).await.unwrap();
    // the requester (four-eyes), even with a session
    let mut self_session = agent.clone();
    self_session.auth = AuthKind::Session;
    self_session.role = Role::Purchasing;
    assert!(matches!(policy::decide(&mut tx, &self_session, request_id, true, None).await, Err(Error::Forbidden)));
    // a role that is not an approver
    assert!(matches!(policy::decide(&mut tx, &engineer, request_id, true, None).await, Err(Error::Forbidden)));
    // an approver role acting through a token (an agent)
    let mut buyer_token = buyer.clone();
    buyer_token.auth = AuthKind::UserToken;
    assert!(matches!(policy::decide(&mut tx, &buyer_token, request_id, true, None).await, Err(Error::Forbidden)));
    drop(tx);
    // an admin of another tenant: the request does not exist for them
    let mut txb = ctx.db.tenant_tx(b).await.unwrap();
    assert!(matches!(policy::decide(&mut txb, &outsider, request_id, true, None).await, Err(Error::NotFound)));
    drop(txb);

    // The buyer approves in the browser.
    let mut tx = ctx.db.tenant_tx(a).await.unwrap();
    policy::decide(&mut tx, &buyer, request_id, true, Some("within budget")).await.unwrap();
    assert!(matches!(policy::decide(&mut tx, &buyer, request_id, true, None).await, Err(Error::Conflict(_))));
    tx.commit().await.unwrap();

    // A changed order does not ride on the old approval.
    let mut tx = ctx.db.tenant_tx(a).await.unwrap();
    let changed = serde_json::json!({ "vendor": "fab", "total_cents": 990_000 });
    let other = policy::require_approval(&mut tx, &agent, GateKind::PlaceOrder { amount_cents: 990_000 }, "order:1", changed).await.unwrap();
    assert!(matches!(other, Approval::Pending { request_id: r } if r != request_id));
    tx.rollback().await.unwrap();

    // The approved action proceeds exactly once.
    let mut tx = ctx.db.tenant_tx(a).await.unwrap();
    assert_eq!(policy::require_approval(&mut tx, &agent, gate(), "order:1", summary.clone()).await.unwrap(), Approval::Approved { request_id });
    let again = policy::require_approval(&mut tx, &agent, gate(), "order:1", summary.clone()).await.unwrap();
    assert!(matches!(again, Approval::Pending { request_id: r } if r != request_id), "an approval is single-use");
    tx.commit().await.unwrap();

    // Everything is in the audit log, and the chain holds.
    let mut tx = ctx.db.tenant_tx(a).await.unwrap();
    let actions: Vec<String> = audit::list(&mut tx, a, None, 100).await.unwrap().into_iter().map(|e| e.action).collect();
    for want in ["approval.requested", "approval.approved", "approval.consumed"] {
        assert!(actions.iter().any(|a| a == want), "{want} missing from {actions:?}");
    }
    audit::verify_chain(&mut tx, a).await.unwrap();
    db.cleanup().await;
}

#[tokio::test]
async fn policy_changes_need_an_admin_and_are_audited() {
    let db = db!();
    let a = db.tenant("acme").await;
    let ctx = db.app_ctx();
    let admin = db.user(a, Role::OrgAdmin).await;
    let engineer = db.user(a, Role::Engineer).await;

    let mut tx = ctx.db.tenant_tx(a).await.unwrap();
    let (mut llm, mut gates) = policy::load(&mut tx, a).await.unwrap();
    assert_eq!(llm, policy::LlmPolicy::default());
    llm.providers[0].zdr = true;
    llm.zdr_required = true;
    assert!(matches!(policy::save_llm_policy(&mut tx, &engineer, &llm).await, Err(Error::Forbidden)));
    policy::save_llm_policy(&mut tx, &admin, &llm).await.unwrap();

    gates.place_order.enabled = false;
    let mut admin_token = admin.clone();
    admin_token.auth = AuthKind::UserToken;
    assert!(matches!(policy::save_approval_gates(&mut tx, &admin_token, &gates).await, Err(Error::Forbidden)), "an agent must not switch its own gate off");
    policy::save_approval_gates(&mut tx, &admin, &gates).await.unwrap();
    tx.commit().await.unwrap();

    let mut tx = ctx.db.tenant_tx(a).await.unwrap();
    let (llm2, gates2) = policy::load(&mut tx, a).await.unwrap();
    assert!(llm2.zdr_required);
    assert!(!gates2.place_order.enabled);
    assert_eq!(policy::require_approval(&mut tx, &engineer, GateKind::PlaceOrder { amount_cents: 5 }, "order:9", serde_json::json!({})).await.unwrap(), Approval::NotRequired);
    let actions: Vec<String> = audit::list(&mut tx, a, None, 10).await.unwrap().into_iter().map(|e| e.action).collect();
    assert!(actions.contains(&"llm_policy.updated".to_string()));
    assert!(actions.contains(&"approval_gates.updated".to_string()));
    db.cleanup().await;
}

#[tokio::test]
async fn migration_check_rejects_a_table_without_isolation() {
    let db = db!();
    bp_ent_core::db::verify_isolation(db.admin_pool()).await.unwrap();
    sqlx::query("CREATE TABLE leaky (id int PRIMARY KEY, secret text)").execute(db.admin_pool()).await.unwrap();
    let err = bp_ent_core::db::verify_isolation(db.admin_pool()).await.unwrap_err();
    assert!(err.to_string().contains("leaky"), "{err}");
    // tenant_id alone is not enough: RLS must be enabled and forced.
    sqlx::query("ALTER TABLE leaky ADD COLUMN tenant_id uuid NOT NULL").execute(db.admin_pool()).await.unwrap();
    sqlx::query("ALTER TABLE leaky ENABLE ROW LEVEL SECURITY").execute(db.admin_pool()).await.unwrap();
    assert!(bp_ent_core::db::verify_isolation(db.admin_pool()).await.is_err());
    sqlx::query("ALTER TABLE leaky FORCE ROW LEVEL SECURITY").execute(db.admin_pool()).await.unwrap();
    sqlx::query("CREATE POLICY tenant_isolation ON leaky USING (tenant_id = bp_tenant()) WITH CHECK (tenant_id = bp_tenant())").execute(db.admin_pool()).await.unwrap();
    bp_ent_core::db::verify_isolation(db.admin_pool()).await.unwrap();
    db.cleanup().await;
}

#[tokio::test]
async fn refuses_to_run_as_a_role_that_bypasses_rls() {
    let db = db!();
    // The owner/superuser connection must be rejected as an application connection.
    let res = bp_ent_core::Db::connect_with(db.admin_options(), 1).await;
    assert!(res.is_err());
    db.cleanup().await;
}
