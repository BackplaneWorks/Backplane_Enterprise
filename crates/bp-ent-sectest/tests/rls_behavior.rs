//! Behavioural isolation tests: act as the `bp_app` service role and try to
//! read, write and move data across tenants.

use bp_ent_sectest::{begin_as, SecDb};
use sqlx::{Connection, Executor, Row};
use uuid::Uuid;

/// With no tenant set, the service role must see nothing in any table that
/// holds tenant data (fail closed), and must not error into a fallback.
#[tokio::test]
async fn no_tenant_set_sees_no_rows_in_any_table() {
    let Some(db) = SecDb::new().await else { return };
    let a = db.make_tenant("acme").await;
    db.make_user(a, "eve@acme.test", "engineer").await;

    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT c.relname::text FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
          WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') AND c.relname <> 'tenant_directory'
          ORDER BY 1",
    )
    .fetch_all(&db.admin)
    .await
    .unwrap();

    let mut c = db.app_conn().await;
    let mut leaks = Vec::new();
    for t in &tables {
        // Tables bp_app has no SELECT on are fine (permission denied).
        let q = format!("SELECT count(*) FROM {t}");
        match sqlx::query_scalar::<_, i64>(&q).fetch_one(&mut c).await {
            Ok(0) => {}
            Ok(n) => leaks.push(format!("{t}: {n} rows visible with no tenant")),
            Err(e) => {
                let msg = e.to_string();
                assert!(msg.contains("permission denied"), "{t}: unexpected error {msg}");
            }
        }
    }
    // Same again with the empty string a pooled connection reports after a
    // previous transaction's SET LOCAL.
    c.execute("SELECT set_config('app.tenant_id', '', false)").await.unwrap();
    for t in ["tenants", "users"] {
        let n: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM {t}")).fetch_one(&mut c).await.unwrap();
        if n != 0 {
            leaks.push(format!("{t}: {n} rows visible with empty tenant"));
        }
    }
    c.close().await.ok();
    db.close().await;
    assert!(leaks.is_empty(), "{}", leaks.join("\n"));
}

#[tokio::test]
async fn tenant_cannot_read_update_or_delete_another_tenants_rows() {
    let Some(db) = SecDb::new().await else { return };
    let a = db.make_tenant("acme").await;
    let b = db.make_tenant("globex").await;
    let user_b = db.make_user(b, "bob@globex.test", "org_admin").await;
    db.make_user(a, "alice@acme.test", "org_admin").await;

    let mut c = db.app_conn().await;
    let mut tx = begin_as(&mut c, a).await;

    let emails: Vec<String> = sqlx::query_scalar("SELECT email FROM users ORDER BY 1").fetch_all(&mut *tx).await.unwrap();
    assert_eq!(emails, vec!["alice@acme.test"], "tenant A sees exactly its own users");

    let seen: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE id = $1")
        .bind(user_b)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(seen, 0, "direct lookup of tenant B's user by id");

    let tenants: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM tenants").fetch_all(&mut *tx).await.unwrap();
    assert_eq!(tenants, vec![a], "tenant A sees only its own tenant row");

    let updated = sqlx::query("UPDATE users SET role = 'org_admin', email = 'pwned@acme.test' WHERE id = $1")
        .bind(user_b)
        .execute(&mut *tx)
        .await
        .unwrap()
        .rows_affected();
    assert_eq!(updated, 0, "update of tenant B's user");

    let deleted = sqlx::query("DELETE FROM users WHERE tenant_id = $1").bind(b).execute(&mut *tx).await.unwrap().rows_affected();
    assert_eq!(deleted, 0, "delete of tenant B's users");
    tx.commit().await.unwrap();
    c.close().await.ok();

    // Ground truth, as superuser: B's user is untouched.
    let r = sqlx::query("SELECT email, role FROM users WHERE id = $1").bind(user_b).fetch_one(&db.admin).await.unwrap();
    assert_eq!(r.get::<String, _>(0), "bob@globex.test");
    assert_eq!(r.get::<String, _>(1), "org_admin");
    db.close().await;
}

#[tokio::test]
async fn tenant_cannot_insert_or_move_rows_into_another_tenant() {
    let Some(db) = SecDb::new().await else { return };
    let a = db.make_tenant("acme").await;
    let b = db.make_tenant("globex").await;
    let user_a = db.make_user(a, "alice@acme.test", "engineer").await;

    let mut c = db.app_conn().await;

    // INSERT a row tagged with tenant B while scoped to tenant A.
    let mut tx = begin_as(&mut c, a).await;
    let err = sqlx::query("INSERT INTO users (id, tenant_id, email, role) VALUES ($1, $2, 'mole@globex.test', 'org_admin')")
        .bind(Uuid::new_v4())
        .bind(b)
        .execute(&mut *tx)
        .await
        .expect_err("insert into another tenant must be rejected");
    assert!(err.to_string().contains("row-level security"), "{err}");
    tx.rollback().await.unwrap();

    // UPDATE own row so it lands in tenant B (WITH CHECK must reject).
    let mut tx = begin_as(&mut c, a).await;
    let err = sqlx::query("UPDATE users SET tenant_id = $1 WHERE id = $2")
        .bind(b)
        .bind(user_a)
        .execute(&mut *tx)
        .await
        .expect_err("moving a row to another tenant must be rejected");
    assert!(err.to_string().contains("row-level security"), "{err}");
    tx.rollback().await.unwrap();

    // Create a tenant row for somebody else's id.
    let mut tx = begin_as(&mut c, a).await;
    let err = sqlx::query("INSERT INTO tenants (id, name, slug) VALUES ($1, 'x', 'squat-x')")
        .bind(Uuid::new_v4())
        .execute(&mut *tx)
        .await
        .expect_err("creating a foreign tenant row must be rejected");
    assert!(err.to_string().contains("row-level security"), "{err}");
    tx.rollback().await.unwrap();

    c.close().await.ok();
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE tenant_id = $1").bind(b).fetch_one(&db.admin).await.unwrap();
    db.close().await;
    assert_eq!(n, 0, "tenant B gained rows");
}

/// The tenant setting is transaction-local. After commit OR rollback, the
/// same (pooled) connection must be back to seeing nothing, so a request can
/// never inherit the previous request's tenant.
#[tokio::test]
async fn tenant_scope_does_not_survive_the_transaction() {
    let Some(db) = SecDb::new().await else { return };
    let a = db.make_tenant("acme").await;
    db.make_user(a, "alice@acme.test", "engineer").await;

    let mut c = db.app_conn().await;
    for commit in [true, false] {
        let mut tx = begin_as(&mut c, a).await;
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM users").fetch_one(&mut *tx).await.unwrap();
        assert_eq!(n, 1);
        if commit {
            tx.commit().await.unwrap();
        } else {
            tx.rollback().await.unwrap();
        }
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM users").fetch_one(&mut c).await.unwrap();
        assert_eq!(n, 0, "tenant scope leaked past the transaction (commit={commit})");
    }
    c.close().await.ok();
    db.close().await;
}

/// The service role cannot switch RLS off, drop a policy, or become the owner.
#[tokio::test]
async fn app_role_cannot_disable_or_bypass_rls() {
    let Some(db) = SecDb::new().await else { return };
    let mut c = db.app_conn().await;
    for sql in [
        "ALTER TABLE users DISABLE ROW LEVEL SECURITY",
        "ALTER TABLE users NO FORCE ROW LEVEL SECURITY",
        "DROP POLICY tenant_isolation ON users",
        "CREATE POLICY open ON users USING (true)",
        "TRUNCATE users CASCADE",
        "SET row_security = off; SELECT count(*) FROM users",
        "CREATE TABLE shadow (x int)",
        "CREATE FUNCTION bp_tenant() RETURNS uuid LANGUAGE sql AS 'SELECT NULL::uuid'",
        "ALTER ROLE bp_app BYPASSRLS",
    ] {
        let res = c.execute(sql).await;
        assert!(res.is_err(), "bp_app was allowed to run: {sql}");
        c.execute("RESET row_security").await.ok();
    }
    c.close().await.ok();
    db.close().await;
}

/// The audit log is append-only for the service role: no UPDATE, DELETE or
/// TRUNCATE, even on its own tenant's rows.
#[tokio::test]
async fn audit_log_is_append_only_for_the_app_role() {
    let Some(db) = SecDb::new().await else { return };
    let a = db.make_tenant("acme").await;
    sqlx::query(
        "INSERT INTO audit_log (tenant_id, seq, at_us, actor_kind, actor, action, target, details, prev_hash, hash)
         VALUES ($1, 1, 1, 'system', 'test', 'test.event', 't', '{}', '\\x00', '\\x01')",
    )
    .bind(a)
    .execute(&db.admin)
    .await
    .unwrap();

    let mut c = db.app_conn().await;
    for sql in [
        "UPDATE audit_log SET action = 'forged'",
        "DELETE FROM audit_log",
        "TRUNCATE audit_log",
    ] {
        let mut tx = begin_as(&mut c, a).await;
        let res = tx.execute(sql).await;
        assert!(res.is_err(), "bp_app was allowed to run: {sql}");
        tx.rollback().await.unwrap();
    }
    c.close().await.ok();

    // Even the schema owner hits the trigger.
    let res = sqlx::query("UPDATE audit_log SET action = 'forged'").execute(&db.admin).await;
    assert!(res.is_err(), "owner UPDATE on audit_log must be blocked by trigger");
    let action: String = sqlx::query_scalar("SELECT action FROM audit_log WHERE tenant_id = $1").bind(a).fetch_one(&db.admin).await.unwrap();
    db.close().await;
    assert_eq!(action, "test.event");
}
