//! Catalog audit: structural multi-tenant guarantees that must hold for EVERY
//! table any crate's migration creates. A new table that forgets row-level
//! security fails here without anyone having to write a test for it.

use bp_ent_sectest::{SecDb, APP_ROLE};
use sqlx::Row;

/// Tables that legitimately have no `tenant_id` column. Keep this list short
/// and justify every entry.
const NO_TENANT_COLUMN: &[&str] = &[
    // The tenant row itself: isolated on `id = bp_tenant()`.
    "tenants",
];

/// Policies allowed to not reference the current tenant. Keep this list short
/// and justify every entry.
const NON_TENANT_POLICIES: &[(&str, &str)] = &[
    // Login routing (slug / verified domain -> tenant id) must be readable
    // before a tenant is known. Holds no customer data.
    ("tenant_directory", "directory_read"),
];

fn mentions_tenant(expr: &str) -> bool {
    expr.contains("bp_tenant()") || expr.contains("app.tenant_id")
}

#[tokio::test]
async fn every_table_has_forced_row_level_security() {
    let Some(db) = SecDb::new().await else { return };
    let rows = sqlx::query(
        "SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity,
                (SELECT count(*) FROM pg_policy p WHERE p.polrelid = c.oid) AS policies
           FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
          WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
          ORDER BY 1",
    )
    .fetch_all(&db.admin)
    .await
    .unwrap();
    assert!(!rows.is_empty());
    let mut bad = Vec::new();
    for r in rows {
        let name: String = r.get(0);
        let (enabled, forced, policies): (bool, bool, i64) = (r.get(1), r.get(2), r.get(3));
        if !enabled || !forced || policies == 0 {
            bad.push(format!("{name}: enabled={enabled} forced={forced} policies={policies}"));
        }
    }
    db.close().await;
    assert!(bad.is_empty(), "tables without ENABLE+FORCE RLS and a policy:\n{}", bad.join("\n"));
}

#[tokio::test]
async fn every_table_carries_a_not_null_tenant_id() {
    let Some(db) = SecDb::new().await else { return };
    let rows = sqlx::query(
        "SELECT c.relname,
                (SELECT format_type(a.atttypid, a.atttypmod) || CASE WHEN a.attnotnull THEN ' not null' ELSE ' nullable' END
                   FROM pg_attribute a
                  WHERE a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped) AS col
           FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
          WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
          ORDER BY 1",
    )
    .fetch_all(&db.admin)
    .await
    .unwrap();
    let mut bad = Vec::new();
    for r in rows {
        let name: String = r.get(0);
        let col: Option<String> = r.get(1);
        if NO_TENANT_COLUMN.contains(&name.as_str()) {
            continue;
        }
        if col.as_deref() != Some("uuid not null") {
            bad.push(format!("{name}: tenant_id is {col:?}, want uuid not null"));
        }
    }
    db.close().await;
    assert!(bad.is_empty(), "tables without `tenant_id uuid NOT NULL`:\n{}", bad.join("\n"));
}

#[tokio::test]
async fn every_policy_is_bound_to_the_current_tenant() {
    let Some(db) = SecDb::new().await else { return };
    let rows = sqlx::query(
        "SELECT c.relname, p.polname, p.polcmd::text, p.polpermissive,
                pg_get_expr(p.polqual, p.polrelid), pg_get_expr(p.polwithcheck, p.polrelid)
           FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid
           JOIN pg_namespace n ON n.oid = c.relnamespace
          WHERE n.nspname = 'public'
          ORDER BY 1, 2",
    )
    .fetch_all(&db.admin)
    .await
    .unwrap();
    let mut bad = Vec::new();
    for r in rows {
        let (table, policy, cmd): (String, String, String) = (r.get(0), r.get(1), r.get(2));
        let permissive: bool = r.get(3);
        let using: Option<String> = r.get(4);
        let check: Option<String> = r.get(5);
        if NON_TENANT_POLICIES.contains(&(table.as_str(), policy.as_str())) {
            // An exempt policy may only ever be a read policy.
            if cmd != "r" {
                bad.push(format!("{table}.{policy}: exempt policy must be FOR SELECT, is '{cmd}'"));
            }
            continue;
        }
        if !permissive {
            continue; // restrictive policies only narrow access
        }
        // polcmd: r=SELECT a=INSERT w=UPDATE d=DELETE *=ALL.
        // Reads/updates/deletes are filtered by USING; inserts/updates are
        // checked by WITH CHECK, which defaults to USING when absent.
        let reads = matches!(cmd.as_str(), "r" | "w" | "d" | "*");
        let writes = matches!(cmd.as_str(), "a" | "w" | "*");
        if reads && !using.as_deref().is_some_and(mentions_tenant) {
            bad.push(format!("{table}.{policy} ({cmd}): USING is {using:?}"));
        }
        if writes {
            let effective = check.as_deref().or(using.as_deref());
            if !effective.is_some_and(mentions_tenant) {
                bad.push(format!("{table}.{policy} ({cmd}): WITH CHECK is {check:?}"));
            }
        }
    }
    db.close().await;
    assert!(bad.is_empty(), "policies not bound to the current tenant:\n{}", bad.join("\n"));
}

#[tokio::test]
async fn app_role_is_unprivileged_and_owns_nothing() {
    let Some(db) = SecDb::new().await else { return };
    let r = sqlx::query(
        "SELECT rolsuper, rolbypassrls, rolcreatedb, rolcreaterole, rolreplication
           FROM pg_roles WHERE rolname = $1",
    )
    .bind(APP_ROLE)
    .fetch_one(&db.admin)
    .await
    .expect("bp_app role exists after migrations");
    let flags: Vec<bool> = (0..5).map(|i| r.get::<bool, _>(i)).collect();
    assert_eq!(flags, vec![false; 5], "bp_app must have no super/bypassrls/createdb/createrole/replication");

    // A table owner can disable RLS or drop policies; bp_app must own nothing.
    let owned: Vec<String> = sqlx::query_scalar(
        "SELECT c.relname::text FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
          WHERE n.nspname = 'public' AND pg_get_userbyid(c.relowner) = $1",
    )
    .bind(APP_ROLE)
    .fetch_all(&db.admin)
    .await
    .unwrap();
    assert!(owned.is_empty(), "bp_app owns relations: {owned:?}");

    // bp_app must not be able to create objects (shadow tables/functions).
    let can_create: bool = sqlx::query_scalar("SELECT has_schema_privilege($1, 'public', 'CREATE')")
        .bind(APP_ROLE)
        .fetch_one(&db.admin)
        .await
        .unwrap();
    assert!(!can_create, "bp_app can CREATE in schema public");

    // TRUNCATE ignores RLS; TRIGGER/REFERENCES let a role attach behaviour.
    let risky: Vec<String> = sqlx::query_scalar(
        "SELECT table_name || ':' || privilege_type FROM information_schema.role_table_grants
          WHERE table_schema = 'public' AND grantee IN ($1, 'PUBLIC')
            AND (privilege_type IN ('TRUNCATE', 'TRIGGER', 'REFERENCES') OR grantee = 'PUBLIC')
          ORDER BY 1",
    )
    .bind(APP_ROLE)
    .fetch_all(&db.admin)
    .await
    .unwrap();
    db.close().await;
    assert!(risky.is_empty(), "risky grants to bp_app / PUBLIC: {risky:?}");
}

/// SECURITY DEFINER functions run as their owner and so bypass RLS. None are
/// expected; add a reviewed exception here if one is ever needed.
#[tokio::test]
async fn no_security_definer_functions() {
    let Some(db) = SecDb::new().await else { return };
    let funcs: Vec<String> = sqlx::query_scalar(
        "SELECT p.proname::text FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
          WHERE n.nspname = 'public' AND p.prosecdef ORDER BY 1",
    )
    .fetch_all(&db.admin)
    .await
    .unwrap();
    db.close().await;
    assert!(funcs.is_empty(), "SECURITY DEFINER functions bypass RLS: {funcs:?}");
}

/// Foreign-key checks bypass RLS. A plain `REFERENCES other(id)` between two
/// tenant tables lets tenant A point a row at tenant B's row (an existence
/// oracle, and a cascade/integrity hazard). Tenant-to-tenant foreign keys must
/// be composite and include `tenant_id`.
#[tokio::test]
async fn foreign_keys_between_tenant_tables_include_tenant_id() {
    let Some(db) = SecDb::new().await else { return };
    let rows = sqlx::query(
        "SELECT src.relname, con.conname, dst.relname,
                EXISTS (SELECT 1 FROM unnest(con.conkey) k
                          JOIN pg_attribute a ON a.attrelid = con.conrelid AND a.attnum = k
                         WHERE a.attname = 'tenant_id') AS has_tenant
           FROM pg_constraint con
           JOIN pg_class src ON src.oid = con.conrelid
           JOIN pg_class dst ON dst.oid = con.confrelid
           JOIN pg_namespace n ON n.oid = src.relnamespace
          WHERE con.contype = 'f' AND n.nspname = 'public' AND dst.relname <> 'tenants'
          ORDER BY 1, 2",
    )
    .fetch_all(&db.admin)
    .await
    .unwrap();
    let bad: Vec<String> = rows
        .iter()
        .filter(|r| !r.get::<bool, _>(3))
        .map(|r| format!("{}.{} -> {}", r.get::<String, _>(0), r.get::<String, _>(1), r.get::<String, _>(2)))
        .collect();
    db.close().await;
    assert!(bad.is_empty(), "foreign keys that can cross tenants (make them (tenant_id, id)):\n{}", bad.join("\n"));
}
