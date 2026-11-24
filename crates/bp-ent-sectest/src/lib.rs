//! Shared harness for the security regression suite.
//!
//! The suite builds a throwaway database from every crate's migrations, in the
//! same global filename order `bp-ent-api migrate` uses, and then attacks it
//! the way a compromised or buggy service would: as the unprivileged `bp_app`
//! role, with the wrong tenant, or with no tenant at all.
//!
//! Set `BP_TEST_ADMIN_DATABASE_URL` to a superuser URL to run the database
//! tests. Without it they are skipped, unless `BP_TEST_REQUIRE_DB=1` (CI), in
//! which case a missing database is a failure rather than a silent pass.

use std::path::{Path, PathBuf};

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{Connection, Executor, PgConnection, PgPool};
use uuid::Uuid;

/// The runtime role every service connects as.
pub const APP_ROLE: &str = "bp_app";

/// A fresh database with all migrations applied. Dropped on `close`.
pub struct SecDb {
    admin_opts: PgConnectOptions,
    name: String,
    /// Superuser pool on the throwaway database (bypasses RLS: use it only to
    /// set up fixtures and to read the catalog).
    pub admin: PgPool,
}

/// Workspace root (two levels above this crate).
pub fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crate lives in <root>/crates/<name>")
        .to_path_buf()
}

/// Every `crates/*/migrations/*.sql`, sorted by file name (the numeric prefix
/// gives the global order: core 0001-0099, httplib 0100-0199, relay 0200-0299,
/// orders 0300-0399).
pub fn all_migrations() -> Vec<PathBuf> {
    let mut files = Vec::new();
    let crates = workspace_root().join("crates");
    for krate in std::fs::read_dir(&crates).expect("read crates/").flatten() {
        let dir = krate.path().join("migrations");
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for e in entries.flatten() {
            let p = e.path();
            if p.extension().and_then(|x| x.to_str()) == Some("sql") {
                files.push(p);
            }
        }
    }
    files.sort_by_key(|p| p.file_name().map(|n| n.to_os_string()));
    files
}

impl SecDb {
    /// `None` when no test database is configured (test should return early).
    pub async fn new() -> Option<SecDb> {
        let url = match std::env::var("BP_TEST_ADMIN_DATABASE_URL") {
            Ok(u) if !u.is_empty() => u,
            _ => {
                if std::env::var("BP_TEST_REQUIRE_DB").as_deref() == Ok("1") {
                    panic!("BP_TEST_REQUIRE_DB=1 but BP_TEST_ADMIN_DATABASE_URL is not set");
                }
                eprintln!("skipped: BP_TEST_ADMIN_DATABASE_URL not set");
                return None;
            }
        };
        let admin_opts: PgConnectOptions = url.parse().expect("valid BP_TEST_ADMIN_DATABASE_URL");
        let name = format!("bp_sectest_{}", Uuid::new_v4().simple());
        let mut c = PgConnection::connect_with(&admin_opts).await.expect("connect admin");
        // Roles are cluster-wide and tests run in parallel: create `bp_app`
        // once under an advisory lock so concurrent migrations do not race on
        // `CREATE ROLE` (the migration's own IF NOT EXISTS then finds it).
        c.execute(
            format!(
                "SELECT pg_advisory_lock(7262696573656374);
                 DO $$ BEGIN
                   IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN
                     CREATE ROLE {APP_ROLE} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
                   END IF;
                 END $$;
                 SELECT pg_advisory_unlock(7262696573656374);"
            )
            .as_str(),
        )
        .await
        .expect("ensure bp_app role");
        c.execute(format!("CREATE DATABASE {name}").as_str()).await.expect("create database");
        c.close().await.ok();

        let admin = PgPoolOptions::new()
            .max_connections(4)
            .connect_with(admin_opts.clone().database(&name))
            .await
            .expect("connect test database");

        let migrations = all_migrations();
        assert!(!migrations.is_empty(), "no migrations found under crates/*/migrations");
        for path in migrations {
            let sql = std::fs::read_to_string(&path).expect("read migration");
            if let Err(e) = sqlx::raw_sql(&sql).execute(&admin).await {
                panic!("migration {} failed: {e}", path.display());
            }
        }
        Some(SecDb { admin_opts, name, admin })
    }

    /// A connection that behaves like a service: role `bp_app`, no tenant set.
    pub async fn app_conn(&self) -> PgConnection {
        let mut c = PgConnection::connect_with(&self.admin_opts.clone().database(&self.name))
            .await
            .expect("connect");
        c.execute(format!("SET ROLE {APP_ROLE}").as_str()).await.expect("set role bp_app");
        c
    }

    /// Insert a tenant as the superuser and return its id.
    pub async fn make_tenant(&self, slug: &str) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)")
            .bind(id)
            .bind(slug)
            .bind(slug)
            .execute(&self.admin)
            .await
            .expect("insert tenant");
        id
    }

    /// Insert a user as the superuser and return its id.
    pub async fn make_user(&self, tenant: Uuid, email: &str, role: &str) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO users (id, tenant_id, email, role) VALUES ($1, $2, $3, $4)")
            .bind(id)
            .bind(tenant)
            .bind(email)
            .bind(role)
            .execute(&self.admin)
            .await
            .expect("insert user");
        id
    }

    pub async fn close(self) {
        self.admin.close().await;
        if let Ok(mut c) = PgConnection::connect_with(&self.admin_opts).await {
            let _ = c
                .execute(format!("DROP DATABASE IF EXISTS {} WITH (FORCE)", self.name).as_str())
                .await;
        }
    }
}

/// Begin a transaction on `c` scoped to `tenant`, exactly like
/// `Db::tenant_tx`: `set_config('app.tenant_id', <id>, true)`.
pub async fn begin_as(c: &mut PgConnection, tenant: Uuid) -> sqlx::Transaction<'_, sqlx::Postgres> {
    let mut tx = c.begin().await.expect("begin");
    sqlx::query("SELECT set_config('app.tenant_id', $1, true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await
        .expect("set tenant");
    tx
}
