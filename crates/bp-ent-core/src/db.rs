//! Tenant-scoped database access.
//!
//! [`Db`] never hands out a bare connection: the only way to run a query is
//! inside [`Db::tenant_tx`], which opens a transaction and sets the
//! `app.tenant_id` GUC with transaction scope. Every table has
//! `FORCE ROW LEVEL SECURITY` with a policy on that GUC, and services connect
//! as `bp_app` (NOBYPASSRLS), so a query that forgets its `WHERE tenant_id`
//! still cannot see or write another tenant's rows.

use crate::{Error, Result, TenantId};
use sqlx::migrate::Migrator;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::str::FromStr;
use std::time::Duration;

/// A transaction bound to one tenant. Use `&mut *tx` as the sqlx executor.
pub type Tx = Transaction<'static, Postgres>;

#[derive(Clone)]
pub struct Db {
    pool: PgPool,
}

impl Db {
    /// Connect as the application role. Refuses to start if that role could
    /// bypass row-level security, because nothing else would notice.
    pub async fn connect(url: &str, max_connections: u32) -> anyhow::Result<Self> {
        Self::connect_with(PgConnectOptions::from_str(url)?, max_connections).await
    }

    pub async fn connect_with(opts: PgConnectOptions, max_connections: u32) -> anyhow::Result<Self> {
        // A transaction abandoned on an error path must not sit on its locks.
        let opts = opts
            .application_name("backplane-enterprise")
            .options([("idle_in_transaction_session_timeout", "60s")]);
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .acquire_timeout(Duration::from_secs(10))
            .connect_with(opts)
            .await?;
        let db = Self { pool };
        db.assert_unprivileged().await?;
        Ok(db)
    }

    async fn assert_unprivileged(&self) -> anyhow::Result<()> {
        let row = sqlx::query(
            "SELECT rolsuper, rolbypassrls, current_user::text AS name \
             FROM pg_roles WHERE rolname = current_user",
        )
        .fetch_one(&self.pool)
        .await?;
        let (sup, bypass): (bool, bool) = (row.get("rolsuper"), row.get("rolbypassrls"));
        let name: String = row.get("name");
        if sup || bypass {
            anyhow::bail!(
                "database role {name:?} can bypass row-level security; \
                 DATABASE_URL must use the bp_app role, not the schema owner"
            );
        }
        let owns: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
             WHERE n.nspname = 'public' AND c.relkind = 'r' \
               AND pg_get_userbyid(c.relowner) = current_user",
        )
        .fetch_one(&self.pool)
        .await?;
        if owns > 0 {
            anyhow::bail!("database role {name:?} owns tables; DATABASE_URL must use the bp_app role");
        }
        Ok(())
    }

    /// Begin a transaction that can only see and write `tenant`'s rows.
    /// The setting dies with the transaction, so a pooled connection never
    /// carries a tenant over to the next request.
    pub async fn tenant_tx(&self, tenant: TenantId) -> Result<Tx> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT set_config('app.tenant_id', $1, true)")
            .bind(tenant.0.to_string())
            .execute(&mut *tx)
            .await?;
        Ok(tx)
    }

    /// Resolve an org slug to its tenant (login routing; the directory holds
    /// nothing but slug/domain -> id).
    pub async fn tenant_by_slug(&self, slug: &str) -> Result<Option<TenantId>> {
        self.directory("slug", &slug.to_ascii_lowercase()).await
    }

    /// Resolve an operator-verified e-mail domain to its tenant.
    pub async fn tenant_by_domain(&self, domain: &str) -> Result<Option<TenantId>> {
        self.directory("domain", &domain.to_ascii_lowercase()).await
    }

    async fn directory(&self, kind: &str, value: &str) -> Result<Option<TenantId>> {
        let id: Option<uuid::Uuid> = sqlx::query_scalar(
            "SELECT tenant_id FROM tenant_directory WHERE kind = $1 AND value = $2",
        )
        .bind(kind)
        .bind(value)
        .fetch_optional(&self.pool)
        .await?;
        Ok(id.map(TenantId))
    }

    /// Every tenant id, for background jobs that loop over tenants and open a
    /// [`Db::tenant_tx`] for each (mail sync, idle-VM reaper, usage metering).
    pub async fn all_tenants(&self) -> Result<Vec<TenantId>> {
        let ids: Vec<uuid::Uuid> = sqlx::query_scalar(
            "SELECT tenant_id FROM tenant_directory WHERE kind = 'slug' ORDER BY tenant_id",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(ids.into_iter().map(TenantId).collect())
    }

    /// Liveness probe.
    pub async fn ping(&self) -> Result<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }

    pub async fn close(&self) {
        self.pool.close().await;
    }
}

/// Org slugs that would read as part of the product or the platform in a
/// URL, an e-mail or a support conversation (`acme` is fine, `admin` is not).
const RESERVED_SLUGS: &[&str] = &[
    "admin", "administrator", "api", "app", "assets", "auth", "backplane", "billing", "boards", "callback", "dashboard", "docs",
    "healthz", "help", "httplib", "internal", "librarian", "login", "logout", "mail", "me", "oauth", "orders", "portal", "public",
    "readyz", "relay", "root", "saml", "security", "signin", "signup", "sso", "static", "status", "support", "system", "v1", "vms",
    "webhooks", "www",
];

pub fn is_reserved_slug(slug: &str) -> bool {
    RESERVED_SLUGS.contains(&slug.to_ascii_lowercase().as_str())
}

/// Create a tenant with its slug and default settings. The caller commits.
pub async fn create_tenant(db: &Db, name: &str, slug: &str) -> Result<(TenantId, Tx)> {
    let tenant = TenantId::new();
    let slug = slug.to_ascii_lowercase();
    if is_reserved_slug(&slug) {
        return Err(Error::invalid("this organisation slug is reserved"));
    }
    let mut tx = db.tenant_tx(tenant).await?;
    sqlx::query("INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)")
        .bind(tenant.0)
        .bind(name)
        .bind(&slug)
        .execute(&mut *tx)
        .await
        .map_err(|e| match Error::from(e) {
            Error::Conflict(_) => Error::conflict("organisation slug is taken"),
            Error::Invalid(_) => Error::invalid(
                "slug must be 2-63 lowercase letters, digits or dashes; name 1-200 characters",
            ),
            other => other,
        })?;
    sqlx::query("INSERT INTO tenant_directory (tenant_id, kind, value) VALUES ($1, 'slug', $2)")
        .bind(tenant.0)
        .bind(&slug)
        .execute(&mut *tx)
        .await?;
    crate::policy::store_defaults(&mut tx, tenant).await?;
    crate::audit::append_system(&mut tx, tenant, "bootstrap", "tenant.created", &format!("tenant:{tenant}"), serde_json::json!({ "slug": slug })).await?;
    Ok((tenant, tx))
}

// ------------------------------------------------------------ migrations

/// This crate's migrations (0001-0099).
pub fn migrator() -> Migrator {
    sqlx::migrate!("./migrations")
}

/// Run every crate's migrations as the schema owner, then check that the
/// result is safe to serve from: every table has forced RLS and a tenant
/// column. `admin` must be the owner connection (`DATABASE_ADMIN_URL`).
pub async fn run_migrations(
    admin: &PgPool,
    migrators: impl IntoIterator<Item = Migrator>,
) -> anyhow::Result<()> {
    let mut all: Vec<Migrator> = migrators.into_iter().collect();
    // Each crate only knows its own files; the others' rows in
    // _sqlx_migrations are not "missing", just someone else's.
    for m in &mut all {
        m.set_ignore_missing(true);
    }
    // Global version order across crates (core 0001.., httplib 0100.., ...).
    all.sort_by_key(|m| m.iter().map(|mig| mig.version).min().unwrap_or(i64::MAX));
    for m in &all {
        m.run(admin).await?;
    }
    sqlx::query("REVOKE ALL ON TABLE _sqlx_migrations FROM bp_app").execute(admin).await?;
    verify_isolation(admin).await
}

/// Fail if any table in `public` could leak across tenants by construction.
pub async fn verify_isolation(admin: &PgPool) -> anyhow::Result<()> {
    let rows = sqlx::query(
        "SELECT c.relname::text AS name, c.relrowsecurity AS rls, c.relforcerowsecurity AS forced, \
                EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid AND a.attname = 'tenant_id' \
                        AND a.attnotnull AND NOT a.attisdropped AND a.atttypid = 'uuid'::regtype) AS has_tenant, \
                (SELECT count(*) FROM pg_policy p WHERE p.polrelid = c.oid) AS policies \
         FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') AND c.relname <> '_sqlx_migrations' \
         ORDER BY 1",
    )
    .fetch_all(admin)
    .await?;
    let mut bad = Vec::new();
    for r in rows {
        let name: String = r.get("name");
        let ok_tenant = r.get::<bool, _>("has_tenant") || name == "tenants";
        if !(r.get::<bool, _>("rls") && r.get::<bool, _>("forced") && ok_tenant && r.get::<i64, _>("policies") > 0) {
            bad.push(name);
        }
    }
    if !bad.is_empty() {
        anyhow::bail!(
            "tables without tenant_id + ENABLE/FORCE ROW LEVEL SECURITY + a policy: {}",
            bad.join(", ")
        );
    }
    Ok(())
}

/// Give the application role its login password (out of band from the
/// migration files). Run as the owner.
pub async fn set_app_role_password(admin: &PgPool, password: &crate::Secret<String>) -> anyhow::Result<()> {
    // ALTER ROLE takes no bind parameters; quote_literal does the escaping server-side.
    let stmt: String = sqlx::query_scalar("SELECT 'ALTER ROLE bp_app LOGIN PASSWORD ' || quote_literal($1)")
        .bind(password.expose())
        .fetch_one(admin)
        .await?;
    sqlx::query(&stmt).execute(admin).await.map(|_| ()).map_err(|e| {
        // The statement text holds the password; never let it into an error chain.
        anyhow::anyhow!("could not set bp_app password: {}", e.as_database_error().map(|d| d.message().to_string()).unwrap_or_else(|| "connection error".into()))
    })
}
