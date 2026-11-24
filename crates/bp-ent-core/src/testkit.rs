//! Test database helper (feature `testkit`): a fresh, fully migrated database
//! per test, reached the way production reaches it (as `bp_app`, under RLS).
//!
//! Point `BP_TEST_ADMIN_DATABASE_URL` at a throwaway Postgres superuser URL.
//! Without it tests that call [`TestDb::new`] skip, unless
//! `BP_TEST_REQUIRE_DB=1`, in which case they fail (so CI cannot pass
//! silently with no database).

use crate::crypto::{KeyBytes, LocalKek, PgDekStore};
use crate::rbac::Scopes;
use crate::{AppCtx, AuthKind, CoreConfig, Db, EnvelopeCipher, Principal, Role, SafeHttp, Secret, TenantId, UserId};
use sqlx::migrate::Migrator;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{Connection, PgPool};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

const APP_PASSWORD: &str = "bp_app_test";
pub const TEST_ORIGIN: &str = "https://portal.test";

pub struct TestDb {
    name: String,
    admin_opts: PgConnectOptions,
    admin: PgPool,
    ctx: AppCtx,
}

impl TestDb {
    /// A new database with core's migrations plus `extra` (other crates'
    /// `migrator()`s). `None` means "no test database configured: skip".
    pub async fn new(extra: impl IntoIterator<Item = Migrator>) -> Option<TestDb> {
        let url = match std::env::var("BP_TEST_ADMIN_DATABASE_URL") {
            Ok(u) if !u.is_empty() => u,
            _ => {
                if crate::config::env_flag("BP_TEST_REQUIRE_DB") {
                    panic!("BP_TEST_REQUIRE_DB=1 but BP_TEST_ADMIN_DATABASE_URL is not set");
                }
                eprintln!("skipping: BP_TEST_ADMIN_DATABASE_URL is not set");
                return None;
            }
        };
        Some(Self::create(&url, extra).await.expect("test database setup failed"))
    }

    async fn create(url: &str, extra: impl IntoIterator<Item = Migrator>) -> anyhow::Result<TestDb> {
        let base = PgConnectOptions::from_str(url)?;
        let name = format!("bpe_test_{}", uuid::Uuid::new_v4().simple());

        // Roles are cluster-wide: create bp_app once, serialised across
        // parallel tests, before any migration tries to.
        let mut conn = sqlx::PgConnection::connect_with(&base).await?;
        sqlx::query("SELECT pg_advisory_lock(7265001)").execute(&mut conn).await?;
        sqlx::query(
            "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'bp_app') THEN \
             CREATE ROLE bp_app NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS; END IF; END $$",
        )
        .execute(&mut conn)
        .await?;
        sqlx::query(&format!("ALTER ROLE bp_app LOGIN PASSWORD '{APP_PASSWORD}'")).execute(&mut conn).await?;
        sqlx::query("SELECT pg_advisory_unlock(7265001)").execute(&mut conn).await?;
        sqlx::query(&format!("CREATE DATABASE {name}")).execute(&mut conn).await?;
        conn.close().await?;

        let admin_opts = base.clone().database(&name);
        let admin = PgPoolOptions::new().max_connections(3).connect_with(admin_opts.clone()).await?;
        let mut migrators = vec![crate::db::migrator()];
        migrators.extend(extra);
        crate::db::run_migrations(&admin, migrators).await?;

        let app_opts = base.clone().database(&name).username("bp_app").password(APP_PASSWORD);
        let db = Db::connect_with(app_opts, 8).await?;
        let kek = LocalKek::new("local:test", KeyBytes::from_slice(&[0x42; 32]).unwrap());
        let cipher = EnvelopeCipher::new(Arc::new(kek), Arc::new(PgDekStore::new(db.clone())));
        let config = CoreConfig {
            database_url: Secret::new(String::new()),
            db_max_connections: 8,
            public_origin: TEST_ORIGIN.into(),
            api_base_url: TEST_ORIGIN.into(),
            cookie_secure: true,
            session_ttl: Duration::from_secs(3600),
            http_allow_private: false,
        };
        let ctx = AppCtx { db, cipher, http: SafeHttp::new(false)?, config: Arc::new(config) };
        Ok(TestDb { name, admin_opts, admin, ctx })
    }

    /// The context services run with: `bp_app` role, fixed test KEK.
    pub fn app_ctx(&self) -> AppCtx {
        self.ctx.clone()
    }

    /// Owner/superuser pool on the test database (bypasses RLS): for
    /// asserting what is really stored, and for simulating tampering.
    pub fn admin_pool(&self) -> &PgPool {
        &self.admin
    }

    /// Connection options for the test database as the owner.
    pub fn admin_options(&self) -> PgConnectOptions {
        self.admin_opts.clone()
    }

    pub async fn tenant(&self, slug: &str) -> TenantId {
        let (id, tx) = crate::db::create_tenant(&self.ctx.db, slug, slug).await.expect("create tenant");
        tx.commit().await.expect("commit tenant");
        id
    }

    /// Create an active user and return a session principal for them.
    pub async fn user(&self, tenant: TenantId, role: Role) -> Principal {
        self.user_with(tenant, role, AuthKind::Session).await
    }

    pub async fn user_with(&self, tenant: TenantId, role: Role, auth: AuthKind) -> Principal {
        let id = UserId::new();
        let email = format!("{}-{}@example.test", role.as_str(), id.0.simple());
        let mut tx = self.ctx.db.tenant_tx(tenant).await.unwrap();
        sqlx::query("INSERT INTO users (id, tenant_id, email, name, role) VALUES ($1, $2, $3, $4, $5)")
            .bind(id.0)
            .bind(tenant.0)
            .bind(&email)
            .bind(role.as_str())
            .bind(role.as_str())
            .execute(&mut *tx)
            .await
            .expect("insert user");
        tx.commit().await.unwrap();
        Principal { tenant_id: tenant, user_id: id, role, email, auth, scopes: Scopes::All, token_id: uuid::Uuid::new_v4() }
    }

    /// A real credential for `p` (session cookie value or bearer token).
    pub async fn token(&self, p: &Principal, kind: AuthKind) -> String {
        let mut tx = self.ctx.db.tenant_tx(p.tenant_id).await.unwrap();
        let (_, tok) = crate::auth::issue_token(&mut tx, p.tenant_id, p.user_id, kind, "test", &Scopes::All, Duration::from_secs(3600))
            .await
            .expect("issue token");
        tx.commit().await.unwrap();
        tok.expose().clone()
    }

    /// Drop the database. Optional: the test cluster is throwaway.
    pub async fn cleanup(self) {
        self.ctx.db.close().await;
        self.admin.close().await;
        let base = self.admin_opts.clone().database("postgres");
        if let Ok(mut c) = sqlx::PgConnection::connect_with(&base).await {
            let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS {} WITH (FORCE)", self.name)).execute(&mut c).await;
        }
    }
}
