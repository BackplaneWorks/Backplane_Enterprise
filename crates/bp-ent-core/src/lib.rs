//! Backplane Enterprise shared kernel.
//!
//! Everything a service crate needs to stay inside its tenant: typed ids and
//! RBAC ([`rbac`]), a database handle that only hands out tenant-scoped
//! transactions ([`db`]), per-tenant envelope encryption ([`crypto`]), the
//! hash-chained audit log ([`audit`]), the admin policy engine ([`policy`]),
//! token verification ([`auth`]) and the HTTP glue ([`http`], [`safehttp`]).

#![forbid(unsafe_code)]

pub mod audit;
pub mod auth;
pub mod config;
pub mod crypto;
pub mod db;
pub mod error;
pub mod http;
pub mod ids;
pub mod policy;
pub mod rbac;
pub mod safehttp;
pub mod secret;
#[cfg(feature = "testkit")]
pub mod testkit;

use std::sync::Arc;

pub use config::CoreConfig;
pub use crypto::EnvelopeCipher;
pub use db::{Db, Tx};
pub use error::{Error, Result};
pub use ids::{TenantId, UserId};
pub use rbac::{AuthKind, Permission, Principal, Role};
pub use safehttp::SafeHttp;
pub use secret::Secret;

/// Shared service context. Cheap to clone; pass it to every `router(ctx)`.
#[derive(Clone)]
pub struct AppCtx {
    pub db: Db,
    pub cipher: EnvelopeCipher,
    pub http: SafeHttp,
    pub config: Arc<CoreConfig>,
}

impl AppCtx {
    /// Build the context a service binary runs with, from the environment
    /// (see [`CoreConfig::from_env`]).
    pub async fn from_env() -> anyhow::Result<Self> {
        let config = Arc::new(CoreConfig::from_env()?);
        let db = Db::connect(config.database_url.expose(), config.db_max_connections).await?;
        let provider = crypto::provider_from_env().await?;
        let cipher = EnvelopeCipher::new(provider, Arc::new(crypto::PgDekStore::new(db.clone())));
        let http = SafeHttp::new(config.http_allow_private)?;
        Ok(Self { db, cipher, http, config })
    }
}
