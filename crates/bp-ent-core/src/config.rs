//! Configuration shared by every service binary.

use crate::Secret;
use anyhow::{bail, Context};
use std::time::Duration;

pub struct CoreConfig {
    /// Postgres URL for the `bp_app` role (never the schema owner).
    pub database_url: Secret<String>,
    pub db_max_connections: u32,
    /// Origin of the web portal, e.g. `https://portal.example.com`. Used for
    /// CSRF/CORS checks and for building links.
    pub public_origin: String,
    /// Public base URL of the API, e.g. `https://api.example.com`.
    pub api_base_url: String,
    /// Set the `Secure` attribute (and `__Host-` prefix) on cookies. Only
    /// turned off for plain-http local development.
    pub cookie_secure: bool,
    pub session_ttl: Duration,
    /// Allow outbound requests to private addresses (self-host with an
    /// internal IdP or LLM). Cloud metadata addresses stay blocked regardless.
    pub http_allow_private: bool,
}

impl CoreConfig {
    /// Environment:
    /// - `DATABASE_URL` (required): bp_app connection string
    /// - `BP_PUBLIC_ORIGIN` (required), `BP_API_BASE_URL` (default: the origin)
    /// - `BP_DB_MAX_CONNECTIONS` (default 20)
    /// - `BP_SESSION_TTL_HOURS` (default 12)
    /// - `BP_INSECURE_COOKIES=1` (local http only)
    /// - `BP_HTTP_ALLOW_PRIVATE=1`
    pub fn from_env() -> anyhow::Result<Self> {
        let database_url = std::env::var("DATABASE_URL").context("DATABASE_URL is not set")?;
        let public_origin = normalize_origin(
            &std::env::var("BP_PUBLIC_ORIGIN").context("BP_PUBLIC_ORIGIN is not set")?,
        )?;
        let api_base_url = match std::env::var("BP_API_BASE_URL") {
            Ok(v) if !v.is_empty() => v.trim_end_matches('/').to_string(),
            _ => public_origin.clone(),
        };
        let cookie_secure = !env_flag("BP_INSECURE_COOKIES");
        if cookie_secure && !public_origin.starts_with("https://") {
            bail!("BP_PUBLIC_ORIGIN must be https (or set BP_INSECURE_COOKIES=1 for local development)");
        }
        Ok(Self {
            database_url: Secret::new(database_url),
            db_max_connections: env_parse("BP_DB_MAX_CONNECTIONS", 20)?,
            public_origin,
            api_base_url,
            cookie_secure,
            session_ttl: Duration::from_secs(env_parse::<u64>("BP_SESSION_TTL_HOURS", 12)? * 3600),
            http_allow_private: env_flag("BP_HTTP_ALLOW_PRIVATE"),
        })
    }

    pub fn session_cookie_name(&self) -> &'static str {
        if self.cookie_secure {
            "__Host-bpe_session"
        } else {
            "bpe_session"
        }
    }
}

/// `scheme://host[:port]` with no path, as browsers send it in `Origin`.
pub fn normalize_origin(raw: &str) -> anyhow::Result<String> {
    let u = url::Url::parse(raw).context("invalid origin URL")?;
    if !matches!(u.scheme(), "http" | "https") || u.host_str().is_none() {
        bail!("origin must be http(s)://host[:port]");
    }
    Ok(u.origin().ascii_serialization())
}

pub fn env_flag(name: &str) -> bool {
    matches!(std::env::var(name).as_deref(), Ok("1") | Ok("true") | Ok("yes"))
}

pub fn env_parse<T: std::str::FromStr>(name: &str, default: T) -> anyhow::Result<T>
where
    T::Err: std::fmt::Display,
{
    match std::env::var(name) {
        Ok(v) if !v.is_empty() => {
            v.parse().map_err(|e| anyhow::anyhow!("{name} is invalid: {e}"))
        }
        _ => Ok(default),
    }
}
