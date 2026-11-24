//! API server state and small shared helpers.

use crate::oidc::OidcClient;
use axum::http::HeaderMap;
use bp_ent_core::AppCtx;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub struct ApiConfig {
    pub bind: SocketAddr,
    /// Directory with the built web portal (`web/dist`); served with an
    /// SPA fallback when set, so one binary is the whole product.
    pub web_dir: Option<String>,
    /// How many reverse proxies in front of us append to `X-Forwarded-For`
    /// (0 = none: use the socket address). ALB = 1; CloudFront + ALB = 2.
    pub trusted_proxy_hops: usize,
    /// Login attempts allowed per client address per minute.
    pub auth_rate_per_minute: u32,
}

impl ApiConfig {
    /// `BP_BIND` (default `0.0.0.0:8080`), `BP_WEB_DIR`,
    /// `BP_TRUSTED_PROXY_HOPS` (default 0), `BP_AUTH_RATE_PER_MINUTE` (default 30).
    pub fn from_env() -> anyhow::Result<Self> {
        use bp_ent_core::config::env_parse;
        Ok(Self {
            bind: env_parse("BP_BIND", SocketAddr::from(([0, 0, 0, 0], 8080)))?,
            web_dir: std::env::var("BP_WEB_DIR").ok().filter(|s| !s.is_empty()),
            trusted_proxy_hops: env_parse("BP_TRUSTED_PROXY_HOPS", 0)?,
            auth_rate_per_minute: env_parse("BP_AUTH_RATE_PER_MINUTE", 30)?,
        })
    }

    pub fn for_tests() -> Self {
        Self { bind: SocketAddr::from(([127, 0, 0, 1], 0)), web_dir: None, trusted_proxy_hops: 0, auth_rate_per_minute: 1000 }
    }
}

#[derive(Clone)]
pub struct ApiState {
    pub ctx: AppCtx,
    pub cfg: Arc<ApiConfig>,
    pub oidc: OidcClient,
    pub limiter: RateLimiter,
}

impl ApiState {
    pub fn new(ctx: AppCtx, cfg: ApiConfig) -> Self {
        let limiter = RateLimiter::new(cfg.auth_rate_per_minute, Duration::from_secs(60));
        Self { ctx, cfg: Arc::new(cfg), oidc: OidcClient::default(), limiter }
    }
}

/// Fixed-window counter per key. In-process: a backstop for self-host and a
/// second layer behind the WAF rate rule on AWS.
#[derive(Clone)]
pub struct RateLimiter {
    max: u32,
    window: Duration,
    hits: Arc<Mutex<HashMap<String, (Instant, u32)>>>,
}

impl RateLimiter {
    pub fn new(max: u32, window: Duration) -> Self {
        Self { max, window, hits: Arc::new(Mutex::new(HashMap::new())) }
    }

    /// Count one hit; false when the key is over its limit.
    pub fn allow(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut hits = self.hits.lock().unwrap();
        if hits.len() > 50_000 {
            let window = self.window;
            hits.retain(|_, (start, _)| now.duration_since(*start) < window);
        }
        let entry = hits.entry(key.to_string()).or_insert((now, 0));
        if now.duration_since(entry.0) >= self.window {
            *entry = (now, 0);
        }
        entry.1 += 1;
        entry.1 <= self.max
    }
}

/// The client address: the socket peer, or the entry in `X-Forwarded-For`
/// written by the outermost trusted proxy. Entries further left are
/// client-supplied and ignored.
pub fn client_ip(headers: &HeaderMap, peer: Option<SocketAddr>, trusted_hops: usize) -> Option<IpAddr> {
    if trusted_hops > 0 {
        let chain: Vec<&str> = headers
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        if chain.len() >= trusted_hops {
            if let Ok(ip) = chain[chain.len() - trusted_hops].parse() {
                return Some(ip);
            }
        }
    }
    peer.map(|p| p.ip())
}

pub fn rfc3339(t: time::OffsetDateTime) -> String {
    t.format(&time::format_description::well_known::Rfc3339).unwrap_or_default()
}

pub fn rfc3339_opt(t: Option<time::OffsetDateTime>) -> Option<String> {
    t.map(rfc3339)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limiter_limits_per_key() {
        let l = RateLimiter::new(3, Duration::from_secs(60));
        assert!(l.allow("a") && l.allow("a") && l.allow("a"));
        assert!(!l.allow("a"));
        assert!(l.allow("b"));
        let l = RateLimiter::new(1, Duration::from_millis(1));
        assert!(l.allow("a"));
        std::thread::sleep(Duration::from_millis(5));
        assert!(l.allow("a"));
    }

    #[test]
    fn client_ip_ignores_spoofed_forwarded_entries() {
        let peer = Some(SocketAddr::from(([10, 0, 0, 9], 1234)));
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "6.6.6.6, 203.0.113.7".parse().unwrap());
        // No trusted proxy: the header is ignored entirely.
        assert_eq!(client_ip(&h, peer, 0), Some("10.0.0.9".parse().unwrap()));
        // One proxy: its entry is the rightmost; the spoofed left one is ignored.
        assert_eq!(client_ip(&h, peer, 1), Some("203.0.113.7".parse().unwrap()));
        // More hops claimed than present: fall back to the peer.
        assert_eq!(client_ip(&h, peer, 3), Some("10.0.0.9".parse().unwrap()));
    }
}
