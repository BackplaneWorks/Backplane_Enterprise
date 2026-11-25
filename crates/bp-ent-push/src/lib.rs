//! Backplane Enterprise account-based mobile push gateway (`bp-ent-push`).
//!
//! Any authenticated account (free or paid, no subscription required) can
//! register iOS/Android push tokens and send push alerts to its own devices.
//! Device tokens are strictly bound to `(tenant_id, user_id)` and stored
//! envelope-encrypted in `push_devices`.

#![forbid(unsafe_code)]

pub mod apns;
pub mod routes;

use axum::Router;
use bp_ent_core::AppCtx;
use sqlx::migrate::Migrator;
use std::sync::Arc;

pub fn migrator() -> Migrator {
    sqlx::migrate!("./migrations")
}

pub fn router(ctx: AppCtx) -> Router {
    let sender: Arc<dyn apns::ApnsSender> = Arc::new(apns::HttpApnsSender::from_env());
    let rate_limit = bp_ent_core::config::env_parse("BP_PUSH_RATE_PER_MINUTE", 60).unwrap_or(60);
    routes::router(ctx, sender, rate_limit)
}

pub fn router_with_sender(
    ctx: AppCtx,
    sender: Arc<dyn apns::ApnsSender>,
    rate_limit_per_min: u32,
) -> Router {
    routes::router(ctx, sender, rate_limit_per_min)
}
