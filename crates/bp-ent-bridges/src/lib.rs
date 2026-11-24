//! Backplane Enterprise External Bridges & Comms:
//! bidirectional signed webhooks (Dots, Grok, n8n, custom bots), Slack,
//! Microsoft Teams, Discord, and a strictly scoped external agent peer (MCP/A2A).

#![forbid(unsafe_code)]

pub mod adapters;
pub mod model;
pub mod outbound;
pub mod peer;
pub mod ratelimit;
pub mod routes;
pub mod sealed;
pub mod signatures;
pub mod store;

use axum::Router;
use bp_ent_core::AppCtx;
use sqlx::migrate::Migrator;

/// This crate's migrations (`0400-0499`). Run after core's.
pub fn migrator() -> Migrator {
    sqlx::migrate!("./migrations")
}

/// Mountable router for `bp-ent-api`:
/// - `/v1/bridges/*` (authenticated OrgAdmin CRUD & outbound dispatch)
/// - `/v1/bridges/{public_id}/inbound` (native signature-verified webhooks)
/// - `/v1/bridges/{public_id}/a2a` (signature-verified sandboxed MCP/A2A peer)
pub fn router(ctx: AppCtx) -> Router {
    routes::router(ctx)
}
