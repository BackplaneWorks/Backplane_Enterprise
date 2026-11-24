//! Backplane Enterprise Private KiCad HTTP Library (`kicad_httplib` v1)
//! and Web Librarian service.

#![forbid(unsafe_code)]

pub mod cache;
pub mod ipc7351;
pub mod kicad_protocol;
pub mod model;
pub mod routes;
pub mod store;
pub mod url_guard;

use axum::middleware;
use axum::routing::get;
use axum::Router;
use bp_ent_core::AppCtx;
use routes::HttpLibState;
use sqlx::migrate::Migrator;

/// This crate's migrations (`0100-0199`).
pub fn migrator() -> Migrator {
    sqlx::migrate!("./migrations")
}

/// Feature router mounted by `bp-ent-api` under the authenticated `/v1` scope.
/// Exposes `/v1/httplib/{tenant}/*` and `/v1/librarian/*`.
pub fn router(ctx: AppCtx) -> Router {
    let state = HttpLibState::new(ctx.clone());
    let routes = Router::new()
        .nest("/v1/httplib", routes::httplib::router())
        .nest("/v1/librarian", routes::librarian::router())
        .with_state(state);
    bp_ent_core::http::with_auth(routes, &ctx)
        .layer(middleware::from_fn(routes::private_no_store_headers))
}

/// Standalone HTTP router when `bp-ent-httplib` runs as its own container/binary.
pub fn standalone_router(ctx: AppCtx) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .merge(router(ctx))
}
