//! Axum routers and security response headers for `bp-ent-httplib`.

pub mod httplib;
pub mod librarian;

use crate::cache::TenantScopedCache;
use axum::body::Body;
use axum::http::{header, HeaderValue, Request};
use axum::middleware::Next;
use axum::response::Response;
use bp_ent_core::AppCtx;

#[derive(Clone)]
pub struct HttpLibState {
    pub ctx: AppCtx,
    pub cache: TenantScopedCache,
}

impl HttpLibState {
    pub fn new(ctx: AppCtx) -> Self {
        Self {
            ctx,
            cache: TenantScopedCache::default(),
        }
    }
}

/// Ensures private library payloads are never stored in shared proxy/CDN caches
/// and always vary on the Authorization credential.
pub async fn private_no_store_headers(req: Request<Body>, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    headers.insert(header::VARY, HeaderValue::from_static("Authorization"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    resp
}
