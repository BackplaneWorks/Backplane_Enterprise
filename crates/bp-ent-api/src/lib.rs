//! Backplane Enterprise API server.
//!
//! One binary serves everything: SSO and sessions, the admin console API,
//! and the routers of the feature crates (private KiCad library, orders and
//! billing, Boat VM relay, bridges, board co-development), plus the built
//! web portal when `BP_WEB_DIR` is set.

#![forbid(unsafe_code)]

pub mod jobs;
pub mod oidc;
pub mod routes;
pub mod saml;
pub mod state;

use axum::extract::{DefaultBodyLimit, Request};
use axum::http::{header, HeaderName, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use bp_ent_core::http::with_auth;
use bp_ent_core::AppCtx;
use sqlx::migrate::Migrator;
use state::ApiState;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;

/// Request bodies above this are refused unless a route sets its own limit.
const BODY_LIMIT: usize = 1024 * 1024;

/// Every crate's migrations, for `bp-ent-api migrate` and the test database.
pub fn migrators() -> Vec<Migrator> {
    #[allow(unused_mut)]
    let mut v = vec![bp_ent_core::db::migrator()];
    #[cfg(feature = "httplib")]
    v.push(bp_ent_httplib::migrator());
    #[cfg(feature = "relay")]
    v.push(bp_ent_relay::migrator());
    #[cfg(feature = "orders")]
    v.push(bp_ent_orders::migrator());
    #[cfg(feature = "bridges")]
    v.push(bp_ent_bridges::migrator());
    #[cfg(feature = "codev")]
    v.push(bp_ent_codev::migrator());
    #[cfg(feature = "push")]
    v.push(bp_ent_push::migrator());
    v
}

/// Routers of the feature crates, built by the binary (they read their own
/// configuration) and handed to [`app`].
#[derive(Default)]
pub struct Mounts {
    pub routers: Vec<Router>,
}

/// The routes this crate owns (auth, me, admin), without the feature crates.
pub fn core_router(st: ApiState) -> Router {
    let authed = with_auth(Router::new().merge(routes::me::router()).merge(routes::admin::router()).with_state(st.clone()), &st.ctx);
    Router::new().merge(routes::sso::router().with_state(st)).merge(authed)
}

/// The complete application.
pub fn app(st: ApiState, mounts: Mounts) -> Router {
    let ctx = st.ctx.clone();
    let mut api = core_router(st.clone());
    for r in mounts.routers {
        api = api.merge(r);
    }
    let api = api
        .route("/healthz", get(|| async { "ok" }))
        .route("/readyz", get(readyz).with_state(ctx.clone()))
        // Unknown API paths are JSON 404s, never the portal's index.html.
        .route("/v1/{*rest}", axum::routing::any(|| async { bp_ent_core::Error::NotFound }))
        .layer(axum::middleware::from_fn(api_headers));

    let mut app = api;
    if let Some(dir) = &st.cfg.web_dir {
        let index = std::path::Path::new(dir).join("index.html");
        let files = tower_http::services::ServeDir::new(dir).fallback(tower_http::services::ServeFile::new(index));
        app = app.fallback_service(tower::ServiceBuilder::new().layer(axum::middleware::from_fn(portal_headers)).service(files));
    }

    app.layer(DefaultBodyLimit::max(BODY_LIMIT))
        .layer(cors(&ctx))
        .layer(axum::middleware::from_fn(common_headers))
        // Method and path only: no query strings (OAuth codes), no headers.
        .layer(TraceLayer::new_for_http().make_span_with(|req: &Request| tracing::info_span!("http", method = %req.method(), path = %req.uri().path())))
}

async fn readyz(axum::extract::State(ctx): axum::extract::State<AppCtx>) -> Response {
    match ctx.db.ping().await {
        Ok(()) => Json(serde_json::json!({ "status": "ready" })).into_response(),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({ "status": "database unavailable" }))).into_response(),
    }
}

fn set_default(resp: &mut Response, name: HeaderName, value: &'static str) {
    if !resp.headers().contains_key(&name) {
        resp.headers_mut().insert(name, HeaderValue::from_static(value));
    }
}

/// Headers on every response.
async fn common_headers(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    set_default(&mut resp, header::STRICT_TRANSPORT_SECURITY, "max-age=63072000; includeSubDomains");
    set_default(&mut resp, header::X_CONTENT_TYPE_OPTIONS, "nosniff");
    set_default(&mut resp, header::X_FRAME_OPTIONS, "DENY");
    set_default(&mut resp, header::REFERRER_POLICY, "no-referrer");
    set_default(&mut resp, HeaderName::from_static("permissions-policy"), "camera=(), microphone=(), geolocation=(), payment=()");
    set_default(&mut resp, HeaderName::from_static("cross-origin-opener-policy"), "same-origin");
    resp
}

/// API responses are tenant data: never cached, never rendered as a page.
async fn api_headers(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    set_default(&mut resp, header::CACHE_CONTROL, "private, no-store");
    set_default(&mut resp, header::CONTENT_SECURITY_POLICY, "default-src 'none'; frame-ancestors 'none'");
    resp
}

/// The portal bundle: scripts and styles only from our own origin.
async fn portal_headers(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    set_default(
        &mut resp,
        header::CONTENT_SECURITY_POLICY,
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; \
         object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
    );
    resp
}

/// CORS: only when the portal is served from a different origin than the
/// API, and then for exactly that origin. Same-origin deployments (the
/// default: portal and API behind one host) get no CORS headers at all.
fn cors(ctx: &AppCtx) -> CorsLayer {
    let api_origin = bp_ent_core::config::normalize_origin(&ctx.config.api_base_url).unwrap_or_default();
    if api_origin == ctx.config.public_origin {
        return CorsLayer::new();
    }
    let origin = HeaderValue::from_str(&ctx.config.public_origin).expect("origin is a valid header value");
    CorsLayer::new()
        .allow_origin(AllowOrigin::exact(origin))
        .allow_credentials(true)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::PATCH, Method::DELETE])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION, HeaderName::from_static(bp_ent_core::http::CSRF_HEADER)])
        .max_age(std::time::Duration::from_secs(600))
}
