//! Standalone binary entrypoint for `bp-ent-httplib`.

#![forbid(unsafe_code)]

use bp_ent_core::AppCtx;
use std::net::SocketAddr;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .json()
        .init();

    let ctx = AppCtx::from_env().await?;
    let addr: SocketAddr = std::env::var("BP_HTTPLIB_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8082".to_string())
        .parse()?;

    let app = bp_ent_httplib::standalone_router(ctx);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "bp-ent-httplib listening");
    axum::serve(listener, app).await?;
    Ok(())
}
