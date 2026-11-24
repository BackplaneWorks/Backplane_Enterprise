//! Standalone `bp-ent-relay` binary:
//! - Client API + Desktop WSS listener (`BP_RELAY_CLIENT_ADDR`, default `0.0.0.0:8081`)
//! - Boat VM outbound TLS 1.3 mTLS listener (`BP_RELAY_MTLS_ADDR`, default `0.0.0.0:8443`)
//! - Background idle-VM reaper emitting Stripe `UsageRecord`s

#![forbid(unsafe_code)]

use bp_ent_core::{config::env_parse, AppCtx};
use bp_ent_relay::{reap_idle_vms, router_with_state, MtlsRelayServer, RelayConfig, RelayState};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .json()
        .init();

    let ctx = AppCtx::from_env().await?;
    let mut state = RelayState::from_ctx(ctx)?;
    let idle_secs: u64 = env_parse("BP_RELAY_IDLE_TIMEOUT_SECS", 900)?;
    state.config = RelayConfig {
        idle_timeout: Duration::from_secs(idle_secs),
        ..RelayConfig::default()
    };

    let client_addr: SocketAddr = std::env::var("BP_RELAY_CLIENT_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8081".to_string())
        .parse()?;
    let mtls_addr: SocketAddr = std::env::var("BP_RELAY_MTLS_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8443".to_string())
        .parse()?;
    let mtls_host = std::env::var("BP_RELAY_MTLS_HOST").unwrap_or_else(|_| "localhost".into());

    let app = router_with_state(state.clone());
    let mtls_server = MtlsRelayServer::new(&state.ca, &[mtls_host.as_str()], app.clone())?;

    let client_listener = TcpListener::bind(client_addr).await?;
    let mtls_listener = TcpListener::bind(mtls_addr).await?;
    tracing::info!(%client_addr, %mtls_addr, "bp-ent-relay listening");

    let reaper_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            if let Err(err) = reap_idle_vms(
                &reaper_state.ctx.db,
                &reaper_state.provisioner,
                &reaper_state.meter_sink,
                reaper_state.config.idle_timeout,
            )
            .await
            {
                tracing::error!(error = %err, "idle VM reaper sweep failed");
            }
        }
    });

    tokio::try_join!(
        async {
            axum::serve(client_listener, app)
                .await
                .map_err(anyhow::Error::from)
        },
        mtls_server.serve(mtls_listener),
    )?;

    Ok(())
}
