//! Standalone `bp-ent-relay` binary and bridge agents:
//! - Server mode (default): client WSS + Boat VM mTLS listener + idle-VM reaper
//! - `boat-agent`: outbound TLS 1.3 mTLS bridge running inside a Boat VM/container
//! - `desktop-bridge`: outbound authenticated WSS bridge running on the Desktop

#![forbid(unsafe_code)]

use anyhow::{bail, Context};
use bp_ent_core::{config::env_parse, AppCtx};
use bp_ent_relay::{
    bridge, client_router_with_state, mtls_router_with_state, reap_idle_vms, MtlsRelayServer,
    RelayConfig, RelayState,
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .json()
        .init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("boat-agent") => {
            let f = parse_flags(&args[1..])?;
            let relay_url = one(&f, "relay-url")?.to_string();
            let ca_cert = PathBuf::from(one(&f, "ca-cert")?);
            let client_cert = PathBuf::from(one(&f, "client-cert")?);
            let client_key = PathBuf::from(one(&f, "client-key")?);
            let local_hub = one(&f, "local-hub")?.to_string();
            let peer_listen: SocketAddr = one(&f, "peer-listen")?.parse().context("invalid --peer-listen")?;
            return bridge::run_boat_agent(
                relay_url,
                ca_cert,
                client_cert,
                client_key,
                local_hub,
                peer_listen,
            )
            .await;
        }
        Some("desktop-bridge") => {
            let f = parse_flags(&args[1..])?;
            let api_url = one(&f, "api-url")?.to_string();
            let vm_id = Uuid::parse_str(one(&f, "vm-id")?).context("invalid --vm-id")?;
            let token_file = PathBuf::from(one(&f, "token-file")?);
            let ca_cert = f.get("ca-cert").filter(|v| !v.is_empty()).map(PathBuf::from);
            let local_hub = one(&f, "local-hub")?.to_string();
            let peer_listen: SocketAddr = one(&f, "peer-listen")?.parse().context("invalid --peer-listen")?;
            return bridge::run_desktop_bridge(
                api_url,
                vm_id,
                token_file,
                ca_cert,
                local_hub,
                peer_listen,
            )
            .await;
        }
        Some("serve") | None => {}
        Some(other) => bail!("unknown subcommand {other:?} (expected serve | boat-agent | desktop-bridge)"),
    }

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
    let mtls_host_raw = std::env::var("BP_RELAY_MTLS_HOST").unwrap_or_else(|_| "localhost".into());
    let mtls_hosts: Vec<&str> = mtls_host_raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    let mtls_hosts = if mtls_hosts.is_empty() { vec!["localhost"] } else { mtls_hosts };

    let client_app = client_router_with_state(state.clone());
    let mtls_app = mtls_router_with_state(state.clone());
    let mtls_server = MtlsRelayServer::new(&state.ca, &mtls_hosts, mtls_app)?;

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
            axum::serve(client_listener, client_app)
                .await
                .map_err(anyhow::Error::from)
        },
        mtls_server.serve(mtls_listener),
    )?;

    Ok(())
}

fn parse_flags(args: &[String]) -> anyhow::Result<HashMap<String, String>> {
    let mut out = HashMap::new();
    let mut i = 0;
    while i < args.len() {
        let key = args[i]
            .strip_prefix("--")
            .with_context(|| format!("unexpected argument {:?}", args[i]))?;
        let val = args
            .get(i + 1)
            .with_context(|| format!("--{key} requires a value"))?;
        out.insert(key.to_string(), val.clone());
        i += 2;
    }
    Ok(out)
}

fn one<'a>(f: &'a HashMap<String, String>, key: &str) -> anyhow::Result<&'a str> {
    f.get(key)
        .map(String::as_str)
        .filter(|s| !s.is_empty())
        .with_context(|| format!("--{key} is required"))
}
