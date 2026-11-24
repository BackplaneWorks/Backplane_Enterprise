//! `bp-ent-api`: the Backplane Enterprise server and its operator commands.
//!
//! ```text
//! bp-ent-api [serve]                       run the server (default)
//! bp-ent-api migrate                       apply all migrations as the schema owner
//! bp-ent-api tenant create --name N --slug S --admin-email E
//! bp-ent-api tenant add-domain --slug S --domain D
//! bp-ent-api idp add --slug S --provider google|microsoft|oidc ... (see --help)
//! bp-ent-api keys rewrap                   re-wrap every tenant key under the current KEK
//! bp-ent-api audit verify [--slug S]       recompute the audit hash chain(s)
//! ```

#![forbid(unsafe_code)]

use anyhow::{bail, Context};
use bp_ent_api::state::{ApiConfig, ApiState};
use bp_ent_api::{app, Mounts};
use bp_ent_core::{AppCtx, Secret};
use std::collections::HashMap;
use std::net::SocketAddr;

const HELP: &str = "\
bp-ent-api: Backplane Enterprise server

USAGE
  bp-ent-api [serve]
      Run the API (and the web portal when BP_WEB_DIR is set).
      Needs DATABASE_URL (bp_app role), BP_PUBLIC_ORIGIN, BP_KEK or BP_KMS_PROVIDER=aws.

  bp-ent-api migrate
      Apply every crate's migrations. Needs DATABASE_ADMIN_URL (schema owner).
      With BP_APP_DB_PASSWORD set, also gives the bp_app role that login password.

  bp-ent-api tenant create --name <name> --slug <slug> --admin-email <email>
      Create an organisation and invite its first org admin.

  bp-ent-api tenant add-domain --slug <slug> --domain <example.com>
      Record an e-mail domain you have verified belongs to the org
      (login routing by domain). Needs DATABASE_ADMIN_URL.

  bp-ent-api idp add --slug <slug> --provider <google|microsoft|oidc>
        --client-id <id> --client-secret-env <ENV_VAR>
        [--directory-id <workspace domain | entra tenant id>]
        [--issuer <https://...>] [--domain <example.com>]... [--auto-provision]
      Configure the org's first sign-in provider (later ones: admin console).

  bp-ent-api keys rewrap
      After rotating the master key (BP_KEK / BP_KMS_KEY_ID), re-wrap every
      tenant's data keys under the new one.

  bp-ent-api audit verify [--slug <slug>]
      Recompute the audit log hash chain for one or all organisations.
";

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(e) = run(args).await {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    let b = tracing_subscriber::fmt().with_env_filter(filter);
    if std::env::var("BP_LOG_FORMAT").as_deref() == Ok("text") {
        b.init();
    } else {
        b.json().init();
    }
}

/// `--key value` pairs and bare `--flag`s; repeated keys accumulate.
fn parse_flags(args: &[String]) -> anyhow::Result<HashMap<String, Vec<String>>> {
    let mut out: HashMap<String, Vec<String>> = HashMap::new();
    let mut i = 0;
    while i < args.len() {
        let key = args[i].strip_prefix("--").with_context(|| format!("unexpected argument {:?}", args[i]))?;
        if i + 1 < args.len() && !args[i + 1].starts_with("--") {
            out.entry(key.to_string()).or_default().push(args[i + 1].clone());
            i += 2;
        } else {
            out.entry(key.to_string()).or_default().push(String::new());
            i += 1;
        }
    }
    Ok(out)
}

fn one<'a>(flags: &'a HashMap<String, Vec<String>>, key: &str) -> anyhow::Result<&'a str> {
    flags.get(key).and_then(|v| v.first()).map(String::as_str).filter(|s| !s.is_empty()).with_context(|| format!("--{key} is required"))
}

async fn run(args: Vec<String>) -> anyhow::Result<()> {
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    match words.as_slice() {
        [] | ["serve"] => serve().await,
        ["migrate"] => migrate().await,
        ["tenant", "create", rest @ ..] => tenant_create(&parse_flags(&to_owned(rest))?).await,
        ["tenant", "add-domain", rest @ ..] => tenant_add_domain(&parse_flags(&to_owned(rest))?).await,
        ["idp", "add", rest @ ..] => idp_add(&parse_flags(&to_owned(rest))?).await,
        ["keys", "rewrap"] => keys_rewrap().await,
        ["audit", "verify", rest @ ..] => audit_verify(&parse_flags(&to_owned(rest))?).await,
        ["help"] | ["--help"] | ["-h"] => {
            print!("{HELP}");
            Ok(())
        }
        _ => bail!("unknown command; run `bp-ent-api --help`"),
    }
}

fn to_owned(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

async fn admin_pool() -> anyhow::Result<sqlx::PgPool> {
    let url = std::env::var("DATABASE_ADMIN_URL").context("DATABASE_ADMIN_URL is not set (the schema owner connection)")?;
    Ok(sqlx::postgres::PgPoolOptions::new().max_connections(2).connect(&url).await?)
}

async fn migrate() -> anyhow::Result<()> {
    let pool = admin_pool().await?;
    bp_ent_core::db::run_migrations(&pool, bp_ent_api::migrators()).await?;
    println!("migrations applied; every table has tenant_id + forced row-level security");
    if let Ok(pw) = std::env::var("BP_APP_DB_PASSWORD") {
        if !pw.is_empty() {
            bp_ent_core::db::set_app_role_password(&pool, &Secret::new(pw)).await?;
            println!("bp_app login password set");
        }
    }
    Ok(())
}

async fn tenant_create(f: &HashMap<String, Vec<String>>) -> anyhow::Result<()> {
    let (name, slug, email) = (one(f, "name")?, one(f, "slug")?, one(f, "admin-email")?);
    let email = bp_ent_api::routes::sso::normalize_email(email).map_err(|_| anyhow::anyhow!("invalid --admin-email"))?;
    let ctx = AppCtx::from_env().await?;
    let (tenant, mut tx) = bp_ent_core::db::create_tenant(&ctx.db, name, slug).await?;
    let user = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO users (id, tenant_id, email, role, status) VALUES ($1, $2, $3, 'org_admin', 'invited')")
        .bind(user)
        .bind(tenant.0)
        .bind(&email)
        .execute(&mut *tx)
        .await?;
    bp_ent_core::audit::append_system(&mut tx, tenant, "operator-cli", "user.invited", &format!("user:{user}"), serde_json::json!({ "role": "org_admin" })).await?;
    tx.commit().await?;
    println!("created organisation {slug} ({tenant}); {email} is invited as org admin");
    println!("next: bp-ent-api idp add --slug {slug} ... so they can sign in");
    Ok(())
}

async fn tenant_add_domain(f: &HashMap<String, Vec<String>>) -> anyhow::Result<()> {
    let (slug, domain) = (one(f, "slug")?, one(f, "domain")?.to_ascii_lowercase());
    let pool = admin_pool().await?;
    let n = sqlx::query("INSERT INTO tenant_directory (tenant_id, kind, value) SELECT id, 'domain', $2 FROM tenants WHERE slug = $1")
        .bind(slug)
        .bind(&domain)
        .execute(&pool)
        .await?
        .rows_affected();
    if n == 0 {
        bail!("no organisation with slug {slug}");
    }
    println!("{domain} now routes to {slug}");
    Ok(())
}

async fn idp_add(f: &HashMap<String, Vec<String>>) -> anyhow::Result<()> {
    use bp_ent_api::routes::admin::{validate_idp, IdpReq};
    let slug = one(f, "slug")?;
    let provider = one(f, "provider")?;
    let secret_env = one(f, "client-secret-env")?;
    let secret = std::env::var(secret_env).with_context(|| format!("environment variable {secret_env} is not set"))?;
    let req = IdpReq {
        provider: provider.to_string(),
        display_name: f.get("name").and_then(|v| v.first()).cloned().unwrap_or_else(|| provider.to_string()),
        enabled: true,
        issuer: f.get("issuer").and_then(|v| v.first()).cloned(),
        client_id: Some(one(f, "client-id")?.to_string()),
        client_secret: Some(Secret::new(secret)),
        directory_id: f.get("directory-id").and_then(|v| v.first()).cloned(),
        allowed_domains: f.get("domain").cloned().unwrap_or_default(),
        saml_entity_id: None,
        saml_sso_url: None,
        saml_cert_pem: None,
        auto_provision: f.contains_key("auto-provision"),
        default_role: None,
        trust_email: false,
    };
    let ctx = AppCtx::from_env().await?;
    let fields = validate_idp(&ctx.http, &req, false).map_err(|e| anyhow::anyhow!("{e}"))?;
    let tenant = ctx.db.tenant_by_slug(slug).await?.with_context(|| format!("no organisation with slug {slug}"))?;
    let id = uuid::Uuid::new_v4();
    let sealed = ctx.cipher.seal(tenant, &bp_ent_api::routes::sso::client_secret_aad(id), req.client_secret.as_ref().unwrap().expose().as_bytes()).await?;
    let mut tx = ctx.db.tenant_tx(tenant).await?;
    sqlx::query(
        "INSERT INTO identity_providers (id, tenant_id, kind, display_name, issuer, client_id, client_secret_enc, directory_id, allowed_domains, auto_provision, default_role) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
    )
    .bind(id)
    .bind(tenant.0)
    .bind(&fields.kind)
    .bind(&req.display_name)
    .bind(&fields.issuer)
    .bind(&fields.client_id)
    .bind(&sealed)
    .bind(&fields.directory_id)
    .bind(&fields.allowed_domains)
    .bind(req.auto_provision)
    .bind(fields.default_role.as_str())
    .execute(&mut *tx)
    .await?;
    bp_ent_core::audit::append_system(&mut tx, tenant, "operator-cli", "idp.created", &format!("idp:{id}"), serde_json::json!({ "provider": fields.kind, "issuer": fields.issuer })).await?;
    tx.commit().await?;
    println!("sign-in provider {id} added to {slug}");
    println!("register this redirect URI at the provider: {}", bp_ent_api::routes::sso::callback_url(&ctx));
    Ok(())
}

async fn keys_rewrap() -> anyhow::Result<()> {
    let ctx = AppCtx::from_env().await?;
    let mut total = 0;
    for tenant in ctx.db.all_tenants().await? {
        let n = ctx.cipher.rewrap(tenant).await.map_err(|e| anyhow::anyhow!("tenant {tenant}: {e}"))?;
        if n > 0 {
            let mut tx = ctx.db.tenant_tx(tenant).await?;
            bp_ent_core::audit::append_system(&mut tx, tenant, "operator-cli", "keys.rewrapped", "tenant_keys", serde_json::json!({ "versions": n })).await?;
            tx.commit().await?;
        }
        total += n;
    }
    println!("re-wrapped {total} data key version(s) under the current master key");
    Ok(())
}

async fn audit_verify(f: &HashMap<String, Vec<String>>) -> anyhow::Result<()> {
    let ctx = AppCtx::from_env().await?;
    let tenants = match f.get("slug").and_then(|v| v.first()) {
        Some(slug) => vec![ctx.db.tenant_by_slug(slug).await?.with_context(|| format!("no organisation with slug {slug}"))?],
        None => ctx.db.all_tenants().await?,
    };
    let mut broken = 0;
    for tenant in tenants {
        let mut tx = ctx.db.tenant_tx(tenant).await?;
        match bp_ent_core::audit::verify_chain(&mut tx, tenant).await {
            Ok(n) => println!("{tenant}: ok, {n} entries"),
            Err(e) => {
                broken += 1;
                println!("{tenant}: BROKEN: {e}");
            }
        }
    }
    if broken > 0 {
        bail!("{broken} audit chain(s) failed verification");
    }
    Ok(())
}

async fn serve() -> anyhow::Result<()> {
    init_tracing();
    let ctx = AppCtx::from_env().await?;
    let cfg = ApiConfig::from_env()?;
    let bind = cfg.bind;
    let st = ApiState::new(ctx.clone(), cfg);
    let mounts = mounts(&ctx).await?;
    bp_ent_api::jobs::spawn_purge(ctx.clone());

    let router = app(st, mounts);
    let listener = tokio::net::TcpListener::bind(bind).await.with_context(|| format!("cannot bind {bind}"))?;
    tracing::info!(%bind, origin = %ctx.config.public_origin, "bp-ent-api listening");
    axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(shutdown())
        .await?;
    Ok(())
}

async fn shutdown() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! { _ = ctrl_c => {}, _ = term => {} }
    tracing::info!("shutting down");
}

/// Build the feature crates' routers and start their background sweeps.
#[allow(unused_variables, unused_mut)]
async fn mounts(ctx: &AppCtx) -> anyhow::Result<Mounts> {
    use std::time::Duration;
    let mut m = Mounts::default();

    #[cfg(feature = "httplib")]
    m.routers.push(bp_ent_httplib::router(ctx.clone()));

    #[cfg(feature = "bridges")]
    m.routers.push(bp_ent_bridges::router(ctx.clone()));

    #[cfg(feature = "codev")]
    m.routers.push(bp_ent_codev::router(ctx.clone()));

    #[cfg(feature = "orders")]
    let orders = {
        let svc = bp_ent_orders::Svc::new(ctx.clone(), bp_ent_orders::OrdersConfig::from_env());
        m.routers.push(bp_ent_orders::routes::router(svc.clone()));
        let s = svc.clone();
        bp_ent_api::jobs::spawn_every("mail-sync", Duration::from_secs(300), move || {
            let s = s.clone();
            async move { bp_ent_orders::mailbox::sync_all(&s).await.map(|_| ()).map_err(|e| e.to_string()) }
        });
        let s = svc.clone();
        bp_ent_api::jobs::spawn_every("usage-flush", Duration::from_secs(600), move || {
            let s = s.clone();
            async move { bp_ent_orders::billing::flush_all_usage(&s).await.map(|_| ()).map_err(|e| e.to_string()) }
        });
        svc
    };

    #[cfg(feature = "relay")]
    if bp_ent_core::config::env_flag("BP_RELAY_DISABLED") {
        tracing::warn!("BP_RELAY_DISABLED=1: Boat VM routes are not mounted");
    } else {
        use bp_ent_relay::{MtlsRelayServer, RelayConfig, RelayState};
        let mut state = RelayState::from_ctx(ctx.clone()).context("Boat VM relay: set BP_BOAT_CA_CERT_FILE/KEY_FILE (or BP_RELAY_DISABLED=1 to run without Boat VMs)")?;
        state.config = RelayConfig {
            idle_timeout: Duration::from_secs(bp_ent_core::config::env_parse("BP_RELAY_IDLE_TIMEOUT_SECS", 900)?),
            ..RelayConfig::default()
        };
        // VM hours stop being "stored by the relay" and become billable here.
        #[cfg(feature = "orders")]
        {
            state.meter_sink = std::sync::Arc::new(StripeUsageSink { svc: orders.clone() });
        }
        let relay_router = bp_ent_relay::router_with_state(state.clone());

        // Boat VMs dial in over mutual TLS on their own port.
        let mtls_addr: SocketAddr = bp_ent_core::config::env_parse("BP_RELAY_MTLS_ADDR", SocketAddr::from(([0, 0, 0, 0], 8443)))?;
        let mtls_host = std::env::var("BP_RELAY_MTLS_HOST").unwrap_or_else(|_| "localhost".into());
        let server = MtlsRelayServer::new(&state.ca, &[mtls_host.as_str()], relay_router.clone())?;
        let listener = tokio::net::TcpListener::bind(mtls_addr).await.with_context(|| format!("cannot bind relay mTLS port {mtls_addr}"))?;
        tracing::info!(%mtls_addr, "Boat VM mTLS relay listening");
        tokio::spawn(async move {
            if let Err(e) = server.serve(listener).await {
                tracing::error!(error = %e, "Boat VM mTLS relay stopped");
            }
        });

        let reaper = state.clone();
        bp_ent_api::jobs::spawn_every("idle-vm-reaper", Duration::from_secs(60), move || {
            let r = reaper.clone();
            async move { bp_ent_relay::reap_idle_vms(&r.ctx.db, &r.provisioner, &r.meter_sink, r.config.idle_timeout).await.map(|_| ()).map_err(|e| e.to_string()) }
        });
        m.routers.push(relay_router);
    }

    Ok(m)
}

/// Feeds the relay's VM run records into the billing ledger (which reports
/// them to Stripe idempotently).
#[cfg(all(feature = "relay", feature = "orders"))]
struct StripeUsageSink {
    svc: bp_ent_orders::Svc,
}

#[cfg(all(feature = "relay", feature = "orders"))]
#[async_trait::async_trait]
impl bp_ent_relay::UsageMeterSink for StripeUsageSink {
    async fn record_usage(&self, u: &bp_ent_relay::UsageRecord) -> bp_ent_core::Result<()> {
        let usage = bp_ent_orders::billing::VmUsage {
            vm_id: u.vm_id,
            started_at: u.started_at,
            stopped_at: u.stopped_at,
            idempotency_key: u.idempotency_key.clone(),
        };
        bp_ent_orders::billing::record_vm_usage_for(&self.svc, u.tenant_id, &usage).await.map(|_| ())
    }
}
