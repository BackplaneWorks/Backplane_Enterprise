//! Background housekeeping run by the server process.

use bp_ent_core::AppCtx;
use std::time::Duration;

/// Delete expired logins, one-time codes and long-dead credentials for every
/// tenant, hourly.
pub fn spawn_purge(ctx: AppCtx) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(3600));
        loop {
            tick.tick().await;
            if let Err(e) = purge_once(&ctx).await {
                tracing::warn!(error = %e, "purge failed");
            }
        }
    });
}

pub async fn purge_once(ctx: &AppCtx) -> bp_ent_core::Result<u64> {
    let mut n = 0;
    for tenant in ctx.db.all_tenants().await? {
        let mut tx = ctx.db.tenant_tx(tenant).await?;
        n += sqlx::query("DELETE FROM login_states WHERE tenant_id = $1 AND expires_at < now()").bind(tenant.0).execute(&mut *tx).await?.rows_affected();
        n += sqlx::query("DELETE FROM desktop_codes WHERE tenant_id = $1 AND expires_at < now()").bind(tenant.0).execute(&mut *tx).await?.rows_affected();
        n += bp_ent_core::auth::purge_expired(&mut tx, tenant).await?;
        tx.commit().await?;
    }
    Ok(n)
}

/// Run `f` every `every`, logging failures. For the feature crates' sweeps.
pub fn spawn_every<F, Fut>(name: &'static str, every: Duration, f: F)
where
    F: Fn() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<(), String>> + Send,
{
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(every);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            if let Err(e) = f().await {
                tracing::warn!(job = name, error = %e, "background job failed");
            }
        }
    });
}
