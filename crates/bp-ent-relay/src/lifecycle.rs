//! Boat VM lifecycle management, idle auto-stop, wake-on-connect, and
//! compute-hour metering (`UsageRecord` for Stripe billing).

use async_trait::async_trait;
use bp_ent_core::{audit, Db, Error, Result, TenantId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::sync::Arc;
use time::OffsetDateTime;
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VmState {
    Provisioning,
    Running,
    Stopping,
    Stopped,
    Terminated,
}

impl VmState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Provisioning => "provisioning",
            Self::Running => "running",
            Self::Stopping => "stopping",
            Self::Stopped => "stopped",
            Self::Terminated => "terminated",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "provisioning" => Ok(Self::Provisioning),
            "running" => Ok(Self::Running),
            "stopping" => Ok(Self::Stopping),
            "stopped" => Ok(Self::Stopped),
            "terminated" => Ok(Self::Terminated),
            _ => Err(Error::invalid("unknown boat vm state")),
        }
    }
}

/// Usage interval emitted when a Boat VM stops (or is reaped for inactivity).
/// Matches the contract coordinated with `bp-ent-orders` for Stripe metering.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageRecord {
    pub id: Uuid,
    pub tenant_id: TenantId,
    pub vm_id: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    pub started_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub stopped_at: OffsetDateTime,
    pub duration_seconds: i64,
    pub idempotency_key: String,
}

impl UsageRecord {
    /// Build a deterministic idempotency key from `(tenant_id, vm_id, started_at, stopped_at)`
    /// so retries never double-bill Stripe.
    pub fn new(
        tenant_id: TenantId,
        vm_id: Uuid,
        started_at: OffsetDateTime,
        stopped_at: OffsetDateTime,
    ) -> Result<Self> {
        let duration_seconds = (stopped_at - started_at).whole_seconds().max(0);
        let mut h = Sha256::new();
        h.update(b"bpe-vm-usage-v1:");
        h.update(tenant_id.0.as_bytes());
        h.update(vm_id.as_bytes());
        h.update(started_at.unix_timestamp_nanos().to_be_bytes());
        h.update(stopped_at.unix_timestamp_nanos().to_be_bytes());
        let idempotency_key = format!("vm_usage_{}", hex::encode(h.finalize()));
        Ok(Self {
            id: Uuid::new_v4(),
            tenant_id,
            vm_id,
            started_at,
            stopped_at,
            duration_seconds,
            idempotency_key,
        })
    }
}

#[async_trait]
pub trait UsageMeterSink: Send + Sync {
    async fn record_usage(&self, usage: &UsageRecord) -> Result<()>;
}

#[derive(Default)]
pub struct NoopUsageMeterSink;

#[async_trait]
impl UsageMeterSink for NoopUsageMeterSink {
    async fn record_usage(&self, _usage: &UsageRecord) -> Result<()> {
        Ok(())
    }
}

#[derive(Default)]
pub struct InMemoryUsageMeterSink {
    pub records: Mutex<Vec<UsageRecord>>,
}

#[async_trait]
impl UsageMeterSink for InMemoryUsageMeterSink {
    async fn record_usage(&self, usage: &UsageRecord) -> Result<()> {
        let mut guard = self.records.lock().await;
        if !guard
            .iter()
            .any(|r| r.idempotency_key == usage.idempotency_key)
        {
            guard.push(usage.clone());
        }
        Ok(())
    }
}

#[async_trait]
pub trait VmProvisioner: Send + Sync {
    async fn start_vm(&self, tenant_id: TenantId, vm_id: Uuid) -> Result<()>;
    async fn stop_vm(&self, tenant_id: TenantId, vm_id: Uuid) -> Result<()>;
    async fn terminate_vm(&self, tenant_id: TenantId, vm_id: Uuid) -> Result<()>;
}

#[derive(Default)]
pub struct LocalMockProvisioner {
    pub actions: Mutex<Vec<(TenantId, Uuid, &'static str)>>,
}

#[async_trait]
impl VmProvisioner for LocalMockProvisioner {
    async fn start_vm(&self, tenant_id: TenantId, vm_id: Uuid) -> Result<()> {
        self.actions.lock().await.push((tenant_id, vm_id, "start"));
        Ok(())
    }

    async fn stop_vm(&self, tenant_id: TenantId, vm_id: Uuid) -> Result<()> {
        self.actions.lock().await.push((tenant_id, vm_id, "stop"));
        Ok(())
    }

    async fn terminate_vm(&self, tenant_id: TenantId, vm_id: Uuid) -> Result<()> {
        self.actions
            .lock()
            .await
            .push((tenant_id, vm_id, "terminate"));
        Ok(())
    }
}

/// Persist a usage record inside the caller's tenant-scoped transaction and
/// emit it to the configured `UsageMeterSink`.
pub async fn record_usage_in_tx(
    tx: &mut bp_ent_core::Tx,
    sink: &dyn UsageMeterSink,
    usage: &UsageRecord,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO boat_vm_usage_records \
         (id, tenant_id, vm_id, started_at, stopped_at, duration_seconds, idempotency_key) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         ON CONFLICT (tenant_id, idempotency_key) DO NOTHING",
    )
    .bind(usage.id)
    .bind(usage.tenant_id.0)
    .bind(usage.vm_id)
    .bind(usage.started_at)
    .bind(usage.stopped_at)
    .bind(usage.duration_seconds)
    .bind(&usage.idempotency_key)
    .execute(&mut **tx)
    .await?;

    sink.record_usage(usage).await?;
    Ok(())
}

/// Background reaper sweep: stops running Boat VMs whose `last_active_at` is
/// older than `idle_timeout`, emits `UsageRecord`s, and appends audit events.
pub async fn reap_idle_vms(
    db: &Db,
    provisioner: &Arc<dyn VmProvisioner>,
    sink: &Arc<dyn UsageMeterSink>,
    idle_timeout: std::time::Duration,
) -> Result<u64> {
    let tenants = db.all_tenants().await?;
    let cutoff =
        OffsetDateTime::now_utc() - time::Duration::seconds(idle_timeout.as_secs() as i64);
    let mut stopped_count = 0u64;

    for tenant in tenants {
        let mut tx = db.tenant_tx(tenant).await?;
        let rows = sqlx::query(
            "SELECT id, started_at FROM boat_vms \
             WHERE tenant_id = $1 AND state = 'running' AND last_active_at < $2 \
             FOR UPDATE",
        )
        .bind(tenant.0)
        .bind(cutoff)
        .fetch_all(&mut *tx)
        .await?;

        for row in rows {
            let vm_id: Uuid = row.get("id");
            let started_at: Option<OffsetDateTime> = row.get("started_at");
            let now = OffsetDateTime::now_utc();

            provisioner.stop_vm(tenant, vm_id).await?;
            sqlx::query(
                "UPDATE boat_vms SET state = 'stopped', started_at = NULL, stopped_at = $3 \
                 WHERE tenant_id = $1 AND id = $2",
            )
            .bind(tenant.0)
            .bind(vm_id)
            .bind(now)
            .execute(&mut *tx)
            .await?;

            if let Some(start) = started_at {
                let usage = UsageRecord::new(tenant, vm_id, start, now)?;
                record_usage_in_tx(&mut tx, sink.as_ref(), &usage).await?;
            }

            audit::append_system(
                &mut tx,
                tenant,
                "relay-reaper",
                "boat_vm.idle_stopped",
                &format!("vm:{vm_id}"),
                serde_json::json!({ "idle_timeout_secs": idle_timeout.as_secs() }),
            )
            .await?;

            stopped_count += 1;
        }

        tx.commit().await?;
    }

    Ok(stopped_count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn usage_record_idempotency_is_deterministic() {
        let t = TenantId::new();
        let vm = Uuid::new_v4();
        let s = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let e = s + time::Duration::minutes(45);
        let u1 = UsageRecord::new(t, vm, s, e).unwrap();
        let u2 = UsageRecord::new(t, vm, s, e).unwrap();
        assert_eq!(u1.duration_seconds, 2700);
        assert_eq!(u1.idempotency_key, u2.idempotency_key);

        let sink = InMemoryUsageMeterSink::default();
        sink.record_usage(&u1).await.unwrap();
        sink.record_usage(&u2).await.unwrap();
        assert_eq!(sink.records.lock().await.len(), 1);
    }
}
