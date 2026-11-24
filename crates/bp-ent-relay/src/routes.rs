//! Axum HTTP & WebSocket routes for Boat VM management and the Zero-Tailscale
//! mTLS/WSS relay.

use crate::ca::{BoatCa, VerifiedBoatIdentity, MAX_DEVICE_CERT_TTL_SECS};
use crate::lifecycle::{
    record_usage_in_tx, LocalMockProvisioner, NoopUsageMeterSink, UsageMeterSink, UsageRecord,
    VmProvisioner, VmState,
};
use crate::protocol::{RelayChannel, RelayFrame, MAX_WS_MESSAGE_BYTES};
use crate::registry::TunnelRegistry;
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Path, State, WebSocketUpgrade};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use bp_ent_core::crypto::{ct_eq, random_token, sha256};
use bp_ent_core::{audit, AppCtx, Error, Permission, Principal, Result, TenantId};
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::sync::Arc;
use std::time::{Duration, Instant};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

const RECHECK_INTERVAL: Duration = Duration::from_secs(60);
const ACTIVITY_TOUCH_THROTTLE: Duration = Duration::from_secs(60);
const ENROLL_TOKEN_TTL_SECS: i64 = 15 * 60;

#[derive(Clone)]
pub struct RelayConfig {
    pub idle_timeout: Duration,
    pub wake_timeout: Duration,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            idle_timeout: Duration::from_secs(900),
            wake_timeout: Duration::from_secs(30),
        }
    }
}

#[derive(Clone)]
pub struct RelayState {
    pub ctx: AppCtx,
    pub ca: Arc<BoatCa>,
    pub registry: TunnelRegistry,
    pub provisioner: Arc<dyn VmProvisioner>,
    pub meter_sink: Arc<dyn UsageMeterSink>,
    pub config: RelayConfig,
}

impl RelayState {
    /// Load `BoatCa` strictly from environment (`BP_BOAT_CA_CERT_FILE`/`KEY_FILE`,
    /// or `BP_BOAT_CA_CERT_PEM`/`KEY_PEM`, or `BP_BOAT_CA_EPHEMERAL=1` for dev).
    pub fn from_ctx(ctx: AppCtx) -> anyhow::Result<Self> {
        let ca = Arc::new(BoatCa::from_env()?);
        Ok(Self::with_ca(ctx, ca))
    }

    pub fn with_ca(ctx: AppCtx, ca: Arc<BoatCa>) -> Self {
        Self {
            ctx,
            ca,
            registry: TunnelRegistry::new(),
            provisioner: Arc::new(LocalMockProvisioner::default()),
            meter_sink: Arc::new(NoopUsageMeterSink),
            config: RelayConfig::default(),
        }
    }
}

/// Migrations owned by `bp-ent-relay` (`0200-0299`).
pub fn migrator() -> sqlx::migrate::Migrator {
    sqlx::migrate!("./migrations")
}

/// Mountable router for `bp-ent-api` (`ctx` state applied internally).
pub fn router(ctx: AppCtx) -> Router {
    let state = RelayState::from_ctx(ctx)
        .expect("Boat CA configuration missing (set BP_BOAT_CA_CERT_FILE/KEY_FILE or BP_BOAT_CA_EPHEMERAL=1)");
    router_with_state(state)
}

/// Mountable router with explicit `RelayState` (e.g. custom `BoatCa`, `VmProvisioner`, `UsageMeterSink`).
pub fn router_with_state(state: RelayState) -> Router {
    let user_authed = bp_ent_core::http::with_auth(
        Router::new()
            .route("/v1/vms", get(list_vms).post(create_vm))
            .route("/v1/vms/usage", get(list_usage))
            .route("/v1/vms/{id}", get(get_vm).delete(delete_vm))
            .route("/v1/vms/{id}/wake", post(wake_vm))
            .route("/v1/vms/{id}/start", post(wake_vm))
            .route("/v1/vms/{id}/stop", post(stop_vm))
            .route("/v1/vms/{id}/cert", post(issue_vm_cert))
            .route("/v1/vms/{id}/cert/revoke", post(revoke_vm_certs))
            .route("/v1/vms/{id}/enroll", post(mint_enrollment_token))
            .route("/v1/relay/desktop/connect/{vm_id}", get(desktop_ws_connect))
            .with_state(state.clone()),
        &state.ctx,
    );

    let boat_mtls = Router::new()
        .route("/v1/relay/boat/connect", get(boat_ws_connect))
        .route("/v1/relay/boat/renew", post(boat_csr_renew))
        .route("/v1/relay/boat/enroll", post(boat_csr_enroll))
        .route("/v1/relay/health", get(health))
        .with_state(state);

    Router::new().merge(user_authed).merge(boat_mtls)
}

// ------------------------------------------------------------------- DTOs

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BoatVmDto {
    pub id: Uuid,
    pub name: String,
    pub assigned_user_id: Option<Uuid>,
    pub assigned_user_email: String,
    pub region: String,
    pub kicad_version: String,
    pub state: VmState,
    pub tunnel_state: &'static str,
    pub cert_expires_at: String,
    pub idle_minutes: i64,
    pub metered_hours_month: f64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateVmRequest {
    pub name: String,
    pub assigned_user_id: Option<Uuid>,
    pub region: Option<String>,
    pub kicad_version: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueCertRequest {
    pub ttl_secs: Option<u64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueCertResponse {
    pub serial_hex: String,
    pub spiffe_uri: String,
    pub cert_pem: String,
    pub key_pem: String,
    pub ca_cert_pem: String,
    pub expires_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CsrRenewRequest {
    pub csr_pem: String,
    pub ttl_secs: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CsrEnrollRequest {
    pub enrollment_token: String,
    pub csr_pem: String,
    pub ttl_secs: Option<u64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedCertResponse {
    pub serial_hex: String,
    pub spiffe_uri: String,
    pub cert_pem: String,
    pub ca_cert_pem: String,
    pub expires_at: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollmentTokenResponse {
    pub enrollment_token: String,
    pub expires_at: String,
}

// ---------------------------------------------------------------- Helpers

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok", "service": "bp-ent-relay" }))
}

fn fmt_rfc3339(ts: OffsetDateTime) -> String {
    ts.format(&Rfc3339).unwrap_or_default()
}

async fn load_vm_dto(
    tx: &mut bp_ent_core::Tx,
    registry: &TunnelRegistry,
    tenant_id: TenantId,
    vm_id: Uuid,
) -> Result<BoatVmDto> {
    let row = sqlx::query(
        "SELECT v.id, v.name, v.assigned_user_id, COALESCE(u.email, '') AS assigned_email, \
                v.region, v.kicad_version, v.state, v.last_active_at, \
                (SELECT max(c.expires_at) FROM boat_device_certs c \
                  WHERE c.tenant_id = v.tenant_id AND c.vm_id = v.id AND c.revoked_at IS NULL) AS cert_exp, \
                COALESCE((SELECT sum(r.duration_seconds) FROM boat_vm_usage_records r \
                  WHERE r.tenant_id = v.tenant_id AND r.vm_id = v.id \
                    AND r.created_at >= date_trunc('month', now())), 0)::bigint AS sec_month \
         FROM boat_vms v \
         LEFT JOIN users u ON u.tenant_id = v.tenant_id AND u.id = v.assigned_user_id \
         WHERE v.tenant_id = $1 AND v.id = $2",
    )
    .bind(tenant_id.0)
    .bind(vm_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(Error::NotFound)?;

    row_to_dto(registry, tenant_id, &row).await
}

async fn row_to_dto(
    registry: &TunnelRegistry,
    tenant_id: TenantId,
    row: &sqlx::postgres::PgRow,
) -> Result<BoatVmDto> {
    let id: Uuid = row.get("id");
    let state_str: String = row.get("state");
    let state = VmState::parse(&state_str)?;
    let connected = registry.is_connected(tenant_id, id).await;
    let tunnel_state = if connected {
        "connected_mtls"
    } else if matches!(state, VmState::Provisioning | VmState::Running) {
        "waking"
    } else {
        "stopped"
    };
    let last_active: OffsetDateTime = row.get("last_active_at");
    let idle_minutes = ((OffsetDateTime::now_utc() - last_active).whole_minutes()).max(0);
    let cert_exp: Option<OffsetDateTime> = row.get("cert_exp");
    let sec_month: i64 = row.get("sec_month");

    Ok(BoatVmDto {
        id,
        name: row.get("name"),
        assigned_user_id: row.get("assigned_user_id"),
        assigned_user_email: row.get("assigned_email"),
        region: row.get("region"),
        kicad_version: row.get("kicad_version"),
        state,
        tunnel_state,
        cert_expires_at: cert_exp.map(fmt_rfc3339).unwrap_or_default(),
        idle_minutes,
        metered_hours_month: (sec_month as f64) / 3600.0,
    })
}

fn check_vm_access(principal: &Principal, assigned_user_id: Option<Uuid>) -> Result<()> {
    if principal.can(Permission::VmManage) {
        return Ok(());
    }
    principal.require(Permission::VmUse)?;
    if assigned_user_id == Some(principal.user_id.0) {
        Ok(())
    } else {
        Err(Error::NotFound)
    }
}

fn parse_enrollment_token(token: &str) -> Option<TenantId> {
    let mut parts = token.split('_');
    if parts.next()? != "bpe" || parts.next()? != "enroll" {
        return None;
    }
    let tenant_hex = parts.next()?;
    let secret = parts.next()?;
    let rest_ok = secret.len() + parts.map(|p| p.len() + 1).sum::<usize>() >= 32;
    if tenant_hex.len() != 32 || !rest_ok || token.len() > 200 {
        return None;
    }
    Some(TenantId(Uuid::try_parse(tenant_hex).ok()?))
}

async fn touch_vm_activity(ctx: &AppCtx, tenant_id: TenantId, vm_id: Uuid) {
    if let Ok(mut tx) = ctx.db.tenant_tx(tenant_id).await {
        let _ = sqlx::query(
            "UPDATE boat_vms SET last_active_at = now() WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id.0)
        .bind(vm_id)
        .execute(&mut *tx)
        .await;
        let _ = tx.commit().await;
    }
}

// ------------------------------------------------------------ VM Handlers

async fn list_vms(
    State(state): State<RelayState>,
    principal: Principal,
) -> Result<Json<Vec<BoatVmDto>>> {
    let is_mgr = principal.can(Permission::VmManage);
    if !is_mgr {
        principal.require(Permission::VmUse)?;
    }
    let mut tx = state.ctx.db.tenant_tx(principal.tenant_id).await?;
    let rows = if is_mgr {
        sqlx::query(
            "SELECT v.id, v.name, v.assigned_user_id, COALESCE(u.email, '') AS assigned_email, \
                    v.region, v.kicad_version, v.state, v.last_active_at, \
                    (SELECT max(c.expires_at) FROM boat_device_certs c \
                      WHERE c.tenant_id = v.tenant_id AND c.vm_id = v.id AND c.revoked_at IS NULL) AS cert_exp, \
                    COALESCE((SELECT sum(r.duration_seconds) FROM boat_vm_usage_records r \
                      WHERE r.tenant_id = v.tenant_id AND r.vm_id = v.id \
                        AND r.created_at >= date_trunc('month', now())), 0)::bigint AS sec_month \
             FROM boat_vms v \
             LEFT JOIN users u ON u.tenant_id = v.tenant_id AND u.id = v.assigned_user_id \
             WHERE v.tenant_id = $1 AND v.state <> 'terminated' \
             ORDER BY v.created_at DESC",
        )
        .bind(principal.tenant_id.0)
        .fetch_all(&mut *tx)
        .await?
    } else {
        sqlx::query(
            "SELECT v.id, v.name, v.assigned_user_id, COALESCE(u.email, '') AS assigned_email, \
                    v.region, v.kicad_version, v.state, v.last_active_at, \
                    (SELECT max(c.expires_at) FROM boat_device_certs c \
                      WHERE c.tenant_id = v.tenant_id AND c.vm_id = v.id AND c.revoked_at IS NULL) AS cert_exp, \
                    COALESCE((SELECT sum(r.duration_seconds) FROM boat_vm_usage_records r \
                      WHERE r.tenant_id = v.tenant_id AND r.vm_id = v.id \
                        AND r.created_at >= date_trunc('month', now())), 0)::bigint AS sec_month \
             FROM boat_vms v \
             LEFT JOIN users u ON u.tenant_id = v.tenant_id AND u.id = v.assigned_user_id \
             WHERE v.tenant_id = $1 AND v.assigned_user_id = $2 AND v.state <> 'terminated' \
             ORDER BY v.created_at DESC",
        )
        .bind(principal.tenant_id.0)
        .bind(principal.user_id.0)
        .fetch_all(&mut *tx)
        .await?
    };

    let mut out = Vec::with_capacity(rows.len());
    for row in &rows {
        out.push(row_to_dto(&state.registry, principal.tenant_id, row).await?);
    }
    tx.commit().await?;
    Ok(Json(out))
}

async fn create_vm(
    State(state): State<RelayState>,
    principal: Principal,
    Json(req): Json<CreateVmRequest>,
) -> Result<Json<BoatVmDto>> {
    principal.require(Permission::VmManage)?;
    let name = req.name.trim();
    if name.is_empty() || name.len() > 120 {
        return Err(Error::invalid("vm name must be 1..=120 chars"));
    }

    let vm_id = Uuid::new_v4();
    let region = req.region.unwrap_or_else(|| "us-east-1".into());
    let kicad_version = req.kicad_version.unwrap_or_else(|| "10.99.0-bp.13.5".into());

    let mut tx = state.ctx.db.tenant_tx(principal.tenant_id).await?;
    sqlx::query(
        "INSERT INTO boat_vms (id, tenant_id, name, assigned_user_id, region, kicad_version, state) \
         VALUES ($1, $2, $3, $4, $5, $6, 'stopped')",
    )
    .bind(vm_id)
    .bind(principal.tenant_id.0)
    .bind(name)
    .bind(req.assigned_user_id)
    .bind(&region)
    .bind(&kicad_version)
    .execute(&mut *tx)
    .await?;

    audit::append(
        &mut tx,
        &principal,
        "boat_vm.created",
        &format!("vm:{vm_id}"),
        serde_json::json!({ "region": region, "kicad_version": kicad_version }),
    )
    .await?;

    let dto = load_vm_dto(&mut tx, &state.registry, principal.tenant_id, vm_id).await?;
    tx.commit().await?;
    Ok(Json(dto))
}

async fn get_vm(
    State(state): State<RelayState>,
    principal: Principal,
    Path(vm_id): Path<Uuid>,
) -> Result<Json<BoatVmDto>> {
    let mut tx = state.ctx.db.tenant_tx(principal.tenant_id).await?;
    let dto = load_vm_dto(&mut tx, &state.registry, principal.tenant_id, vm_id).await?;
    check_vm_access(&principal, dto.assigned_user_id)?;
    tx.commit().await?;
    Ok(Json(dto))
}

async fn wake_vm(
    State(state): State<RelayState>,
    principal: Principal,
    Path(vm_id): Path<Uuid>,
) -> Result<Json<BoatVmDto>> {
    let mut tx = state.ctx.db.tenant_tx(principal.tenant_id).await?;
    let row = sqlx::query(
        "SELECT assigned_user_id, state FROM boat_vms WHERE tenant_id = $1 AND id = $2 FOR UPDATE",
    )
    .bind(principal.tenant_id.0)
    .bind(vm_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(Error::NotFound)?;

    let assigned: Option<Uuid> = row.get("assigned_user_id");
    check_vm_access(&principal, assigned)?;
    let cur = VmState::parse(&row.get::<String, _>("state"))?;
    if cur == VmState::Terminated {
        return Err(Error::conflict("boat vm has been terminated"));
    }

    let now = OffsetDateTime::now_utc();
    if cur != VmState::Running {
        state.provisioner.start_vm(principal.tenant_id, vm_id).await?;
        // Always set started_at = $3 on start (never COALESCE), so stopped time is never billed.
        sqlx::query(
            "UPDATE boat_vms SET state = 'running', started_at = $3, stopped_at = NULL, last_active_at = $3 \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(principal.tenant_id.0)
        .bind(vm_id)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        audit::append(
            &mut tx,
            &principal,
            "boat_vm.started",
            &format!("vm:{vm_id}"),
            serde_json::json!({}),
        )
        .await?;
    }

    let dto = load_vm_dto(&mut tx, &state.registry, principal.tenant_id, vm_id).await?;
    tx.commit().await?;
    Ok(Json(dto))
}

async fn stop_vm(
    State(state): State<RelayState>,
    principal: Principal,
    Path(vm_id): Path<Uuid>,
) -> Result<Json<BoatVmDto>> {
    let mut tx = state.ctx.db.tenant_tx(principal.tenant_id).await?;
    let row = sqlx::query(
        "SELECT assigned_user_id, state, started_at FROM boat_vms \
         WHERE tenant_id = $1 AND id = $2 FOR UPDATE",
    )
    .bind(principal.tenant_id.0)
    .bind(vm_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(Error::NotFound)?;

    let assigned: Option<Uuid> = row.get("assigned_user_id");
    check_vm_access(&principal, assigned)?;
    let started_at: Option<OffsetDateTime> = row.get("started_at");
    let now = OffsetDateTime::now_utc();

    state.provisioner.stop_vm(principal.tenant_id, vm_id).await?;
    // Clear started_at = NULL on stop so the next start begins a fresh billing interval.
    sqlx::query(
        "UPDATE boat_vms SET state = 'stopped', started_at = NULL, stopped_at = $3 \
         WHERE tenant_id = $1 AND id = $2",
    )
    .bind(principal.tenant_id.0)
    .bind(vm_id)
    .bind(now)
    .execute(&mut *tx)
    .await?;

    if let Some(start) = started_at {
        let usage = UsageRecord::new(principal.tenant_id, vm_id, start, now)?;
        record_usage_in_tx(&mut tx, state.meter_sink.as_ref(), &usage).await?;
    }

    audit::append(
        &mut tx,
        &principal,
        "boat_vm.stopped",
        &format!("vm:{vm_id}"),
        serde_json::json!({}),
    )
    .await?;

    let dto = load_vm_dto(&mut tx, &state.registry, principal.tenant_id, vm_id).await?;
    tx.commit().await?;

    state
        .registry
        .force_disconnect_vm(principal.tenant_id, vm_id)
        .await;
    Ok(Json(dto))
}

async fn delete_vm(
    State(state): State<RelayState>,
    principal: Principal,
    Path(vm_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    principal.require(Permission::VmManage)?;
    let mut tx = state.ctx.db.tenant_tx(principal.tenant_id).await?;

    let row = sqlx::query(
        "SELECT started_at FROM boat_vms WHERE tenant_id = $1 AND id = $2 FOR UPDATE",
    )
    .bind(principal.tenant_id.0)
    .bind(vm_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(Error::NotFound)?;

    let started_at: Option<OffsetDateTime> = row.get("started_at");
    let now = OffsetDateTime::now_utc();
    if let Some(start) = started_at {
        let usage = UsageRecord::new(principal.tenant_id, vm_id, start, now)?;
        record_usage_in_tx(&mut tx, state.meter_sink.as_ref(), &usage).await?;
    }

    state.provisioner.terminate_vm(principal.tenant_id, vm_id).await?;
    sqlx::query(
        "UPDATE boat_vms SET state = 'terminated', started_at = NULL, stopped_at = $3 \
         WHERE tenant_id = $1 AND id = $2",
    )
    .bind(principal.tenant_id.0)
    .bind(vm_id)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE boat_device_certs SET revoked_at = now() \
         WHERE tenant_id = $1 AND vm_id = $2 AND revoked_at IS NULL",
    )
    .bind(principal.tenant_id.0)
    .bind(vm_id)
    .execute(&mut *tx)
    .await?;

    audit::append(
        &mut tx,
        &principal,
        "boat_vm.terminated",
        &format!("vm:{vm_id}"),
        serde_json::json!({}),
    )
    .await?;

    tx.commit().await?;
    state
        .registry
        .force_disconnect_vm(principal.tenant_id, vm_id)
        .await;

    Ok(Json(serde_json::json!({ "deleted": true, "id": vm_id })))
}

async fn issue_vm_cert(
    State(state): State<RelayState>,
    principal: Principal,
    Path(vm_id): Path<Uuid>,
    Json(req): Json<IssueCertRequest>,
) -> Result<Json<IssueCertResponse>> {
    principal.require(Permission::VmManage)?;
    let ttl_secs = req.ttl_secs.unwrap_or(MAX_DEVICE_CERT_TTL_SECS);

    let mut tx = state.ctx.db.tenant_tx(principal.tenant_id).await?;
    let exists: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM boat_vms WHERE tenant_id = $1 AND id = $2")
            .bind(principal.tenant_id.0)
            .bind(vm_id)
            .fetch_optional(&mut *tx)
            .await?;
    if exists.is_none() {
        return Err(Error::NotFound);
    }

    let issued = state
        .ca
        .issue_device_cert(principal.tenant_id, vm_id, Duration::from_secs(ttl_secs))?;

    sqlx::query(
        "INSERT INTO boat_device_certs (serial_hex, tenant_id, vm_id, spiffe_uri, issued_at, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(&issued.serial_hex)
    .bind(principal.tenant_id.0)
    .bind(vm_id)
    .bind(&issued.spiffe_uri)
    .bind(issued.issued_at)
    .bind(issued.expires_at)
    .execute(&mut *tx)
    .await?;

    audit::append(
        &mut tx,
        &principal,
        "boat_vm.cert_issued",
        &format!("vm:{vm_id}"),
        serde_json::json!({ "serial_hex": issued.serial_hex }),
    )
    .await?;

    tx.commit().await?;

    Ok(Json(IssueCertResponse {
        serial_hex: issued.serial_hex,
        spiffe_uri: issued.spiffe_uri,
        cert_pem: issued.cert_pem,
        key_pem: issued.key_pem.expose().clone(),
        ca_cert_pem: issued.ca_cert_pem,
        expires_at: fmt_rfc3339(issued.expires_at),
    }))
}

async fn revoke_vm_certs(
    State(state): State<RelayState>,
    principal: Principal,
    Path(vm_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    principal.require(Permission::VmManage)?;
    let mut tx = state.ctx.db.tenant_tx(principal.tenant_id).await?;
    let res = sqlx::query(
        "UPDATE boat_device_certs SET revoked_at = now() \
         WHERE tenant_id = $1 AND vm_id = $2 AND revoked_at IS NULL",
    )
    .bind(principal.tenant_id.0)
    .bind(vm_id)
    .execute(&mut *tx)
    .await?;

    audit::append(
        &mut tx,
        &principal,
        "boat_vm.certs_revoked",
        &format!("vm:{vm_id}"),
        serde_json::json!({ "revoked_count": res.rows_affected() }),
    )
    .await?;
    tx.commit().await?;

    state
        .registry
        .force_disconnect_vm(principal.tenant_id, vm_id)
        .await;

    Ok(Json(serde_json::json!({ "revoked": res.rows_affected() })))
}

async fn mint_enrollment_token(
    State(state): State<RelayState>,
    principal: Principal,
    Path(vm_id): Path<Uuid>,
) -> Result<Json<EnrollmentTokenResponse>> {
    principal.require(Permission::VmManage)?;
    let mut tx = state.ctx.db.tenant_tx(principal.tenant_id).await?;
    let vm_state: Option<String> = sqlx::query_scalar(
        "SELECT state FROM boat_vms WHERE tenant_id = $1 AND id = $2",
    )
    .bind(principal.tenant_id.0)
    .bind(vm_id)
    .fetch_optional(&mut *tx)
    .await?;
    if vm_state.is_none() || vm_state.as_deref() == Some("terminated") {
        return Err(Error::NotFound);
    }

    let token = format!(
        "bpe_enroll_{}_{}",
        principal.tenant_id.0.simple(),
        random_token(32)
    );
    let expires_at = OffsetDateTime::now_utc() + time::Duration::seconds(ENROLL_TOKEN_TTL_SECS);
    sqlx::query(
        "INSERT INTO boat_enrollment_tokens (token_hash, tenant_id, vm_id, expires_at) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(sha256(token.as_bytes()).as_slice())
    .bind(principal.tenant_id.0)
    .bind(vm_id)
    .bind(expires_at)
    .execute(&mut *tx)
    .await?;

    audit::append(
        &mut tx,
        &principal,
        "boat_vm.enrollment_token_minted",
        &format!("vm:{vm_id}"),
        serde_json::json!({}),
    )
    .await?;
    tx.commit().await?;

    Ok(Json(EnrollmentTokenResponse {
        enrollment_token: token,
        expires_at: fmt_rfc3339(expires_at),
    }))
}

async fn list_usage(
    State(state): State<RelayState>,
    principal: Principal,
) -> Result<Json<Vec<UsageRecord>>> {
    if !principal.can(Permission::VmManage) {
        principal.require(Permission::BillingManage)?;
    }
    let mut tx = state.ctx.db.tenant_tx(principal.tenant_id).await?;
    let rows = sqlx::query(
        "SELECT id, vm_id, started_at, stopped_at, duration_seconds, idempotency_key \
         FROM boat_vm_usage_records WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 200",
    )
    .bind(principal.tenant_id.0)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;

    let records = rows
        .into_iter()
        .map(|r| UsageRecord {
            id: r.get("id"),
            tenant_id: principal.tenant_id,
            vm_id: r.get("vm_id"),
            started_at: r.get("started_at"),
            stopped_at: r.get("stopped_at"),
            duration_seconds: r.get("duration_seconds"),
            idempotency_key: r.get("idempotency_key"),
        })
        .collect();
    Ok(Json(records))
}

// -------------------------------------------- Boat CSR Enroll & Self-Renew

/// First-boot enrollment: VM generates its keypair locally and exchanges a
/// single-use enrollment token + CSR for its initial `<= 24h` device cert.
async fn boat_csr_enroll(
    State(state): State<RelayState>,
    Json(req): Json<CsrEnrollRequest>,
) -> Result<Json<SignedCertResponse>> {
    let tenant_id =
        parse_enrollment_token(&req.enrollment_token).ok_or(Error::Unauthorized)?;
    let hash = sha256(req.enrollment_token.as_bytes());
    let ttl_secs = req.ttl_secs.unwrap_or(MAX_DEVICE_CERT_TTL_SECS);

    let mut tx = state.ctx.db.tenant_tx(tenant_id).await?;
    let row = sqlx::query(
        "SELECT token_hash, vm_id FROM boat_enrollment_tokens \
         WHERE tenant_id = $1 AND token_hash = $2 AND used_at IS NULL AND expires_at > now() \
         FOR UPDATE",
    )
    .bind(tenant_id.0)
    .bind(hash.as_slice())
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(Error::Unauthorized)?;

    let stored_hash: Vec<u8> = row.get("token_hash");
    if !ct_eq(&stored_hash, &hash) {
        return Err(Error::Unauthorized);
    }
    let vm_id: Uuid = row.get("vm_id");

    let vm_state: Option<String> = sqlx::query_scalar(
        "SELECT state FROM boat_vms WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant_id.0)
    .bind(vm_id)
    .fetch_optional(&mut *tx)
    .await?;
    if vm_state.is_none() || vm_state.as_deref() == Some("terminated") {
        return Err(Error::Unauthorized);
    }

    sqlx::query(
        "UPDATE boat_enrollment_tokens SET used_at = now() WHERE tenant_id = $1 AND token_hash = $2",
    )
    .bind(tenant_id.0)
    .bind(hash.as_slice())
    .execute(&mut *tx)
    .await?;

    let signed = state.ca.sign_device_csr(
        &req.csr_pem,
        tenant_id,
        vm_id,
        Duration::from_secs(ttl_secs),
    )?;

    sqlx::query(
        "INSERT INTO boat_device_certs (serial_hex, tenant_id, vm_id, spiffe_uri, issued_at, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(&signed.serial_hex)
    .bind(tenant_id.0)
    .bind(vm_id)
    .bind(&signed.spiffe_uri)
    .bind(signed.issued_at)
    .bind(signed.expires_at)
    .execute(&mut *tx)
    .await?;

    audit::append_system(
        &mut tx,
        tenant_id,
        "boat-relay",
        "boat_vm.cert_enrolled",
        &format!("vm:{vm_id}"),
        serde_json::json!({ "serial_hex": signed.serial_hex }),
    )
    .await?;
    tx.commit().await?;

    Ok(Json(SignedCertResponse {
        serial_hex: signed.serial_hex,
        spiffe_uri: signed.spiffe_uri,
        cert_pem: signed.cert_pem,
        ca_cert_pem: signed.ca_cert_pem,
        expires_at: fmt_rfc3339(signed.expires_at),
    }))
}

/// mTLS self-renewal: Boat VM presents its current valid mTLS cert + a newly
/// generated CSR. Private key never leaves the VM.
async fn boat_csr_renew(
    State(state): State<RelayState>,
    identity: Option<Extension<VerifiedBoatIdentity>>,
    Json(req): Json<CsrRenewRequest>,
) -> Result<Json<SignedCertResponse>> {
    let Extension(identity) = identity.ok_or(Error::Unauthorized)?;
    let ttl_secs = req.ttl_secs.unwrap_or(MAX_DEVICE_CERT_TTL_SECS);

    let mut tx = state.ctx.db.tenant_tx(identity.tenant_id).await?;
    let vm_state: Option<String> = sqlx::query_scalar(
        "SELECT state FROM boat_vms WHERE tenant_id = $1 AND id = $2",
    )
    .bind(identity.tenant_id.0)
    .bind(identity.vm_id)
    .fetch_optional(&mut *tx)
    .await?;
    if !matches!(vm_state.as_deref(), Some("provisioning" | "running")) {
        return Err(Error::Forbidden);
    }

    let valid_cert: Option<bool> = sqlx::query_scalar(
        "SELECT revoked_at IS NULL AND expires_at > now() \
         FROM boat_device_certs WHERE tenant_id = $1 AND vm_id = $2 AND serial_hex = $3",
    )
    .bind(identity.tenant_id.0)
    .bind(identity.vm_id)
    .bind(&identity.serial_hex)
    .fetch_optional(&mut *tx)
    .await?;
    if valid_cert != Some(true) {
        return Err(Error::Unauthorized);
    }

    let signed = state.ca.sign_device_csr(
        &req.csr_pem,
        identity.tenant_id,
        identity.vm_id,
        Duration::from_secs(ttl_secs),
    )?;

    sqlx::query(
        "INSERT INTO boat_device_certs (serial_hex, tenant_id, vm_id, spiffe_uri, issued_at, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(&signed.serial_hex)
    .bind(identity.tenant_id.0)
    .bind(identity.vm_id)
    .bind(&signed.spiffe_uri)
    .bind(signed.issued_at)
    .bind(signed.expires_at)
    .execute(&mut *tx)
    .await?;

    audit::append_system(
        &mut tx,
        identity.tenant_id,
        "boat-relay",
        "boat_vm.cert_renewed",
        &format!("vm:{}", identity.vm_id),
        serde_json::json!({ "serial_hex": signed.serial_hex }),
    )
    .await?;
    tx.commit().await?;

    Ok(Json(SignedCertResponse {
        serial_hex: signed.serial_hex,
        spiffe_uri: signed.spiffe_uri,
        cert_pem: signed.cert_pem,
        ca_cert_pem: signed.ca_cert_pem,
        expires_at: fmt_rfc3339(signed.expires_at),
    }))
}

// ------------------------------------------------------ WebSocket Bridges

async fn desktop_ws_connect(
    State(state): State<RelayState>,
    principal: Principal,
    Path(vm_id): Path<Uuid>,
    ws: WebSocketUpgrade,
) -> Result<impl IntoResponse> {
    let mut tx = state.ctx.db.tenant_tx(principal.tenant_id).await?;
    let row = sqlx::query(
        "SELECT assigned_user_id, state FROM boat_vms WHERE tenant_id = $1 AND id = $2 FOR UPDATE",
    )
    .bind(principal.tenant_id.0)
    .bind(vm_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(Error::NotFound)?;

    let assigned: Option<Uuid> = row.get("assigned_user_id");
    check_vm_access(&principal, assigned)?;
    let vm_state = VmState::parse(&row.get::<String, _>("state"))?;
    if vm_state == VmState::Terminated {
        return Err(Error::NotFound);
    }

    let now = OffsetDateTime::now_utc();
    if vm_state != VmState::Running {
        state.provisioner.start_vm(principal.tenant_id, vm_id).await?;
        sqlx::query(
            "UPDATE boat_vms SET state = 'running', started_at = $3, stopped_at = NULL, last_active_at = $3 \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(principal.tenant_id.0)
        .bind(vm_id)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    } else {
        sqlx::query("UPDATE boat_vms SET last_active_at = $3 WHERE tenant_id = $1 AND id = $2")
            .bind(principal.tenant_id.0)
            .bind(vm_id)
            .bind(now)
            .execute(&mut *tx)
            .await?;
    }

    let session_id = Uuid::new_v4();
    let client_kind = match principal.auth {
        bp_ent_core::AuthKind::Session => "web",
        _ => "desktop",
    };
    sqlx::query(
        "INSERT INTO boat_relay_sessions (id, tenant_id, vm_id, user_id, client_kind) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(session_id)
    .bind(principal.tenant_id.0)
    .bind(vm_id)
    .bind(principal.user_id.0)
    .bind(client_kind)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(ws
        .max_message_size(MAX_WS_MESSAGE_BYTES)
        .max_frame_size(MAX_WS_MESSAGE_BYTES)
        .on_upgrade(move |socket| {
            handle_desktop_socket(state, principal, vm_id, session_id, socket)
        }))
}

async fn desktop_session_still_valid(state: &RelayState, principal: &Principal, vm_id: Uuid) -> bool {
    let Ok(mut tx) = state.ctx.db.tenant_tx(principal.tenant_id).await else {
        return false;
    };
    let tok_ok: Option<bool> = sqlx::query_scalar(
        "SELECT t.revoked_at IS NULL AND t.expires_at > now() AND u.status = 'active' \
         FROM auth_tokens t JOIN users u ON u.tenant_id = t.tenant_id AND u.id = t.user_id \
         WHERE t.tenant_id = $1 AND t.id = $2",
    )
    .bind(principal.tenant_id.0)
    .bind(principal.token_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();

    let vm_ok: Option<String> = sqlx::query_scalar(
        "SELECT state FROM boat_vms WHERE tenant_id = $1 AND id = $2",
    )
    .bind(principal.tenant_id.0)
    .bind(vm_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();

    let _ = tx.commit().await;
    tok_ok == Some(true) && vm_ok.as_deref() == Some("running")
}

async fn handle_desktop_socket(
    state: RelayState,
    principal: Principal,
    vm_id: Uuid,
    session_id: Uuid,
    mut socket: WebSocket,
) {
    let tenant_id = principal.tenant_id;
    if !state.registry.is_connected(tenant_id, vm_id).await {
        let notify = state.registry.wake_notifier(tenant_id, vm_id).await;
        let _ = tokio::time::timeout(state.config.wake_timeout, notify.notified()).await;
    }

    let (to_vm_tx, mut from_vm_rx, mut shutdown_rx) = match state
        .registry
        .attach_client(tenant_id, vm_id, session_id)
        .await
    {
        Ok(tuple) => tuple,
        Err(_) => {
            let _ = socket.close().await;
            return;
        }
    };

    let (mut ws_tx, mut ws_rx) = socket.split();
    let mut recheck = tokio::time::interval(RECHECK_INTERVAL);
    recheck.tick().await;
    let mut last_activity_touch = Instant::now();

    loop {
        tokio::select! {
            maybe_frame = from_vm_rx.recv() => {
                let Some(frame) = maybe_frame else { break; };
                let Ok(json) = frame.encode_json() else { break; };
                if ws_tx.send(Message::Text(json.into())).await.is_err() {
                    break;
                }
            }
            maybe_msg = ws_rx.next() => {
                match maybe_msg {
                    Some(Ok(Message::Text(txt))) => {
                        if let Ok(frame) = RelayFrame::decode_json(&txt) {
                            if matches!(frame.channel, RelayChannel::HealthPing) {
                                state.registry.touch_heartbeat(tenant_id, vm_id).await;
                            }
                            if last_activity_touch.elapsed() >= ACTIVITY_TOUCH_THROTTLE {
                                last_activity_touch = Instant::now();
                                touch_vm_activity(&state.ctx, tenant_id, vm_id).await;
                            }
                            if to_vm_tx.send(frame).await.is_err() {
                                break;
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                    _ => {}
                }
            }
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    let _ = ws_tx.send(Message::Close(None)).await;
                    break;
                }
            }
            _ = recheck.tick() => {
                if !desktop_session_still_valid(&state, &principal, vm_id).await {
                    let _ = ws_tx.send(Message::Close(None)).await;
                    break;
                }
            }
        }
    }

    state
        .registry
        .detach_client(tenant_id, vm_id, session_id)
        .await;

    if let Ok(mut tx) = state.ctx.db.tenant_tx(tenant_id).await {
        let _ = sqlx::query(
            "UPDATE boat_relay_sessions SET disconnected_at = now() WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id.0)
        .bind(session_id)
        .execute(&mut *tx)
        .await;
        let _ = sqlx::query(
            "UPDATE boat_vms SET last_active_at = now() WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id.0)
        .bind(vm_id)
        .execute(&mut *tx)
        .await;
        let _ = tx.commit().await;
    }
}

/// Boat VM outbound mTLS tunnel endpoint.
/// - Identity MUST come strictly from `Extension<VerifiedBoatIdentity>`.
/// - Rejects stopped/stopping/terminated VMs (never resurrects a stopped VM).
async fn boat_ws_connect(
    State(state): State<RelayState>,
    identity: Option<Extension<VerifiedBoatIdentity>>,
    ws: WebSocketUpgrade,
) -> Result<impl IntoResponse> {
    let Extension(identity) = identity.ok_or(Error::Unauthorized)?;

    let mut tx = state.ctx.db.tenant_tx(identity.tenant_id).await?;
    let vm_state: Option<String> = sqlx::query_scalar(
        "SELECT state FROM boat_vms WHERE tenant_id = $1 AND id = $2 FOR UPDATE",
    )
    .bind(identity.tenant_id.0)
    .bind(identity.vm_id)
    .fetch_optional(&mut *tx)
    .await?;

    // Only accept tunnels when the VM is explicitly provisioning or running.
    match vm_state.as_deref() {
        Some("provisioning") | Some("running") => {}
        Some(_) => return Err(Error::Forbidden),
        None => return Err(Error::Unauthorized),
    }

    let valid_cert: Option<bool> = sqlx::query_scalar(
        "SELECT revoked_at IS NULL AND expires_at > now() \
         FROM boat_device_certs WHERE tenant_id = $1 AND vm_id = $2 AND serial_hex = $3",
    )
    .bind(identity.tenant_id.0)
    .bind(identity.vm_id)
    .bind(&identity.serial_hex)
    .fetch_optional(&mut *tx)
    .await?;
    if valid_cert != Some(true) {
        return Err(Error::Unauthorized);
    }

    let now = OffsetDateTime::now_utc();
    if vm_state.as_deref() == Some("provisioning") {
        sqlx::query(
            "UPDATE boat_vms SET state = 'running', started_at = $3, stopped_at = NULL, last_active_at = $3 \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(identity.tenant_id.0)
        .bind(identity.vm_id)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    } else {
        sqlx::query("UPDATE boat_vms SET last_active_at = $3 WHERE tenant_id = $1 AND id = $2")
            .bind(identity.tenant_id.0)
            .bind(identity.vm_id)
            .bind(now)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;

    Ok(ws
        .max_message_size(MAX_WS_MESSAGE_BYTES)
        .max_frame_size(MAX_WS_MESSAGE_BYTES)
        .on_upgrade(move |socket| handle_boat_socket(state, identity, socket)))
}

async fn boat_cert_and_vm_still_valid(state: &RelayState, id: &VerifiedBoatIdentity) -> bool {
    if OffsetDateTime::now_utc() >= id.not_after {
        return false;
    }
    let Ok(mut tx) = state.ctx.db.tenant_tx(id.tenant_id).await else {
        return false;
    };
    let cert_ok: Option<bool> = sqlx::query_scalar(
        "SELECT revoked_at IS NULL AND expires_at > now() \
         FROM boat_device_certs WHERE tenant_id = $1 AND vm_id = $2 AND serial_hex = $3",
    )
    .bind(id.tenant_id.0)
    .bind(id.vm_id)
    .bind(&id.serial_hex)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();

    let vm_state: Option<String> = sqlx::query_scalar(
        "SELECT state FROM boat_vms WHERE tenant_id = $1 AND id = $2",
    )
    .bind(id.tenant_id.0)
    .bind(id.vm_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();

    let _ = tx.commit().await;
    cert_ok == Some(true) && matches!(vm_state.as_deref(), Some("provisioning" | "running"))
}

async fn handle_boat_socket(
    state: RelayState,
    identity: VerifiedBoatIdentity,
    socket: WebSocket,
) {
    let (session_id, mut from_clients_rx, mut shutdown_rx) = state
        .registry
        .register_vm(identity.tenant_id, identity.vm_id)
        .await;

    let (mut ws_tx, mut ws_rx) = socket.split();
    let secs_left = (identity.not_after - OffsetDateTime::now_utc())
        .whole_seconds()
        .max(0) as u64;
    let cert_expiry_sleep = tokio::time::sleep(Duration::from_secs(secs_left));
    tokio::pin!(cert_expiry_sleep);

    let mut recheck = tokio::time::interval(RECHECK_INTERVAL);
    recheck.tick().await;
    let mut last_activity_touch = Instant::now();

    loop {
        tokio::select! {
            maybe_frame = from_clients_rx.recv() => {
                let Some(frame) = maybe_frame else { break; };
                let Ok(json) = frame.encode_json() else { break; };
                if ws_tx.send(Message::Text(json.into())).await.is_err() {
                    break;
                }
            }
            maybe_msg = ws_rx.next() => {
                match maybe_msg {
                    Some(Ok(Message::Text(txt))) => {
                        if let Ok(frame) = RelayFrame::decode_json(&txt) {
                            if last_activity_touch.elapsed() >= ACTIVITY_TOUCH_THROTTLE {
                                last_activity_touch = Instant::now();
                                touch_vm_activity(&state.ctx, identity.tenant_id, identity.vm_id).await;
                            }
                            let _ = state
                                .registry
                                .forward_from_vm(identity.tenant_id, identity.vm_id, frame)
                                .await;
                        }
                    }
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                    _ => {}
                }
            }
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    let _ = ws_tx.send(Message::Close(None)).await;
                    break;
                }
            }
            _ = &mut cert_expiry_sleep => {
                let _ = ws_tx.send(Message::Close(None)).await;
                break;
            }
            _ = recheck.tick() => {
                if !boat_cert_and_vm_still_valid(&state, &identity).await {
                    let _ = ws_tx.send(Message::Close(None)).await;
                    break;
                }
            }
        }
    }

    state
        .registry
        .unregister_vm(identity.tenant_id, identity.vm_id, session_id)
        .await;
}
