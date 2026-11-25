//! Per-user push device registration & gateway send routes.
//!
//! Security & tenancy properties:
//! - Every route requires an authenticated `Principal` (`Session` or `UserToken`).
//! - `AuthKind::DeviceToken` (e.g. KiCad httplib tokens) is forbidden.
//! - Zero subscription or billing seat checks: free accounts can push.
//! - Rate limited per `(tenant_id, user_id)` rather than gated on Stripe.
//! - Every query is strictly scoped to `(principal.tenant_id, principal.user_id)`:
//!   even an `org_admin` can only list, delete, or push to their own devices.

use crate::apns::{ApnsRequest, ApnsSender};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use bp_ent_core::crypto::sha256;
use bp_ent_core::{audit, AppCtx, AuthKind, Error, Principal, Result, Secret};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Clone)]
struct RateLimiter {
    max: u32,
    window: Duration,
    hits: Arc<Mutex<HashMap<String, (Instant, u32)>>>,
}

impl RateLimiter {
    fn new(max: u32, window: Duration) -> Self {
        Self {
            max: max.max(1),
            window,
            hits: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn allow(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut hits = self.hits.lock().unwrap_or_else(|e| e.into_inner());
        if hits.len() > 20_000 {
            let window = self.window;
            hits.retain(|_, (start, _)| now.duration_since(*start) < window);
        }
        let entry = hits.entry(key.to_string()).or_insert((now, 0));
        if now.duration_since(entry.0) >= self.window {
            *entry = (now, 0);
        }
        entry.1 += 1;
        entry.1 <= self.max
    }
}

#[derive(Clone)]
pub struct PushState {
    ctx: AppCtx,
    sender: Arc<dyn ApnsSender>,
    limiter: RateLimiter,
    allowed_topics: Vec<String>,
}

pub fn router(ctx: AppCtx, sender: Arc<dyn ApnsSender>, rate_limit_per_min: u32) -> Router {
    let allowed_topics = std::env::var("BP_APNS_TOPICS")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    let state = PushState {
        ctx: ctx.clone(),
        sender,
        limiter: RateLimiter::new(rate_limit_per_min, Duration::from_secs(60)),
        allowed_topics,
    };
    let routes = Router::new()
        .route("/v1/push/status", get(status))
        .route("/v1/push/devices", get(list_devices).post(register_device))
        .route("/v1/push/devices/unregister", post(unregister_device))
        .route("/v1/push/devices/{id}", delete(delete_device))
        .route("/v1/push/send", post(send_push))
        .with_state(state);
    bp_ent_core::http::with_auth(routes, &ctx)
}

fn require_user_auth(p: &Principal) -> Result<()> {
    if p.auth == AuthKind::DeviceToken || p.scopes != bp_ent_core::rbac::Scopes::All {
        return Err(Error::Forbidden);
    }
    Ok(())
}

fn safe_token_or_bundle(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 512
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-'))
}

pub fn device_handle(token: &str) -> String {
    hex::encode(&sha256(token.as_bytes())[..6])
}

fn device_aad(device_id: Uuid) -> Vec<u8> {
    format!("push_devices|{device_id}|token").into_bytes()
}

fn rfc3339(ts: OffsetDateTime) -> String {
    ts.format(&Rfc3339).unwrap_or_default()
}

// ------------------------------------------------------------------- DTOs

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PushStatusOut {
    configured: bool,
    mode: &'static str,
    device_count: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PushDeviceOut {
    id: Uuid,
    handle: String,
    platform: String,
    bundle: String,
    env: String,
    kind: String,
    device_name: String,
    muted: bool,
    updated_at: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterDeviceReq {
    token: String,
    platform: String,
    bundle: String,
    #[serde(default = "default_env")]
    env: String,
    #[serde(default = "default_kind")]
    kind: String,
    #[serde(default)]
    device_name: String,
    #[serde(default)]
    muted: bool,
}

fn default_env() -> String {
    "production".into()
}

fn default_kind() -> String {
    "alert".into()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UnregisterDeviceReq {
    token: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SendPushReq {
    #[serde(default = "default_push_type")]
    push_type: String,
    #[serde(default)]
    priority: Option<u8>,
    #[serde(default)]
    collapse_id: Option<String>,
    payload: serde_json::Value,
    #[serde(default)]
    target_handle: Option<String>,
    #[serde(default)]
    through: bool,
}

fn default_push_type() -> String {
    "alert".into()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SendDeviceResult {
    handle: String,
    status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    apns_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SendPushResp {
    sent: u64,
    retired: u64,
    failed: u64,
    results: Vec<SendDeviceResult>,
}

// ---------------------------------------------------------------- Handlers

async fn status(State(st): State<PushState>, p: Principal) -> Result<Json<PushStatusOut>> {
    require_user_auth(&p)?;
    let mut tx = st.ctx.db.tenant_tx(p.tenant_id).await?;
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM push_devices WHERE tenant_id = $1 AND user_id = $2",
    )
    .bind(p.tenant_id.0)
    .bind(p.user_id.0)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    let mode = st.sender.mode();
    Ok(Json(PushStatusOut {
        configured: mode != "unconfigured",
        mode,
        device_count: count,
    }))
}

async fn list_devices(
    State(st): State<PushState>,
    p: Principal,
) -> Result<Json<Vec<PushDeviceOut>>> {
    require_user_auth(&p)?;
    let mut tx = st.ctx.db.tenant_tx(p.tenant_id).await?;
    let rows = sqlx::query(
        "SELECT id, handle, platform, bundle, env, kind, device_name, muted, updated_at \
         FROM push_devices WHERE tenant_id = $1 AND user_id = $2 ORDER BY updated_at DESC",
    )
    .bind(p.tenant_id.0)
    .bind(p.user_id.0)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;

    let out = rows
        .into_iter()
        .map(|r| PushDeviceOut {
            id: r.get("id"),
            handle: r.get("handle"),
            platform: r.get("platform"),
            bundle: r.get("bundle"),
            env: r.get("env"),
            kind: r.get("kind"),
            device_name: r.get("device_name"),
            muted: r.get("muted"),
            updated_at: rfc3339(r.get("updated_at")),
        })
        .collect();
    Ok(Json(out))
}

async fn register_device(
    State(st): State<PushState>,
    p: Principal,
    Json(req): Json<RegisterDeviceReq>,
) -> Result<Json<PushDeviceOut>> {
    require_user_auth(&p)?;
    let reg_key = format!("reg:{}:{}", p.tenant_id, p.user_id);
    if !st.limiter.allow(&reg_key) {
        return Err(Error::TooManyRequests);
    }
    let token = req.token.trim();
    let bundle = req.bundle.trim();
    if !safe_token_or_bundle(token) || !safe_token_or_bundle(bundle) || bundle.len() > 255 {
        return Err(Error::invalid("invalid push token or bundle id"));
    }
    if !matches!(req.platform.as_str(), "ios" | "android") {
        return Err(Error::invalid("platform must be ios or android"));
    }
    if req.platform == "ios"
        && (!(64..=200).contains(&token.len()) || !token.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Err(Error::invalid("invalid iOS APNs device token"));
    }
    if !st.allowed_topics.is_empty() && !st.allowed_topics.iter().any(|t| t == bundle) {
        return Err(Error::invalid("bundle id is not allowed"));
    }
    if !matches!(req.env.as_str(), "sandbox" | "production") {
        return Err(Error::invalid("env must be sandbox or production"));
    }
    if !matches!(req.kind.as_str(), "alert" | "activity" | "start") {
        return Err(Error::invalid("kind must be alert, activity, or start"));
    }
    let device_name: String = req
        .device_name
        .trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(120)
        .collect();

    let token_hash = sha256(token.as_bytes());
    let handle = device_handle(token);

    let mut tx = st.ctx.db.tenant_tx(p.tenant_id).await?;
    sqlx::query(
        "DELETE FROM push_devices WHERE tenant_id = $1 AND token_hash = $2 AND user_id <> $3",
    )
    .bind(p.tenant_id.0)
    .bind(token_hash.as_slice())
    .bind(p.user_id.0)
    .execute(&mut *tx)
    .await?;

    let existing_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM push_devices WHERE tenant_id = $1 AND user_id = $2 AND token_hash = $3 FOR UPDATE",
    )
    .bind(p.tenant_id.0)
    .bind(p.user_id.0)
    .bind(token_hash.as_slice())
    .fetch_optional(&mut *tx)
    .await?;

    if existing_id.is_none() {
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM push_devices WHERE tenant_id = $1 AND user_id = $2",
        )
        .bind(p.tenant_id.0)
        .bind(p.user_id.0)
        .fetch_one(&mut *tx)
        .await?;
        if count >= 20 {
            return Err(Error::invalid("device registration limit reached (max 20)"));
        }
    }

    let id = existing_id.unwrap_or_else(Uuid::new_v4);
    let token_enc = st
        .ctx
        .cipher
        .seal(p.tenant_id, &device_aad(id), token.as_bytes())
        .await?;

    let row = if existing_id.is_some() {
        sqlx::query(
            "UPDATE push_devices \
             SET token_enc = $4, handle = $5, platform = $6, bundle = $7, env = $8, kind = $9, device_name = $10, muted = $11, updated_at = now() \
             WHERE tenant_id = $1 AND user_id = $2 AND id = $3 \
             RETURNING id, handle, platform, bundle, env, kind, device_name, muted, updated_at",
        )
        .bind(p.tenant_id.0)
        .bind(p.user_id.0)
        .bind(id)
        .bind(&token_enc)
        .bind(&handle)
        .bind(&req.platform)
        .bind(bundle)
        .bind(&req.env)
        .bind(&req.kind)
        .bind(&device_name)
        .bind(req.muted)
        .fetch_one(&mut *tx)
        .await?
    } else {
        sqlx::query(
            "INSERT INTO push_devices (id, tenant_id, user_id, token_hash, token_enc, handle, platform, bundle, env, kind, device_name, muted) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
             RETURNING id, handle, platform, bundle, env, kind, device_name, muted, updated_at",
        )
        .bind(id)
        .bind(p.tenant_id.0)
        .bind(p.user_id.0)
        .bind(token_hash.as_slice())
        .bind(&token_enc)
        .bind(&handle)
        .bind(&req.platform)
        .bind(bundle)
        .bind(&req.env)
        .bind(&req.kind)
        .bind(&device_name)
        .bind(req.muted)
        .fetch_one(&mut *tx)
        .await?
    };

    audit::append(
        &mut tx,
        &p,
        "push.device_registered",
        &format!("push_device:{handle}"),
        serde_json::json!({ "platform": req.platform, "env": req.env, "kind": req.kind, "muted": req.muted }),
    )
    .await?;
    tx.commit().await?;

    Ok(Json(PushDeviceOut {
        id: row.get("id"),
        handle: row.get("handle"),
        platform: row.get("platform"),
        bundle: row.get("bundle"),
        env: row.get("env"),
        kind: row.get("kind"),
        device_name: row.get("device_name"),
        muted: row.get("muted"),
        updated_at: rfc3339(row.get("updated_at")),
    }))
}

async fn delete_device(
    State(st): State<PushState>,
    p: Principal,
    Path(id): Path<Uuid>,
) -> Result<StatusCode> {
    require_user_auth(&p)?;
    let mut tx = st.ctx.db.tenant_tx(p.tenant_id).await?;
    let res = sqlx::query(
        "DELETE FROM push_devices WHERE tenant_id = $1 AND user_id = $2 AND id = $3",
    )
    .bind(p.tenant_id.0)
    .bind(p.user_id.0)
    .bind(id)
    .execute(&mut *tx)
    .await?;
    if res.rows_affected() == 0 {
        return Err(Error::NotFound);
    }
    audit::append(
        &mut tx,
        &p,
        "push.device_deleted",
        &format!("push_device:{id}"),
        serde_json::json!({}),
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn unregister_device(
    State(st): State<PushState>,
    p: Principal,
    Json(req): Json<UnregisterDeviceReq>,
) -> Result<StatusCode> {
    require_user_auth(&p)?;
    let token = req.token.trim();
    if !safe_token_or_bundle(token) {
        return Err(Error::invalid("invalid push token"));
    }
    let token_hash = sha256(token.as_bytes());
    let mut tx = st.ctx.db.tenant_tx(p.tenant_id).await?;
    let res = sqlx::query(
        "DELETE FROM push_devices WHERE tenant_id = $1 AND user_id = $2 AND token_hash = $3",
    )
    .bind(p.tenant_id.0)
    .bind(p.user_id.0)
    .bind(token_hash.as_slice())
    .execute(&mut *tx)
    .await?;
    if res.rows_affected() > 0 {
        audit::append(
            &mut tx,
            &p,
            "push.device_unregistered",
            &format!("push_device:{}", device_handle(token)),
            serde_json::json!({}),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn send_push(
    State(st): State<PushState>,
    p: Principal,
    Json(req): Json<SendPushReq>,
) -> Result<Json<SendPushResp>> {
    require_user_auth(&p)?;
    let rate_key = format!("{}:{}", p.tenant_id, p.user_id);
    if !st.limiter.allow(&rate_key) {
        return Err(Error::TooManyRequests);
    }
    if !matches!(req.push_type.as_str(), "alert" | "background") {
        return Err(Error::invalid("pushType must be alert or background"));
    }
    if !req.payload.is_object() {
        return Err(Error::invalid("payload must be a JSON object"));
    }
    let payload_len = serde_json::to_vec(&req.payload).map(|v| v.len()).unwrap_or(usize::MAX);
    if payload_len > 4096 {
        return Err(Error::invalid("APNs payload exceeds 4096 bytes"));
    }
    if let Some(cid) = &req.collapse_id {
        if cid.len() > 128 || cid.chars().any(|c| c.is_control()) {
            return Err(Error::invalid("invalid collapseId"));
        }
    }
    let priority = req
        .priority
        .unwrap_or(if req.push_type == "background" { 5 } else { 10 });
    if !matches!(priority, 1 | 5 | 10) {
        return Err(Error::invalid("priority must be 1, 5, or 10"));
    }

    let target_handle = req
        .target_handle
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let mut tx = st.ctx.db.tenant_tx(p.tenant_id).await?;
    let rows = if let Some(handle) = target_handle {
        sqlx::query(
            "SELECT id, handle, bundle, env, token_enc, muted \
             FROM push_devices \
             WHERE tenant_id = $1 AND user_id = $2 AND platform = 'ios' AND kind = 'alert' AND handle = $3",
        )
        .bind(p.tenant_id.0)
        .bind(p.user_id.0)
        .bind(handle)
        .fetch_all(&mut *tx)
        .await?
    } else {
        sqlx::query(
            "SELECT id, handle, bundle, env, token_enc, muted \
             FROM push_devices \
             WHERE tenant_id = $1 AND user_id = $2 AND platform = 'ios' AND kind = 'alert' \
             ORDER BY updated_at DESC LIMIT 20",
        )
        .bind(p.tenant_id.0)
        .bind(p.user_id.0)
        .fetch_all(&mut *tx)
        .await?
    };
    tx.commit().await?;

    struct Target {
        id: Uuid,
        handle: String,
        bundle: String,
        env: String,
        token: Secret<String>,
    }

    let mut sent = 0u64;
    let mut retired = 0u64;
    let mut failed = 0u64;
    let mut results = Vec::with_capacity(rows.len());
    let mut dead_ids = Vec::new();
    let mut targets = Vec::new();
    for r in rows {
        let muted: bool = r.get("muted");
        if muted && !req.through && req.push_type != "background" {
            continue;
        }
        let id: Uuid = r.get("id");
        let handle: String = r.get("handle");
        let bundle: String = r.get("bundle");
        if !st.allowed_topics.is_empty() && !st.allowed_topics.iter().any(|t| t == &bundle) {
            failed += 1;
            results.push(SendDeviceResult {
                handle,
                status: 403,
                apns_id: None,
                reason: Some("bundle id is not allowed".into()),
            });
            continue;
        }
        let enc: Vec<u8> = r.get("token_enc");
        let raw = match st
            .ctx
            .cipher
            .open_str(p.tenant_id, &device_aad(id), &enc)
            .await
        {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(device_id = %id, handle = %handle, error = %e, "failed to decrypt push device token");
                failed += 1;
                results.push(SendDeviceResult {
                    handle,
                    status: 500,
                    apns_id: None,
                    reason: Some("token decryption failed".into()),
                });
                continue;
            }
        };
        targets.push(Target {
            id,
            handle,
            bundle,
            env: r.get("env"),
            token: Secret::new(raw),
        });
    }

    for t in targets {
        let delivery = st
            .sender
            .send(ApnsRequest {
                token: t.token,
                env: t.env,
                topic: t.bundle,
                push_type: req.push_type.clone(),
                priority,
                collapse_id: req.collapse_id.clone(),
                payload: req.payload.clone(),
            })
            .await;

        if delivery.status == 200 {
            sent += 1;
        } else if delivery.dead {
            retired += 1;
            dead_ids.push(t.id);
        } else {
            failed += 1;
        }

        results.push(SendDeviceResult {
            handle: t.handle,
            status: delivery.status,
            apns_id: delivery.apns_id,
            reason: delivery.reason,
        });
    }

    if !dead_ids.is_empty() || sent > 0 || failed > 0 {
        let mut tx = st.ctx.db.tenant_tx(p.tenant_id).await?;
        for dead_id in &dead_ids {
            sqlx::query(
                "DELETE FROM push_devices WHERE tenant_id = $1 AND user_id = $2 AND id = $3",
            )
            .bind(p.tenant_id.0)
            .bind(p.user_id.0)
            .bind(dead_id)
            .execute(&mut *tx)
            .await?;
        }
        audit::append(
            &mut tx,
            &p,
            "push.sent",
            &format!("user:{}", p.user_id),
            serde_json::json!({
                "pushType": req.push_type,
                "sent": sent,
                "retired": retired,
                "failed": failed
            }),
        )
        .await?;
        tx.commit().await?;
    }

    Ok(Json(SendPushResp {
        sent,
        retired,
        failed,
        results,
    }))
}
