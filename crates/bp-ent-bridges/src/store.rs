//! Tenant-scoped PostgreSQL persistence for bridges, deliveries, and quarantined messages.
//!
//! Every query runs inside `ctx.db.tenant_tx(tenant_id)` under forced RLS.

use crate::model::{
    sanitize_external_text, AdapterConfig, BridgeDirection, BridgeEventKind, BridgeKind,
    BridgePublicId, BridgeView, CreateBridgeRequest, CreateBridgeResponse, DeliveryView,
    RotateSecretResponse, UpdateBridgeRequest,
};
use crate::peer::validate_peer_scopes;
use crate::sealed;
use bp_ent_core::crypto::random_token;
use bp_ent_core::{audit, AppCtx, Error, Principal, Result, TenantId, Tx, UserId};
use serde_json::json;
use sqlx::Row;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct LoadedBridge {
    pub id: Uuid,
    pub tenant_id: TenantId,
    pub name: String,
    pub kind: BridgeKind,
    pub enabled: bool,
    pub direction: BridgeDirection,
    pub target_url: Option<String>,
    pub subscribed_events: Vec<String>,
    pub inbound_secret: Vec<u8>,
    pub outbound_secret: Option<Vec<u8>>,
    pub adapter_config: AdapterConfig,
    pub secret_hint: String,
    pub rate_limit_rpm: i32,
    pub peer_enabled: bool,
    pub peer_scopes: Vec<String>,
    pub created_by: UserId,
}

pub enum DedupeOutcome {
    Accepted(Uuid),
    Replay,
}

fn fmt_ts(ts: OffsetDateTime) -> String {
    ts.format(&Rfc3339).unwrap_or_else(|_| ts.unix_timestamp().to_string())
}

fn validate_events(events: &[String]) -> Result<Vec<String>> {
    let mut out = Vec::with_capacity(events.len());
    for e in events {
        let k = BridgeEventKind::parse(e)?;
        let s = k.as_str().to_string();
        if !out.contains(&s) {
            out.push(s);
        }
    }
    Ok(out)
}

fn validate_target_url(ctx: &AppCtx, raw: Option<&str>, direction: BridgeDirection) -> Result<Option<String>> {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        Some(u) => {
            if u.len() > 2048 {
                return Err(Error::invalid("targetUrl is too long"));
            }
            ctx.http.check_url(u)?;
            Ok(Some(u.to_string()))
        }
        None => {
            if direction == BridgeDirection::Outbound {
                return Err(Error::invalid("outbound bridge requires a valid https targetUrl"));
            }
            Ok(None)
        }
    }
}

fn validate_adapter_config(kind: BridgeKind, cfg: &AdapterConfig) -> Result<()> {
    if kind == BridgeKind::Discord {
        if let Some(ref pk) = cfg.discord_public_key_hex {
            let decoded = hex::decode(pk.trim())
                .map_err(|_| Error::invalid("discordPublicKeyHex must be 64 hex characters"))?;
            if decoded.len() != 32 {
                return Err(Error::invalid("discordPublicKeyHex must be 32 bytes (64 hex chars)"));
            }
        }
    }
    if kind == BridgeKind::Teams {
        if let Some(ref app_id) = cfg.teams_app_id {
            if app_id.trim().is_empty() || app_id.len() > 128 {
                return Err(Error::invalid("teamsAppId must be 1..=128 characters"));
            }
        }
    }
    Ok(())
}

fn row_to_view(tenant: TenantId, r: &sqlx::postgres::PgRow) -> Result<BridgeView> {
    let id: Uuid = r.get("id");
    let pub_id = BridgePublicId {
        tenant_id: tenant,
        bridge_id: id,
    }
    .format();
    let kind_str: String = r.get("kind");
    let dir_str: String = r.get("direction");
    let created_at: OffsetDateTime = r.get("created_at");
    let updated_at: OffsetDateTime = r.get("updated_at");
    Ok(BridgeView {
        id,
        public_id: pub_id.clone(),
        name: r.get("name"),
        kind: BridgeKind::parse(&kind_str)?,
        enabled: r.get("enabled"),
        direction: BridgeDirection::parse(&dir_str)?,
        target_url: r.get("target_url"),
        subscribed_events: r.get("subscribed_events"),
        secret_hint: r.get("secret_hint"),
        rate_limit_rpm: r.get("rate_limit_rpm"),
        peer_enabled: r.get("peer_enabled"),
        peer_scopes: r.get("peer_scopes"),
        inbound_path: format!("/v1/bridges/{pub_id}/inbound"),
        a2a_path: format!("/v1/bridges/{pub_id}/a2a"),
        created_at: fmt_ts(created_at),
        updated_at: fmt_ts(updated_at),
    })
}

pub async fn create_bridge(
    ctx: &AppCtx,
    principal: &Principal,
    req: CreateBridgeRequest,
) -> Result<CreateBridgeResponse> {
    let name = sanitize_external_text(&req.name, 120);
    if name.is_empty() {
        return Err(Error::invalid("bridge name is required"));
    }
    if !(1..=600).contains(&req.rate_limit_rpm) {
        return Err(Error::invalid("rateLimitRpm must be between 1 and 600"));
    }
    let target_url = validate_target_url(ctx, req.target_url.as_deref(), req.direction)?;
    let subscribed_events = validate_events(&req.subscribed_events)?;
    let peer_perms = validate_peer_scopes(&req.peer_scopes)?;
    let peer_scopes: Vec<String> = peer_perms.iter().map(|p| p.scope().to_string()).collect();
    validate_adapter_config(req.kind, &req.adapter_config)?;

    let bridge_id = Uuid::new_v4();
    let inbound_secret = match req.inbound_signing_secret.filter(|s| !s.trim().is_empty()) {
        Some(s) => s.trim().to_string(),
        None => format!("bps_{}", random_token(32)),
    };
    let outbound_secret = if req.direction.allows_outbound() {
        Some(format!("bpo_{}", random_token(32)))
    } else {
        None
    };

    let hint = match req.kind {
        BridgeKind::Discord => "ed25519-pubkey".to_string(),
        BridgeKind::Teams => "ms-teams-jwks".to_string(),
        _ => sealed::secret_hint(&inbound_secret),
    };

    let inbound_sealed = sealed::seal_str(
        ctx,
        principal.tenant_id,
        &sealed::aad("bridges", bridge_id, "inbound_secret"),
        &inbound_secret,
    )
    .await?;
    let outbound_sealed = match &outbound_secret {
        Some(s) => Some(
            sealed::seal_str(
                ctx,
                principal.tenant_id,
                &sealed::aad("bridges", bridge_id, "outbound_secret"),
                s,
            )
            .await?,
        ),
        None => None,
    };
    let config_sealed = sealed::seal_json(
        ctx,
        principal.tenant_id,
        &sealed::aad("bridges", bridge_id, "adapter_config"),
        &req.adapter_config,
    )
    .await?;

    let mut tx = ctx.db.tenant_tx(principal.tenant_id).await?;
    let row = sqlx::query(
        "INSERT INTO bridges (id, tenant_id, name, kind, enabled, direction, target_url, \
         subscribed_events, inbound_secret_sealed, outbound_secret_sealed, adapter_config_sealed, \
         secret_hint, rate_limit_rpm, peer_enabled, peer_scopes, created_by) \
         VALUES ($1, $2, $3, $4, true, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) \
         RETURNING id, name, kind, enabled, direction, target_url, subscribed_events, secret_hint, \
                   rate_limit_rpm, peer_enabled, peer_scopes, created_at, updated_at",
    )
    .bind(bridge_id)
    .bind(principal.tenant_id.0)
    .bind(&name)
    .bind(req.kind.as_str())
    .bind(req.direction.as_str())
    .bind(&target_url)
    .bind(&subscribed_events)
    .bind(&inbound_sealed)
    .bind(&outbound_sealed)
    .bind(&config_sealed)
    .bind(&hint)
    .bind(req.rate_limit_rpm)
    .bind(req.peer_enabled)
    .bind(&peer_scopes)
    .bind(principal.user_id.0)
    .fetch_one(&mut *tx)
    .await?;

    audit::append(
        &mut tx,
        principal,
        "bridge.created",
        &format!("bridge:{bridge_id}"),
        json!({
            "kind": req.kind.as_str(),
            "direction": req.direction.as_str(),
            "peerEnabled": req.peer_enabled,
            "peerScopes": peer_scopes,
        }),
    )
    .await?;
    tx.commit().await?;

    let show_inbound = !matches!(req.kind, BridgeKind::Discord | BridgeKind::Teams);
    Ok(CreateBridgeResponse {
        bridge: row_to_view(principal.tenant_id, &row)?,
        inbound_secret_once: show_inbound.then_some(inbound_secret),
        outbound_secret_once: outbound_secret,
    })
}

pub async fn list_bridges(ctx: &AppCtx, tenant: TenantId) -> Result<Vec<BridgeView>> {
    let mut tx = ctx.db.tenant_tx(tenant).await?;
    let rows = sqlx::query(
        "SELECT id, name, kind, enabled, direction, target_url, subscribed_events, secret_hint, \
                rate_limit_rpm, peer_enabled, peer_scopes, created_at, updated_at \
         FROM bridges WHERE tenant_id = $1 ORDER BY created_at DESC",
    )
    .bind(tenant.0)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    rows.iter().map(|r| row_to_view(tenant, r)).collect()
}

pub async fn get_bridge(ctx: &AppCtx, tenant: TenantId, id: Uuid) -> Result<BridgeView> {
    let mut tx = ctx.db.tenant_tx(tenant).await?;
    let row = sqlx::query(
        "SELECT id, name, kind, enabled, direction, target_url, subscribed_events, secret_hint, \
                rate_limit_rpm, peer_enabled, peer_scopes, created_at, updated_at \
         FROM bridges WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant.0)
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(Error::NotFound)?;
    tx.commit().await?;
    row_to_view(tenant, &row)
}

pub async fn update_bridge(
    ctx: &AppCtx,
    principal: &Principal,
    id: Uuid,
    req: UpdateBridgeRequest,
) -> Result<BridgeView> {
    let mut tx = ctx.db.tenant_tx(principal.tenant_id).await?;
    let existing = sqlx::query(
        "SELECT kind, direction, target_url, name, enabled, subscribed_events, rate_limit_rpm, \
                peer_enabled, peer_scopes, adapter_config_sealed \
         FROM bridges WHERE tenant_id = $1 AND id = $2 FOR UPDATE",
    )
    .bind(principal.tenant_id.0)
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(Error::NotFound)?;

    let kind = BridgeKind::parse(&existing.get::<String, _>("kind"))?;
    let next_direction = match req.direction {
        Some(d) => d,
        None => BridgeDirection::parse(&existing.get::<String, _>("direction"))?,
    };
    let next_target_url = match req.target_url {
        Some(inner) => validate_target_url(ctx, inner.as_deref(), next_direction)?,
        None => existing.get("target_url"),
    };
    let next_name = match req.name {
        Some(n) => {
            let clean = sanitize_external_text(&n, 120);
            if clean.is_empty() {
                return Err(Error::invalid("bridge name cannot be empty"));
            }
            clean
        }
        None => existing.get("name"),
    };
    let next_enabled = req.enabled.unwrap_or_else(|| existing.get("enabled"));
    let next_events = match req.subscribed_events {
        Some(evs) => validate_events(&evs)?,
        None => existing.get("subscribed_events"),
    };
    let next_rpm = match req.rate_limit_rpm {
        Some(r) if (1..=600).contains(&r) => r,
        Some(_) => return Err(Error::invalid("rateLimitRpm must be between 1 and 600")),
        None => existing.get("rate_limit_rpm"),
    };
    let next_peer_enabled = req.peer_enabled.unwrap_or_else(|| existing.get("peer_enabled"));
    let next_peer_scopes: Vec<String> = match req.peer_scopes {
        Some(raw) => validate_peer_scopes(&raw)?
            .into_iter()
            .map(|p| p.scope().to_string())
            .collect(),
        None => existing.get("peer_scopes"),
    };
    let next_cfg_sealed = match req.adapter_config {
        Some(cfg) => {
            validate_adapter_config(kind, &cfg)?;
            sealed::seal_json(
                ctx,
                principal.tenant_id,
                &sealed::aad("bridges", id, "adapter_config"),
                &cfg,
            )
            .await?
        }
        None => existing.get("adapter_config_sealed"),
    };

    let updated = sqlx::query(
        "UPDATE bridges SET name = $3, enabled = $4, direction = $5, target_url = $6, \
         subscribed_events = $7, rate_limit_rpm = $8, peer_enabled = $9, peer_scopes = $10, \
         adapter_config_sealed = $11, updated_at = now() \
         WHERE tenant_id = $1 AND id = $2 \
         RETURNING id, name, kind, enabled, direction, target_url, subscribed_events, secret_hint, \
                   rate_limit_rpm, peer_enabled, peer_scopes, created_at, updated_at",
    )
    .bind(principal.tenant_id.0)
    .bind(id)
    .bind(&next_name)
    .bind(next_enabled)
    .bind(next_direction.as_str())
    .bind(&next_target_url)
    .bind(&next_events)
    .bind(next_rpm)
    .bind(next_peer_enabled)
    .bind(&next_peer_scopes)
    .bind(&next_cfg_sealed)
    .fetch_one(&mut *tx)
    .await?;

    audit::append(
        &mut tx,
        principal,
        "bridge.updated",
        &format!("bridge:{id}"),
        json!({ "enabled": next_enabled, "peerEnabled": next_peer_enabled }),
    )
    .await?;
    tx.commit().await?;
    row_to_view(principal.tenant_id, &updated)
}

pub async fn delete_bridge(ctx: &AppCtx, principal: &Principal, id: Uuid) -> Result<()> {
    let mut tx = ctx.db.tenant_tx(principal.tenant_id).await?;
    let n = sqlx::query("DELETE FROM bridges WHERE tenant_id = $1 AND id = $2")
        .bind(principal.tenant_id.0)
        .bind(id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(Error::NotFound);
    }
    audit::append(
        &mut tx,
        principal,
        "bridge.deleted",
        &format!("bridge:{id}"),
        json!({}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn rotate_secret(
    ctx: &AppCtx,
    principal: &Principal,
    id: Uuid,
) -> Result<RotateSecretResponse> {
    let mut tx = ctx.db.tenant_tx(principal.tenant_id).await?;
    let row = sqlx::query(
        "SELECT kind, direction FROM bridges WHERE tenant_id = $1 AND id = $2 FOR UPDATE",
    )
    .bind(principal.tenant_id.0)
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(Error::NotFound)?;

    let kind = BridgeKind::parse(&row.get::<String, _>("kind"))?;
    let dir = BridgeDirection::parse(&row.get::<String, _>("direction"))?;

    let new_inbound = format!("bps_{}", random_token(32));
    let new_outbound = dir.allows_outbound().then(|| format!("bpo_{}", random_token(32)));
    let hint = match kind {
        BridgeKind::Discord => "ed25519-pubkey".to_string(),
        BridgeKind::Teams => "ms-teams-jwks".to_string(),
        _ => sealed::secret_hint(&new_inbound),
    };
    let in_sealed = sealed::seal_str(
        ctx,
        principal.tenant_id,
        &sealed::aad("bridges", id, "inbound_secret"),
        &new_inbound,
    )
    .await?;
    let out_sealed = match &new_outbound {
        Some(s) => Some(
            sealed::seal_str(
                ctx,
                principal.tenant_id,
                &sealed::aad("bridges", id, "outbound_secret"),
                s,
            )
            .await?,
        ),
        None => None,
    };

    sqlx::query(
        "UPDATE bridges SET inbound_secret_sealed = $3, outbound_secret_sealed = $4, \
         secret_hint = $5, updated_at = now() WHERE tenant_id = $1 AND id = $2",
    )
    .bind(principal.tenant_id.0)
    .bind(id)
    .bind(&in_sealed)
    .bind(&out_sealed)
    .bind(&hint)
    .execute(&mut *tx)
    .await?;

    audit::append(
        &mut tx,
        principal,
        "bridge.secret_rotated",
        &format!("bridge:{id}"),
        json!({ "hint": hint }),
    )
    .await?;
    tx.commit().await?;

    let show_inbound = !matches!(kind, BridgeKind::Discord | BridgeKind::Teams);
    Ok(RotateSecretResponse {
        bridge_id: id,
        secret_hint: hint,
        inbound_secret_once: show_inbound.then_some(new_inbound),
        outbound_secret_once: new_outbound,
    })
}

pub async fn load_bridge(
    ctx: &AppCtx,
    tx: &mut Tx,
    tenant: TenantId,
    id: Uuid,
) -> Result<Option<LoadedBridge>> {
    let r = sqlx::query(
        "SELECT id, name, kind, enabled, direction, target_url, subscribed_events, \
                inbound_secret_sealed, outbound_secret_sealed, adapter_config_sealed, \
                secret_hint, rate_limit_rpm, peer_enabled, peer_scopes, created_by \
         FROM bridges WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant.0)
    .bind(id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(r) = r else {
        return Ok(None);
    };
    let in_sealed: Vec<u8> = r.get("inbound_secret_sealed");
    let out_sealed: Option<Vec<u8>> = r.get("outbound_secret_sealed");
    let cfg_sealed: Vec<u8> = r.get("adapter_config_sealed");

    let inbound_secret =
        sealed::open_bytes(ctx, tenant, &sealed::aad("bridges", id, "inbound_secret"), &in_sealed)
            .await?;
    let outbound_secret = match out_sealed {
        Some(b) => Some(
            sealed::open_bytes(ctx, tenant, &sealed::aad("bridges", id, "outbound_secret"), &b)
                .await?,
        ),
        None => None,
    };
    let adapter_config: AdapterConfig =
        sealed::open_json(ctx, tenant, &sealed::aad("bridges", id, "adapter_config"), &cfg_sealed)
            .await?;

    Ok(Some(LoadedBridge {
        id,
        tenant_id: tenant,
        name: r.get("name"),
        kind: BridgeKind::parse(&r.get::<String, _>("kind"))?,
        enabled: r.get("enabled"),
        direction: BridgeDirection::parse(&r.get::<String, _>("direction"))?,
        target_url: r.get("target_url"),
        subscribed_events: r.get("subscribed_events"),
        inbound_secret,
        outbound_secret,
        adapter_config,
        secret_hint: r.get("secret_hint"),
        rate_limit_rpm: r.get("rate_limit_rpm"),
        peer_enabled: r.get("peer_enabled"),
        peer_scopes: r.get("peer_scopes"),
        created_by: UserId(r.get("created_by")),
    }))
}

pub async fn load_outbound_subscribers(
    ctx: &AppCtx,
    tx: &mut Tx,
    tenant: TenantId,
    event_kind: BridgeEventKind,
) -> Result<Vec<LoadedBridge>> {
    let rows = sqlx::query(
        "SELECT id FROM bridges WHERE tenant_id = $1 AND enabled = true \
         AND direction IN ('outbound', 'bidirectional') AND target_url IS NOT NULL \
         AND $2 = ANY(subscribed_events)",
    )
    .bind(tenant.0)
    .bind(event_kind.as_str())
    .fetch_all(&mut **tx)
    .await?;

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let id: Uuid = r.get("id");
        if let Some(b) = load_bridge(ctx, tx, tenant, id).await? {
            out.push(b);
        }
    }
    Ok(out)
}

pub async fn count_recent_inbound_deliveries(
    tx: &mut Tx,
    tenant: TenantId,
    bridge_id: Uuid,
) -> Result<i64> {
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM bridge_deliveries \
         WHERE tenant_id = $1 AND bridge_id = $2 AND direction = 'inbound' \
           AND created_at > now() - interval '1 minute'",
    )
    .bind(tenant.0)
    .bind(bridge_id)
    .fetch_one(&mut **tx)
    .await?;
    Ok(count)
}

#[allow(clippy::too_many_arguments)]
pub async fn record_inbound_dedupe(
    ctx: &AppCtx,
    tx: &mut Tx,
    tenant: TenantId,
    bridge_id: Uuid,
    delivery_id: &str,
    event_type: &str,
    status: &str,
    payload_summary: &serde_json::Value,
) -> Result<DedupeOutcome> {
    let row_id = Uuid::new_v4();
    let sealed_payload = sealed::seal_json(
        ctx,
        tenant,
        &sealed::aad("bridge_deliveries", row_id, "payload"),
        payload_summary,
    )
    .await?;
    let res = sqlx::query(
        "INSERT INTO bridge_deliveries (id, tenant_id, bridge_id, direction, delivery_id, event_type, status, payload_sealed) \
         VALUES ($1, $2, $3, 'inbound', $4, $5, $6, $7) \
         ON CONFLICT (tenant_id, bridge_id, direction, delivery_id) DO NOTHING",
    )
    .bind(row_id)
    .bind(tenant.0)
    .bind(bridge_id)
    .bind(delivery_id)
    .bind(event_type)
    .bind(status)
    .bind(&sealed_payload)
    .execute(&mut **tx)
    .await?;
    if res.rows_affected() == 0 {
        return Ok(DedupeOutcome::Replay);
    }
    Ok(DedupeOutcome::Accepted(row_id))
}

#[allow(clippy::too_many_arguments)]
pub async fn store_quarantined_message(
    ctx: &AppCtx,
    tx: &mut Tx,
    tenant: TenantId,
    bridge_id: Uuid,
    delivery_row_id: Uuid,
    external_actor: &str,
    channel_ref: &str,
    event_type: &str,
    sanitized_text: &str,
    approval_request_id: Option<Uuid>,
) -> Result<Uuid> {
    let msg_id = Uuid::new_v4();
    let body_sealed = sealed::seal_str(
        ctx,
        tenant,
        &sealed::aad("bridge_messages", msg_id, "body"),
        sanitized_text,
    )
    .await?;
    sqlx::query(
        "INSERT INTO bridge_messages \
         (id, tenant_id, bridge_id, delivery_id, external_actor, channel_ref, event_type, trust_level, approval_request_id, body_sealed) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, 'untrusted_external', $8, $9)",
    )
    .bind(msg_id)
    .bind(tenant.0)
    .bind(bridge_id)
    .bind(delivery_row_id)
    .bind(external_actor)
    .bind(channel_ref)
    .bind(event_type)
    .bind(approval_request_id)
    .bind(&body_sealed)
    .execute(&mut **tx)
    .await?;
    Ok(msg_id)
}

pub async fn list_deliveries(
    ctx: &AppCtx,
    tenant: TenantId,
    bridge_id: Uuid,
) -> Result<Vec<DeliveryView>> {
    let mut tx = ctx.db.tenant_tx(tenant).await?;
    let exists: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM bridges WHERE tenant_id = $1 AND id = $2")
            .bind(tenant.0)
            .bind(bridge_id)
            .fetch_optional(&mut *tx)
            .await?;
    if exists.is_none() {
        return Err(Error::NotFound);
    }
    let rows = sqlx::query(
        "SELECT id, bridge_id, direction, delivery_id, event_type, status, http_status, created_at \
         FROM bridge_deliveries WHERE tenant_id = $1 AND bridge_id = $2 \
         ORDER BY created_at DESC LIMIT 50",
    )
    .bind(tenant.0)
    .bind(bridge_id)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;

    Ok(rows
        .iter()
        .map(|r| DeliveryView {
            id: r.get("id"),
            bridge_id: r.get("bridge_id"),
            direction: r.get("direction"),
            delivery_id: r.get("delivery_id"),
            event_type: r.get("event_type"),
            status: r.get("status"),
            http_status: r.get("http_status"),
            created_at: fmt_ts(r.get("created_at")),
        })
        .collect())
}
