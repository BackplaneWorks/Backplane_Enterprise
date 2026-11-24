//! Outbound event delivery via `SafeHttp` (HTTPS-only, DNS-rebind & SSRF guarded).

use crate::adapters::{adapter_for, OutboundHttpPayload};
use crate::model::{BridgeEvent, DeliveryView};
use crate::sealed;
use crate::store::{self, LoadedBridge};
use async_trait::async_trait;
use bp_ent_core::{audit, AppCtx, Error, Result, TenantId};
use serde_json::json;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

#[async_trait]
pub trait OutboundTransport: Send + Sync {
    async fn send(&self, url: &str, payload: &OutboundHttpPayload) -> Result<u16>;
}

/// Production transport backed strictly by `bp_ent_core::SafeHttp`.
pub struct SafeHttpTransport {
    pub http: bp_ent_core::SafeHttp,
}

#[async_trait]
impl OutboundTransport for SafeHttpTransport {
    async fn send(&self, url: &str, payload: &OutboundHttpPayload) -> Result<u16> {
        let mut req = self.http.post(url)?;
        for (k, v) in &payload.headers {
            req = req.header(k.as_str(), v.as_str());
        }
        req = req.body(payload.body.clone());
        let (status, _) = self.http.fetch(req, 64 * 1024).await?;
        Ok(status.as_u16())
    }
}

pub async fn dispatch_to_bridge_with<T: OutboundTransport>(
    ctx: &AppCtx,
    transport: &T,
    tenant: TenantId,
    bridge_id: Uuid,
    event: &BridgeEvent,
) -> Result<DeliveryView> {
    let mut tx = ctx.db.tenant_tx(tenant).await?;
    let bridge = store::load_bridge(ctx, &mut tx, tenant, bridge_id)
        .await?
        .ok_or(Error::NotFound)?;
    tx.commit().await?;

    if !bridge.enabled || !bridge.direction.allows_outbound() {
        return Err(Error::invalid("bridge is disabled or does not allow outbound delivery"));
    }
    deliver_one(ctx, transport, &bridge, event).await
}

pub async fn dispatch_event(
    ctx: &AppCtx,
    tenant: TenantId,
    event: &BridgeEvent,
) -> Result<Vec<DeliveryView>> {
    let transport = SafeHttpTransport {
        http: ctx.http.clone(),
    };
    dispatch_event_with(ctx, &transport, tenant, event).await
}

pub async fn dispatch_event_with<T: OutboundTransport>(
    ctx: &AppCtx,
    transport: &T,
    tenant: TenantId,
    event: &BridgeEvent,
) -> Result<Vec<DeliveryView>> {
    let mut tx = ctx.db.tenant_tx(tenant).await?;
    let subscribers = store::load_outbound_subscribers(ctx, &mut tx, tenant, event.kind()).await?;
    tx.commit().await?;

    let mut results = Vec::with_capacity(subscribers.len());
    for bridge in &subscribers {
        results.push(deliver_one(ctx, transport, bridge, event).await?);
    }
    Ok(results)
}

async fn deliver_one<T: OutboundTransport>(
    ctx: &AppCtx,
    transport: &T,
    bridge: &LoadedBridge,
    event: &BridgeEvent,
) -> Result<DeliveryView> {
    let url = bridge
        .target_url
        .as_deref()
        .ok_or_else(|| Error::invalid("bridge has no targetUrl configured"))?;
    // Re-check URL before dispatch as defense-in-depth.
    ctx.http.check_url(url)?;

    let delivery_row_id = Uuid::new_v4();
    let delivery_id = format!("bpd_{}", delivery_row_id.simple());
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let adapter = adapter_for(bridge.kind);
    let payload = adapter.format_outbound(
        event,
        &delivery_id,
        bridge.outbound_secret.as_deref(),
        &bridge.adapter_config,
        now,
    )?;

    let (status_str, http_status) = match transport.send(url, &payload).await {
        Ok(code) if (200..300).contains(&code) => ("delivered", Some(code as i16)),
        Ok(code) => ("failed", Some(code as i16)),
        Err(_) => ("failed", None),
    };

    let sealed_payload = sealed::seal_json(
        ctx,
        bridge.tenant_id,
        &sealed::aad("bridge_deliveries", delivery_row_id, "payload"),
        &json!({ "event": event, "deliveryId": delivery_id }),
    )
    .await?;

    let mut tx = ctx.db.tenant_tx(bridge.tenant_id).await?;
    let row = sqlx::query(
        "INSERT INTO bridge_deliveries (id, tenant_id, bridge_id, direction, delivery_id, event_type, status, http_status, payload_sealed) \
         VALUES ($1, $2, $3, 'outbound', $4, $5, $6, $7, $8) \
         RETURNING created_at",
    )
    .bind(delivery_row_id)
    .bind(bridge.tenant_id.0)
    .bind(bridge.id)
    .bind(&delivery_id)
    .bind(event.kind().as_str())
    .bind(status_str)
    .bind(http_status)
    .bind(&sealed_payload)
    .execute(&mut *tx)
    .await;

    // Fetch created_at cleanly via query_one.
    let _ = row?;
    let created_at: OffsetDateTime = sqlx::query_scalar(
        "SELECT created_at FROM bridge_deliveries WHERE tenant_id = $1 AND id = $2",
    )
    .bind(bridge.tenant_id.0)
    .bind(delivery_row_id)
    .fetch_one(&mut *tx)
    .await?;

    audit::append_system(
        &mut tx,
        bridge.tenant_id,
        "bridge_outbound",
        if status_str == "delivered" {
            "bridge.outbound.delivered"
        } else {
            "bridge.outbound.failed"
        },
        &format!("bridge:{}", bridge.id),
        json!({
            "deliveryId": delivery_id,
            "eventType": event.kind().as_str(),
            "status": status_str,
            "httpStatus": http_status,
        }),
    )
    .await?;
    tx.commit().await?;

    Ok(DeliveryView {
        id: delivery_row_id,
        bridge_id: bridge.id,
        direction: "outbound".to_string(),
        delivery_id,
        event_type: event.kind().as_str().to_string(),
        status: status_str.to_string(),
        http_status,
        created_at: created_at
            .format(&Rfc3339)
            .unwrap_or_else(|_| created_at.unix_timestamp().to_string()),
    })
}
