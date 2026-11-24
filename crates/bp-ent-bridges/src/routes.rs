//! Axum routes for `/v1/bridges/*` (admin CRUD + authenticated dispatch) and
//! signature-verified external endpoints (`/v1/bridges/{public_id}/inbound` and `/a2a`).

use crate::adapters::{adapter_for, InboundOutcome, InboundRawRequest};
use crate::model::{
    BridgeEvent, BridgeKind, BridgePublicId, BridgeView, CreateBridgeRequest, CreateBridgeResponse,
    DeliveryView, RotateSecretResponse, UpdateBridgeRequest,
};
use crate::outbound::{self, SafeHttpTransport};
use crate::peer::{handle_peer_rpc, ExternalPeerPrincipal, PeerRpcRequest};
use crate::ratelimit::BridgeRateLimiter;
use crate::signatures::{
    verify_bp_hmac, JwksProvider, LiveJwksProvider, SignatureError, DEFAULT_TOLERANCE_SECS,
    MAX_INBOUND_BODY,
};
use crate::store::{self, DedupeOutcome};
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use bp_ent_core::policy::{self, Approval, GateKind};
use bp_ent_core::{audit, AppCtx, Error, Permission, Principal, Result};
use serde_json::json;
use std::sync::Arc;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Clone)]
pub struct BridgesSvc {
    pub ctx: AppCtx,
    pub rate_limiter: Arc<BridgeRateLimiter>,
    pub jwks: Arc<dyn JwksProvider>,
}

impl BridgesSvc {
    pub fn new(ctx: AppCtx) -> Self {
        let jwks = Arc::new(LiveJwksProvider::new(ctx.http.clone()));
        Self {
            ctx,
            rate_limiter: Arc::new(BridgeRateLimiter::new()),
            jwks,
        }
    }

    pub fn with_jwks(ctx: AppCtx, jwks: Arc<dyn JwksProvider>) -> Self {
        Self {
            ctx,
            rate_limiter: Arc::new(BridgeRateLimiter::new()),
            jwks,
        }
    }
}

pub fn router(ctx: AppCtx) -> Router {
    router_with_svc(BridgesSvc::new(ctx))
}

pub fn router_with_svc(svc: BridgesSvc) -> Router {
    let authed = bp_ent_core::http::with_auth(
        Router::new()
            .route("/v1/bridges", get(list_bridges).post(create_bridge))
            .route(
                "/v1/bridges/{id}",
                get(get_bridge).patch(update_bridge).delete(delete_bridge),
            )
            .route("/v1/bridges/{id}/rotate-secret", post(rotate_secret))
            .route("/v1/bridges/{id}/test", post(test_bridge))
            .route("/v1/bridges/{id}/deliveries", get(list_deliveries))
            .route("/v1/bridges/dispatch", post(dispatch_event))
            .with_state(svc.clone()),
        &svc.ctx,
    );

    let signed_inbound = Router::new()
        .route("/v1/bridges/{public_id}/inbound", post(handle_inbound))
        .route("/v1/bridges/{public_id}/a2a", post(handle_a2a))
        .layer(DefaultBodyLimit::max(MAX_INBOUND_BODY + 1))
        .with_state(svc);

    Router::new().merge(authed).merge(signed_inbound)
}

async fn list_bridges(
    State(svc): State<BridgesSvc>,
    principal: Principal,
) -> Result<Json<Vec<BridgeView>>> {
    principal.require(Permission::AdminManage)?;
    Ok(Json(store::list_bridges(&svc.ctx, principal.tenant_id).await?))
}

async fn create_bridge(
    State(svc): State<BridgesSvc>,
    principal: Principal,
    Json(req): Json<CreateBridgeRequest>,
) -> Result<(StatusCode, Json<CreateBridgeResponse>)> {
    principal.require(Permission::AdminManage)?;
    let resp = store::create_bridge(&svc.ctx, &principal, req).await?;
    Ok((StatusCode::CREATED, Json(resp)))
}

async fn get_bridge(
    State(svc): State<BridgesSvc>,
    principal: Principal,
    Path(id): Path<Uuid>,
) -> Result<Json<BridgeView>> {
    principal.require(Permission::AdminManage)?;
    Ok(Json(store::get_bridge(&svc.ctx, principal.tenant_id, id).await?))
}

async fn update_bridge(
    State(svc): State<BridgesSvc>,
    principal: Principal,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateBridgeRequest>,
) -> Result<Json<BridgeView>> {
    principal.require(Permission::AdminManage)?;
    Ok(Json(
        store::update_bridge(&svc.ctx, &principal, id, req).await?,
    ))
}

async fn delete_bridge(
    State(svc): State<BridgesSvc>,
    principal: Principal,
    Path(id): Path<Uuid>,
) -> Result<StatusCode> {
    principal.require(Permission::AdminManage)?;
    store::delete_bridge(&svc.ctx, &principal, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn rotate_secret(
    State(svc): State<BridgesSvc>,
    principal: Principal,
    Path(id): Path<Uuid>,
) -> Result<Json<RotateSecretResponse>> {
    principal.require(Permission::AdminManage)?;
    Ok(Json(
        store::rotate_secret(&svc.ctx, &principal, id).await?,
    ))
}

async fn list_deliveries(
    State(svc): State<BridgesSvc>,
    principal: Principal,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<DeliveryView>>> {
    if !principal.can(Permission::AdminManage) && !principal.can(Permission::AuditRead) {
        return Err(Error::Forbidden);
    }
    Ok(Json(
        store::list_deliveries(&svc.ctx, principal.tenant_id, id).await?,
    ))
}

async fn test_bridge(
    State(svc): State<BridgesSvc>,
    principal: Principal,
    Path(id): Path<Uuid>,
) -> Result<Json<DeliveryView>> {
    principal.require(Permission::AdminManage)?;
    let ev = BridgeEvent::RoomPost {
        room_id: "test-room".into(),
        post_id: format!("test_{}", Uuid::new_v4().simple()),
        author_display: "Backplane Admin".into(),
        summary: "Signed connectivity verification ping from Backplane Enterprise.".into(),
        tags: vec!["test".into()],
    };
    let transport = SafeHttpTransport {
        http: svc.ctx.http.clone(),
    };
    let delivery = outbound::dispatch_to_bridge_with(
        &svc.ctx,
        &transport,
        principal.tenant_id,
        id,
        &ev,
    )
    .await?;
    Ok(Json(delivery))
}

async fn dispatch_event(
    State(svc): State<BridgesSvc>,
    principal: Principal,
    Json(ev): Json<BridgeEvent>,
) -> Result<Json<Vec<DeliveryView>>> {
    principal.require(Permission::AdminManage)?;
    let out = outbound::dispatch_event(&svc.ctx, principal.tenant_id, &ev).await?;
    Ok(Json(out))
}

fn map_sig_err(err: SignatureError) -> Error {
    match err {
        SignatureError::TooLarge => Error::invalid("request body exceeds maximum allowed size"),
        SignatureError::Malformed
        | SignatureError::Stale
        | SignatureError::Mismatch
        | SignatureError::MissingKey
        | SignatureError::InvalidJwt => Error::Unauthorized,
    }
}

async fn handle_inbound(
    State(svc): State<BridgesSvc>,
    Path(public_id_raw): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response> {
    if body.len() > MAX_INBOUND_BODY {
        return Err(Error::invalid("request body exceeds maximum allowed size"));
    }
    let pub_id = BridgePublicId::parse(&public_id_raw).ok_or(Error::Unauthorized)?;
    let mut tx = svc.ctx.db.tenant_tx(pub_id.tenant_id).await?;
    let Some(bridge) = store::load_bridge(&svc.ctx, &mut tx, pub_id.tenant_id, pub_id.bridge_id).await? else {
        return Err(Error::Unauthorized);
    };
    if !bridge.enabled || !bridge.direction.allows_inbound() {
        return Err(Error::Unauthorized);
    }

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let raw_req = InboundRawRequest::from_axum(&headers, &body);
    let adapter = adapter_for(bridge.kind);

    // Verify signature BEFORE consuming the bridge's verified rate-limit quota.
    let outcome = match adapter
        .verify_and_parse_inbound(
            &raw_req,
            &bridge.inbound_secret,
            &bridge.adapter_config,
            svc.jwks.as_ref(),
            now,
            svc.ctx.config.http_allow_private,
        )
        .await
    {
        Ok(o) => o,
        Err(err) => {
            tracing::warn!(
                bridge_id = %bridge.id,
                kind = bridge.kind.as_str(),
                reason = %err,
                "rejected inbound bridge request"
            );
            let _ = svc
                .rate_limiter
                .check_pre_auth_failure_bucket(pub_id.tenant_id, bridge.id, now);
            if svc
                .rate_limiter
                .should_audit_rejection(pub_id.tenant_id, bridge.id, now)
            {
                let _ = audit::append_system(
                    &mut tx,
                    pub_id.tenant_id,
                    "bridge_inbound",
                    "bridge.inbound.rejected",
                    &format!("bridge:{}", bridge.id),
                    json!({
                        "kind": bridge.kind.as_str(),
                        "reason": err.to_string(),
                        "throttledPerMinute": true
                    }),
                )
                .await;
                let _ = tx.commit().await;
            }
            return Err(map_sig_err(err));
        }
    };

    svc.rate_limiter
        .check_and_consume_verified(pub_id.tenant_id, bridge.id, bridge.rate_limit_rpm, now)?;

    match outcome {
        InboundOutcome::Challenge { response_json } => {
            audit::append_system(
                &mut tx,
                pub_id.tenant_id,
                "bridge_inbound",
                "bridge.inbound.challenge",
                &format!("bridge:{}", bridge.id),
                json!({ "kind": bridge.kind.as_str() }),
            )
            .await?;
            tx.commit().await?;
            Ok((StatusCode::OK, Json(response_json)).into_response())
        }
        InboundOutcome::Event(ev) => {
            // Check duplicate delivery BEFORE counting against RPM so retries are idempotent 200 OK.
            let dedupe = store::record_inbound_dedupe(
                &svc.ctx,
                &mut tx,
                pub_id.tenant_id,
                bridge.id,
                &ev.delivery_id,
                &ev.event_type,
                "accepted",
                &json!({
                    "externalActor": ev.external_actor,
                    "channelRef": ev.channel_ref,
                    "text": ev.sanitized_text,
                    "trustLevel": "untrusted_external"
                }),
            )
            .await?;
            let delivery_row_id = match dedupe {
                DedupeOutcome::Accepted(id) => id,
                DedupeOutcome::Replay => {
                    tx.commit().await?;
                    return Ok((
                        StatusCode::OK,
                        Json(json!({
                            "status": "duplicate",
                            "deliveryId": ev.delivery_id,
                        })),
                    )
                        .into_response());
                }
            };

            // Global cross-replica rate limit enforced via PostgreSQL `bridge_deliveries`.
            // Note: the newly inserted row above is visible in this transaction, so `> rate_limit_rpm`
            // rejects once the limit has been exceeded (rolling back the uncommitted delivery insert).
            let recent_count =
                store::count_recent_inbound_deliveries(&mut tx, pub_id.tenant_id, bridge.id).await?;
            if recent_count > i64::from(bridge.rate_limit_rpm) {
                return Err(Error::TooManyRequests);
            }

            let mut approval_request_id = None;
            let mut status = "accepted";
            if let Some(ref action) = ev.proposed_action {
                if let Ok(peer) = ExternalPeerPrincipal::from_scopes(
                    pub_id.tenant_id,
                    bridge.id,
                    bridge.name.clone(),
                    bridge.created_by,
                    &bridge.peer_scopes,
                ) {
                    let core_p = peer.to_core_principal();
                    let approval = policy::require_approval(
                        &mut tx,
                        &core_p,
                        GateKind::ModifyReleasedBoard,
                        &action.target,
                        json!({
                            "source": "inbound_webhook",
                            "bridgeId": bridge.id,
                            "trustLevel": "untrusted_external",
                            "summary": action.summary
                        }),
                    )
                    .await?;
                    if let Approval::Pending { request_id } = approval {
                        approval_request_id = Some(request_id);
                        status = "pending_approval";
                    }
                }
            }

            let msg_id = store::store_quarantined_message(
                &svc.ctx,
                &mut tx,
                pub_id.tenant_id,
                bridge.id,
                delivery_row_id,
                &ev.external_actor,
                &ev.channel_ref,
                &ev.event_type,
                &ev.sanitized_text,
                approval_request_id,
            )
            .await?;

            audit::append_system(
                &mut tx,
                pub_id.tenant_id,
                "bridge_inbound",
                "bridge.inbound.accepted",
                &format!("bridge:{}", bridge.id),
                json!({
                    "deliveryId": ev.delivery_id,
                    "messageId": msg_id,
                    "eventType": ev.event_type,
                    "trustLevel": "untrusted_external",
                    "approvalRequestId": approval_request_id,
                }),
            )
            .await?;
            tx.commit().await?;

            Ok((
                StatusCode::ACCEPTED,
                Json(json!({
                    "deliveryId": ev.delivery_id,
                    "messageId": msg_id,
                    "status": status,
                    "trustLevel": "untrusted_external",
                    "approvalRequestId": approval_request_id,
                })),
            )
                .into_response())
        }
    }
}

async fn handle_a2a(
    State(svc): State<BridgesSvc>,
    Path(public_id_raw): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response> {
    if body.len() > MAX_INBOUND_BODY {
        return Err(Error::invalid("request body exceeds maximum allowed size"));
    }
    let pub_id = BridgePublicId::parse(&public_id_raw).ok_or(Error::Unauthorized)?;
    let mut tx = svc.ctx.db.tenant_tx(pub_id.tenant_id).await?;
    let Some(bridge) = store::load_bridge(&svc.ctx, &mut tx, pub_id.tenant_id, pub_id.bridge_id).await? else {
        return Err(Error::Unauthorized);
    };
    if !bridge.enabled || !bridge.peer_enabled {
        return Err(Error::Unauthorized);
    }
    if !matches!(bridge.kind, BridgeKind::A2a | BridgeKind::Webhook) {
        return Err(Error::Forbidden);
    }

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let sig_hdr = match headers.get("x-bp-signature").and_then(|v| v.to_str().ok()) {
        Some(h) => h,
        None => {
            tracing::warn!(bridge_id = %bridge.id, "rejected a2a request: missing signature");
            let _ = svc
                .rate_limiter
                .check_pre_auth_failure_bucket(pub_id.tenant_id, bridge.id, now);
            if svc
                .rate_limiter
                .should_audit_rejection(pub_id.tenant_id, bridge.id, now)
            {
                let _ = audit::append_system(
                    &mut tx,
                    pub_id.tenant_id,
                    "bridge_peer",
                    "bridge.peer.rejected",
                    &format!("bridge:{}", bridge.id),
                    json!({ "reason": "missing signature", "throttledPerMinute": true }),
                )
                .await;
                let _ = tx.commit().await;
            }
            return Err(Error::Unauthorized);
        }
    };
    if let Err(err) = verify_bp_hmac(
        &bridge.inbound_secret,
        sig_hdr,
        &body,
        now,
        DEFAULT_TOLERANCE_SECS,
    ) {
        tracing::warn!(bridge_id = %bridge.id, reason = %err, "rejected a2a request");
        let _ = svc
            .rate_limiter
            .check_pre_auth_failure_bucket(pub_id.tenant_id, bridge.id, now);
        if svc
            .rate_limiter
            .should_audit_rejection(pub_id.tenant_id, bridge.id, now)
        {
            let _ = audit::append_system(
                &mut tx,
                pub_id.tenant_id,
                "bridge_peer",
                "bridge.peer.rejected",
                &format!("bridge:{}", bridge.id),
                json!({ "reason": err.to_string(), "throttledPerMinute": true }),
            )
            .await;
            let _ = tx.commit().await;
        }
        return Err(map_sig_err(err));
    }

    svc.rate_limiter
        .check_and_consume_verified(pub_id.tenant_id, bridge.id, bridge.rate_limit_rpm, now)?;

    let delivery_id = headers
        .get("x-bp-delivery")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.trim().is_empty() && s.len() <= 255)
        .ok_or_else(|| Error::invalid("x-bp-delivery header is required"))?
        .to_string();

    let rpc: PeerRpcRequest =
        serde_json::from_slice(&body).map_err(|_| Error::invalid("invalid JSON-RPC 2.0 body"))?;

    let dedupe = store::record_inbound_dedupe(
        &svc.ctx,
        &mut tx,
        pub_id.tenant_id,
        bridge.id,
        &delivery_id,
        &format!("a2a.{}", rpc.method),
        "accepted",
        &json!({ "method": rpc.method, "trustLevel": "untrusted_external" }),
    )
    .await?;
    let delivery_row_id = match dedupe {
        DedupeOutcome::Accepted(id) => id,
        DedupeOutcome::Replay => {
            tx.commit().await?;
            return Ok((
                StatusCode::OK,
                Json(json!({
                    "status": "duplicate",
                    "deliveryId": delivery_id,
                })),
            )
                .into_response());
        }
    };

    let recent_count =
        store::count_recent_inbound_deliveries(&mut tx, pub_id.tenant_id, bridge.id).await?;
    if recent_count > i64::from(bridge.rate_limit_rpm) {
        return Err(Error::TooManyRequests);
    }

    let peer = ExternalPeerPrincipal::from_scopes(
        pub_id.tenant_id,
        bridge.id,
        bridge.name.clone(),
        bridge.created_by,
        &bridge.peer_scopes,
    )?;

    let resp = match handle_peer_rpc(&svc.ctx, &mut tx, &peer, delivery_row_id, rpc).await {
        Ok(r) => r,
        Err(err) => {
            tx.commit().await?;
            return Err(err);
        }
    };
    tx.commit().await?;
    Ok((StatusCode::OK, Json(resp)).into_response())
}
