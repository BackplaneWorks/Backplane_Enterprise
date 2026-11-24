//! Mailbox connections, order mail ingestion and customer notifications.
//!
//! Trust rules for inbound mail, in one place:
//!
//! 1. A message is kept only if it names exactly one of this tenant's order
//!    references. Unrelated mail in the mailbox is never stored.
//! 2. It is stored as sanitised plain text, sealed, with attachment names
//!    only. Nothing in it is rendered, executed or sent to an LLM.
//! 3. The parser yields a *proposal*. It is applied automatically only when
//!    the sender's domain is the order's vendor domain, the mailbox provider
//!    itself reports DMARC pass for that domain, the parser is confident,
//!    and the state machine allows the step for `Source::Mail` (fulfilment
//!    progress of an already placed order, nothing else).
//! 4. Anything short of that waits for a person, who applies it with their
//!    own `OrdersWrite` permission.

use crate::mail::google::Gmail;
use crate::mail::microsoft::Graph;
use crate::mail::notify::{status_notice, StatusNotice};
use crate::mail::oauth::{self, OAuthClient};
use crate::mail::parser::{self, Confidence, Signal, Tracking};
use crate::mail::ses::Ses;
use crate::mail::{AttachmentMeta, InboundMessage, Mailbox, OutboundMessage, Provider, MAX_MESSAGES_PER_SYNC};
use crate::net::{Base, NetError};
use crate::orders::{self, TransitionMeta, TransitionOutcome};
use crate::sealed::{aad, open_json, seal_json};
use crate::status::{OrderStatus, Source};
use crate::Svc;
use bp_ent_core::{audit, Error, Permission, Principal, Result, Secret, TenantId};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

const STATE_TTL_MINUTES: i64 = 10;

/// The sealed content of a ledger message.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct MailContent {
    from: String,
    to: String,
    subject: String,
    text: String,
    tracking: Option<Tracking>,
    attachments: Vec<AttachmentMeta>,
}

fn upstream(e: NetError) -> Error {
    match e {
        NetError::Unauthorized => Error::conflict("the mailbox needs to be reconnected"),
        other => Error::upstream(anyhow::anyhow!("mail provider: {other}")),
    }
}

fn oauth_client(svc: &Svc, provider: Provider) -> Result<OAuthClient> {
    let cfg = &svc.cfg;
    let missing = || Error::conflict("this mail provider is not configured on the server");
    let mut c = match provider {
        Provider::Google => OAuthClient::google(
            cfg.google_client_id.clone().ok_or_else(missing)?,
            cfg.google_client_secret.clone().ok_or_else(missing)?,
        ),
        Provider::Microsoft => OAuthClient::microsoft(
            cfg.microsoft_client_id.clone().ok_or_else(missing)?,
            cfg.microsoft_client_secret.clone().ok_or_else(missing)?,
            &cfg.microsoft_tenant,
        ),
    };
    let base_override = match provider {
        Provider::Google => cfg.google_token_base.as_deref(),
        Provider::Microsoft => cfg.microsoft_token_base.as_deref(),
    };
    if let Some(b) = base_override {
        c.token_base = Base::new(b).map_err(|_| missing())?;
    }
    Ok(c)
}

fn mailbox_api(svc: &Svc, provider: Provider) -> Result<Box<dyn Mailbox>> {
    let bad = |_| Error::internal(anyhow::anyhow!("mail API base is not https"));
    Ok(match provider {
        Provider::Google => match svc.cfg.gmail_api_base.as_deref() {
            Some(b) => Box::new(Gmail::with_base(svc.http.clone(), Base::new(b).map_err(bad)?)),
            None => Box::new(Gmail::new(svc.http.clone())),
        },
        Provider::Microsoft => match svc.cfg.graph_api_base.as_deref() {
            Some(b) => Box::new(Graph::with_base(svc.http.clone(), Base::new(b).map_err(bad)?)),
            None => Box::new(Graph::new(svc.http.clone())),
        },
    })
}

/// Fixed, server-side redirect URI. Never taken from the request.
pub fn redirect_uri(svc: &Svc, provider: Provider) -> String {
    format!("{}/v1/mail/callback/{}", svc.ctx.config.api_base_url, provider.as_str())
}

// ------------------------------------------------------------ connecting

/// Begin connecting a mailbox: returns the provider's consent URL.
pub async fn start_connect(svc: &Svc, who: &Principal, provider: Provider) -> Result<String> {
    who.require(Permission::MailManage)?;
    who.require_interactive()?;
    let client = oauth_client(svc, provider)?;
    let tenant = who.tenant_id;
    let state = oauth::random_token();
    let verifier = oauth::random_token();
    let id = Uuid::new_v4();
    let verifier_sealed = svc
        .ctx
        .cipher
        .seal_str(tenant, aad("mail_oauth_states", id, "verifier_sealed").as_bytes(), &verifier)
        .await?;
    let mut tx = svc.ctx.db.tenant_tx(tenant).await?;
    sqlx::query("DELETE FROM mail_oauth_states WHERE tenant_id = $1 AND (expires_at < now() OR user_id = $2)")
        .bind(tenant.0)
        .bind(who.user_id.0)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO mail_oauth_states (id, tenant_id, user_id, provider, state_hash, verifier_sealed, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(id)
    .bind(tenant.0)
    .bind(who.user_id.0)
    .bind(provider.as_str())
    .bind(oauth::state_hash(&state))
    .bind(&verifier_sealed)
    .bind(OffsetDateTime::now_utc() + Duration::minutes(STATE_TTL_MINUTES))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(client.authorize_url(&redirect_uri(svc, provider), &state, &oauth::pkce_challenge(&verifier)))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectorView {
    pub id: Uuid,
    /// `gmail` | `microsoft_graph`
    pub provider: &'static str,
    pub mailbox_email: String,
    /// `connected` | `disconnected`
    pub status: &'static str,
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_synced_at: Option<OffsetDateTime>,
    pub last_error: Option<String>,
}

fn provider_label(p: Provider) -> &'static str {
    match p {
        Provider::Google => "gmail",
        Provider::Microsoft => "microsoft_graph",
    }
}

/// Finish connecting: the browser comes back with `code` and `state`.
///
/// The state is single-use, expires, and is bound to the same signed-in user
/// and tenant that started the flow, so a consent URL cannot be completed in
/// someone else's session (login CSRF) or replayed.
pub async fn finish_connect(svc: &Svc, who: &Principal, provider: Provider, code: &str, state: &str) -> Result<ConnectorView> {
    who.require(Permission::MailManage)?;
    who.require_interactive()?;
    if code.is_empty() || code.len() > 4096 || state.len() > 256 {
        return Err(Error::invalid("invalid authorisation response"));
    }
    let client = oauth_client(svc, provider)?;
    let tenant = who.tenant_id;

    let mut tx = svc.ctx.db.tenant_tx(tenant).await?;
    let row = sqlx::query(
        "DELETE FROM mail_oauth_states WHERE tenant_id = $1 AND state_hash = $2 AND user_id = $3 AND provider = $4 \
         RETURNING id, verifier_sealed, expires_at",
    )
    .bind(tenant.0)
    .bind(oauth::state_hash(state))
    .bind(who.user_id.0)
    .bind(provider.as_str())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    let row = row.ok_or_else(|| Error::invalid("this connection attempt is not valid any more; start again"))?;
    let expires: OffsetDateTime = row.try_get("expires_at")?;
    if expires < OffsetDateTime::now_utc() {
        return Err(Error::invalid("this connection attempt expired; start again"));
    }
    let state_id: Uuid = row.try_get("id")?;
    let sealed: Vec<u8> = row.try_get("verifier_sealed")?;
    let verifier = Secret::new(
        svc.ctx
            .cipher
            .open_str(tenant, aad("mail_oauth_states", state_id, "verifier_sealed").as_bytes(), &sealed)
            .await?,
    );

    let tokens = client
        .exchange_code(&svc.http, code, &redirect_uri(svc, provider), verifier.expose())
        .await
        .map_err(upstream)?;
    let refresh = tokens
        .refresh_token
        .ok_or_else(|| Error::conflict("the provider did not grant offline access; remove the app's access and connect again"))?;
    let api = mailbox_api(svc, provider)?;
    let address = api.address(tokens.access_token.expose()).await.map_err(upstream)?;

    let id = Uuid::new_v4();
    let token_sealed = svc
        .ctx
        .cipher
        .seal_str(tenant, aad("mail_connections", id, "refresh_token_sealed").as_bytes(), refresh.expose())
        .await?;
    let mut tx = svc.ctx.db.tenant_tx(tenant).await?;
    // Reconnecting the same mailbox replaces the old connection (and token).
    sqlx::query("DELETE FROM mail_connections WHERE tenant_id = $1 AND provider = $2 AND address = $3")
        .bind(tenant.0)
        .bind(provider.as_str())
        .bind(&address)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO mail_connections (id, tenant_id, provider, address, refresh_token_sealed, scopes, connected_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(id)
    .bind(tenant.0)
    .bind(provider.as_str())
    .bind(&address)
    .bind(&token_sealed)
    .bind(tokens.scope.chars().take(1000).collect::<String>())
    .bind(who.user_id.0)
    .execute(&mut *tx)
    .await?;
    audit::append(&mut tx, who, "mail.connected", &format!("mail_connection:{id}"), serde_json::json!({ "provider": provider.as_str() })).await?;
    tx.commit().await?;
    Ok(ConnectorView { id, provider: provider_label(provider), mailbox_email: address, status: "connected", last_synced_at: None, last_error: None })
}

pub async fn list_connections(svc: &Svc, who: &Principal) -> Result<Vec<ConnectorView>> {
    who.require(Permission::MailManage)?;
    let mut tx = svc.ctx.db.tenant_tx(who.tenant_id).await?;
    // The refresh token column is never selected here.
    let rows = sqlx::query(
        "SELECT id, provider, address, status, last_sync_at, last_error FROM mail_connections WHERE tenant_id = $1 ORDER BY created_at",
    )
    .bind(who.tenant_id.0)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    rows.iter()
        .map(|r| {
            let provider: String = r.try_get("provider")?;
            let status: String = r.try_get("status")?;
            Ok(ConnectorView {
                id: r.try_get("id")?,
                provider: provider_label(Provider::parse(&provider).unwrap_or(Provider::Google)),
                mailbox_email: r.try_get("address")?,
                status: if status == "active" { "connected" } else { "disconnected" },
                last_synced_at: r.try_get("last_sync_at")?,
                last_error: r.try_get("last_error")?,
            })
        })
        .collect()
}

/// Remove a connection. The sealed refresh token is deleted with the row.
pub async fn disconnect(svc: &Svc, who: &Principal, id: Uuid) -> Result<()> {
    who.require(Permission::MailManage)?;
    let mut tx = svc.ctx.db.tenant_tx(who.tenant_id).await?;
    let n = sqlx::query("DELETE FROM mail_connections WHERE tenant_id = $1 AND id = $2")
        .bind(who.tenant_id.0)
        .bind(id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(Error::NotFound);
    }
    audit::append(&mut tx, who, "mail.disconnected", &format!("mail_connection:{id}"), serde_json::json!({})).await?;
    tx.commit().await?;
    Ok(())
}

// --------------------------------------------------------------- tokens

struct Connection {
    id: Uuid,
    provider: Provider,
    address: String,
    cursor: OffsetDateTime,
    token_sealed: Vec<u8>,
}

async fn load_connection(svc: &Svc, tenant: TenantId, id: Option<Uuid>) -> Result<Option<Connection>> {
    let mut tx = svc.ctx.db.tenant_tx(tenant).await?;
    let row = sqlx::query(
        "SELECT id, provider, address, sync_cursor, refresh_token_sealed FROM mail_connections \
         WHERE tenant_id = $1 AND status = 'active' AND ($2::uuid IS NULL OR id = $2) ORDER BY created_at LIMIT 1",
    )
    .bind(tenant.0)
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    let Some(r) = row else { return Ok(None) };
    let provider: String = r.try_get("provider")?;
    Ok(Some(Connection {
        id: r.try_get("id")?,
        provider: Provider::parse(&provider).ok_or_else(|| Error::internal(anyhow::anyhow!("unknown mail provider")))?,
        address: r.try_get("address")?,
        cursor: r.try_get("sync_cursor")?,
        token_sealed: r.try_get("refresh_token_sealed")?,
    }))
}

async fn mark_error(svc: &Svc, tenant: TenantId, id: Uuid, code: &'static str, deactivate: bool) -> Result<()> {
    let mut tx = svc.ctx.db.tenant_tx(tenant).await?;
    sqlx::query(
        "UPDATE mail_connections SET last_error = $3, status = CASE WHEN $4 THEN 'error' ELSE status END \
         WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant.0)
    .bind(id)
    .bind(code)
    .bind(deactivate)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Exchange the stored refresh token for an access token. A rotated refresh
/// token (Microsoft) is re-sealed and stored.
async fn access_token(svc: &Svc, tenant: TenantId, conn: &Connection) -> Result<Secret<String>> {
    let token_aad = aad("mail_connections", conn.id, "refresh_token_sealed");
    let refresh = Secret::new(svc.ctx.cipher.open_str(tenant, token_aad.as_bytes(), &conn.token_sealed).await?);
    let client = oauth_client(svc, conn.provider)?;
    let tokens = match client.refresh(&svc.http, refresh.expose()).await {
        Ok(t) => t,
        Err(NetError::Unauthorized) => {
            mark_error(svc, tenant, conn.id, "reauthorize", true).await?;
            return Err(upstream(NetError::Unauthorized));
        }
        Err(e) => {
            mark_error(svc, tenant, conn.id, "provider_unavailable", false).await?;
            return Err(upstream(e));
        }
    };
    if let Some(rotated) = &tokens.refresh_token {
        let sealed = svc.ctx.cipher.seal_str(tenant, token_aad.as_bytes(), rotated.expose()).await?;
        let mut tx = svc.ctx.db.tenant_tx(tenant).await?;
        sqlx::query("UPDATE mail_connections SET refresh_token_sealed = $3 WHERE tenant_id = $1 AND id = $2")
            .bind(tenant.0)
            .bind(conn.id)
            .bind(&sealed)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
    }
    Ok(tokens.access_token)
}

// ----------------------------------------------------------------- sync

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncReport {
    /// Messages fetched from the provider.
    pub fetched: usize,
    /// Messages that named one of this tenant's orders and were stored.
    pub stored: usize,
    /// Status proposals applied automatically.
    pub applied: usize,
}

/// What ingestion decided for one message. Pure, so it is unit-tested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verdict {
    pub sender_verified: bool,
    pub auto_apply: bool,
}

/// Decide whether a parsed message may move its order automatically.
pub fn verdict(provider: Provider, msg: &InboundMessage, signal: &Signal, vendor_domain: Option<&str>) -> Verdict {
    let from_domain = parser::sender_domain(&msg.from);
    let sender_verified = match (from_domain.as_deref(), vendor_domain) {
        (Some(d), Some(v)) => {
            parser::domain_matches(d, v)
                && msg
                    .authentication_results
                    .as_deref()
                    .is_some_and(|ar| parser::dmarc_pass(ar, provider.trusted_authserv(), d))
        }
        _ => false,
    };
    Verdict {
        sender_verified,
        auto_apply: sender_verified && signal.status.is_some() && signal.confidence >= Confidence::Medium,
    }
}

fn kind_str(k: parser::MailKind) -> &'static str {
    match k {
        parser::MailKind::Quote => "quote",
        parser::MailKind::Confirmation => "confirmation",
        parser::MailKind::InFabrication => "in_fabrication",
        parser::MailKind::Shipping => "shipping",
        parser::MailKind::Delivery => "delivery",
        parser::MailKind::Other => "other",
    }
}

/// Store one fetched message and apply its proposal if allowed.
/// Returns `(stored, applied)`.
async fn ingest(svc: &Svc, tenant: TenantId, conn: &Connection, msg: &InboundMessage) -> Result<(bool, bool)> {
    let signal = parser::parse(&msg.subject, &msg.text);
    let Some(order_ref) = signal.order_ref.as_deref() else {
        return Ok((false, false));
    };
    let mut tx = svc.ctx.db.tenant_tx(tenant).await?;
    // Row-level security scopes this lookup: a reference belonging to another
    // tenant simply is not found.
    let Some(order) = orders::load_by_ref(&mut tx, tenant, order_ref, true).await? else {
        return Ok((false, false));
    };
    let v = verdict(conn.provider, msg, &signal, order.vendor_domain.as_deref());
    let id = Uuid::new_v4();
    let content = MailContent {
        from: msg.from.clone(),
        to: conn.address.clone(),
        subject: msg.subject.clone(),
        text: msg.text.clone(),
        tracking: signal.tracking.clone(),
        attachments: msg.attachments.clone(),
    };
    let sealed = seal_json(&svc.ctx, tenant, &aad("mail_messages", id, "sealed"), &content).await?;
    let inserted = sqlx::query(
        "INSERT INTO mail_messages (id, tenant_id, connection_id, provider_message, direction, order_id, received_at, \
           sender_verified, kind, proposed_status, confidence, sealed) \
         VALUES ($1, $2, $3, $4, 'inbound', $5, $6, $7, $8, $9, $10, $11) \
         ON CONFLICT (tenant_id, connection_id, provider_message) DO NOTHING",
    )
    .bind(id)
    .bind(tenant.0)
    .bind(conn.id)
    .bind(&msg.id)
    .bind(order.id)
    .bind(msg.received_at)
    .bind(v.sender_verified)
    .bind(kind_str(signal.kind))
    .bind(signal.status.map(OrderStatus::as_str))
    .bind(signal.confidence as i16)
    .bind(&sealed)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if inserted == 0 {
        return Ok((false, false)); // already ingested
    }

    let mut applied = false;
    if let (true, Some(to)) = (v.auto_apply, signal.status) {
        let meta = TransitionMeta { mail_message: Some(id), ..Default::default() };
        match orders::apply_transition(&mut tx, tenant, &order, to, Source::Mail, meta).await {
            Ok(()) => {
                applied = true;
                sqlx::query("UPDATE mail_messages SET applied = true WHERE tenant_id = $1 AND id = $2")
                    .bind(tenant.0)
                    .bind(id)
                    .execute(&mut *tx)
                    .await?;
                audit::append_system(
                    &mut tx,
                    tenant,
                    "mail-sync",
                    "order.status_from_mail",
                    &format!("order:{}", order.id),
                    serde_json::json!({ "from": order.status, "to": to, "message": id }),
                )
                .await?;
            }
            // The state machine refused (order not placed yet, already past
            // that step, ...): keep the message as a record, change nothing.
            Err(TransitionOutcome::Refused(_)) => {}
            Err(TransitionOutcome::Failed(e)) => return Err(e),
        }
    }
    // Tracking from a verified vendor goes onto the order; from anyone else
    // it stays inside the sealed message for a person to judge.
    if let (true, Some(t)) = (v.sender_verified, &signal.tracking) {
        let fresh = orders::load(&mut tx, tenant, order.id, true).await?;
        if fresh.status.is_placed() {
            orders::set_tracking(svc, &mut tx, tenant, &fresh, t).await?;
        }
    }
    tx.commit().await?;
    Ok((true, applied))
}

/// Pull new mail for one connection (or the tenant's first active one).
pub async fn sync_connection(svc: &Svc, tenant: TenantId, connection: Option<Uuid>) -> Result<SyncReport> {
    let conn = load_connection(svc, tenant, connection).await?.ok_or(Error::NotFound)?;
    let access = access_token(svc, tenant, &conn).await?;
    let api = mailbox_api(svc, conn.provider)?;
    // Small overlap so a message that arrived during the last pass is not
    // missed; the unique index makes re-reading harmless.
    let since = conn.cursor - Duration::minutes(5);
    let ids = match api.list_since(access.expose(), since, MAX_MESSAGES_PER_SYNC).await {
        Ok(ids) => ids,
        Err(e) => {
            mark_error(svc, tenant, conn.id, "provider_unavailable", false).await?;
            return Err(upstream(e));
        }
    };
    let mut report = SyncReport::default();
    let mut newest = conn.cursor;
    for id in ids.iter().take(MAX_MESSAGES_PER_SYNC) {
        // One bad message must not stop the rest.
        let msg = match api.fetch(access.expose(), id).await {
            Ok(m) => m,
            Err(NetError::Unauthorized) => return Err(upstream(NetError::Unauthorized)),
            Err(_) => continue,
        };
        report.fetched += 1;
        newest = newest.max(msg.received_at.min(OffsetDateTime::now_utc()));
        let (stored, applied) = ingest(svc, tenant, &conn, &msg).await?;
        report.stored += usize::from(stored);
        report.applied += usize::from(applied);
    }
    let mut tx = svc.ctx.db.tenant_tx(tenant).await?;
    sqlx::query(
        "UPDATE mail_connections SET sync_cursor = $3, last_sync_at = now(), last_error = NULL WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant.0)
    .bind(conn.id)
    .bind(newest)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(report)
}

/// Sync every active connection of every tenant. For the API's scheduler.
/// One tenant's failure is logged (without content) and does not stop the rest.
pub async fn sync_all(svc: &Svc) -> Result<SyncReport> {
    let mut total = SyncReport::default();
    for tenant in svc.ctx.db.all_tenants().await? {
        let ids: Vec<Uuid> = {
            let mut tx = svc.ctx.db.tenant_tx(tenant).await?;
            let ids = sqlx::query_scalar("SELECT id FROM mail_connections WHERE tenant_id = $1 AND status = 'active'")
                .bind(tenant.0)
                .fetch_all(&mut *tx)
                .await?;
            tx.commit().await?;
            ids
        };
        for id in ids {
            match sync_connection(svc, tenant, Some(id)).await {
                Ok(r) => {
                    total.fetched += r.fetched;
                    total.stored += r.stored;
                    total.applied += r.applied;
                }
                Err(e) => tracing::warn!(%tenant, connection = %id, code = e.code(), "mail sync failed"),
            }
        }
    }
    Ok(total)
}

// ---------------------------------------------------------------- ledger

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MailEventView {
    pub id: Uuid,
    pub order_id: Option<Uuid>,
    pub order_number: String,
    pub provider: &'static str,
    pub direction: String,
    pub sender: String,
    pub subject: String,
    /// Plain text, already sanitised; render as text only.
    pub sanitized_preview: String,
    pub kind: String,
    pub proposed_state: Option<OrderStatus>,
    /// 0..1, for display.
    pub confidence: f32,
    pub sender_verified: bool,
    pub applied: bool,
    pub tracking_number: Option<String>,
    pub attachments: Vec<AttachmentMeta>,
    #[serde(with = "time::serde::rfc3339")]
    pub received_at: OffsetDateTime,
}

pub async fn list_events(svc: &Svc, who: &Principal, order: Option<Uuid>) -> Result<Vec<MailEventView>> {
    who.require(Permission::MailManage)?;
    let tenant = who.tenant_id;
    let mut tx = svc.ctx.db.tenant_tx(tenant).await?;
    let rows = sqlx::query(
        "SELECT m.id, m.order_id, o.order_ref, c.provider, m.direction, m.kind, m.proposed_status, m.confidence, \
                m.sender_verified, m.applied, m.sealed, m.received_at \
         FROM mail_messages m \
         LEFT JOIN orders o ON o.tenant_id = m.tenant_id AND o.id = m.order_id \
         LEFT JOIN mail_connections c ON c.tenant_id = m.tenant_id AND c.id = m.connection_id \
         WHERE m.tenant_id = $1 AND ($2::uuid IS NULL OR m.order_id = $2) \
         ORDER BY m.received_at DESC LIMIT 100",
    )
    .bind(tenant.0)
    .bind(order)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let id: Uuid = r.try_get("id")?;
        let sealed: Vec<u8> = r.try_get("sealed")?;
        let c: MailContent = open_json(&svc.ctx, tenant, &aad("mail_messages", id, "sealed"), &sealed).await?;
        let provider: Option<String> = r.try_get("provider")?;
        let proposed: Option<String> = r.try_get("proposed_status")?;
        let confidence: i16 = r.try_get("confidence")?;
        out.push(MailEventView {
            id,
            order_id: r.try_get("order_id")?,
            order_number: r.try_get::<Option<String>, _>("order_ref")?.unwrap_or_default(),
            provider: provider.as_deref().and_then(Provider::parse).map_or("ses", provider_label),
            direction: r.try_get("direction")?,
            sender: c.from,
            subject: c.subject,
            sanitized_preview: c.text.chars().take(600).collect(),
            kind: r.try_get("kind")?,
            proposed_state: proposed.as_deref().and_then(OrderStatus::parse),
            confidence: [0.3, 0.6, 0.9][confidence.clamp(0, 2) as usize],
            sender_verified: r.try_get("sender_verified")?,
            applied: r.try_get("applied")?,
            tracking_number: c.tracking.map(|t| t.number),
            attachments: c.attachments,
            received_at: r.try_get("received_at")?,
        });
    }
    Ok(out)
}

/// A person accepts a message's proposed status. It is their decision and
/// their permission (`Source::User`), and still only the three fulfilment
/// statuses can ever be proposed.
pub async fn apply_event(svc: &Svc, who: &Principal, message: Uuid) -> Result<crate::model::OrderView> {
    who.require(Permission::OrdersWrite)?;
    let tenant = who.tenant_id;
    let mut tx = svc.ctx.db.tenant_tx(tenant).await?;
    let row = sqlx::query(
        "SELECT order_id, proposed_status, applied, direction, sealed FROM mail_messages WHERE tenant_id = $1 AND id = $2 FOR UPDATE",
    )
    .bind(tenant.0)
    .bind(message)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(Error::NotFound)?;
    let order_id: Option<Uuid> = row.try_get("order_id")?;
    let proposed: Option<String> = row.try_get("proposed_status")?;
    let direction: String = row.try_get("direction")?;
    if row.try_get::<bool, _>("applied")? {
        return Err(Error::conflict("this update was already applied"));
    }
    let (Some(order_id), Some(to), "inbound") = (order_id, proposed.as_deref().and_then(OrderStatus::parse), direction.as_str()) else {
        return Err(Error::conflict("this message does not propose a status change"));
    };
    let order = orders::load(&mut tx, tenant, order_id, true).await?;
    let meta = TransitionMeta { actor: Some(who.user_id.0), mail_message: Some(message), ..Default::default() };
    orders::apply_transition(&mut tx, tenant, &order, to, Source::User, meta).await?;
    sqlx::query("UPDATE mail_messages SET applied = true WHERE tenant_id = $1 AND id = $2")
        .bind(tenant.0)
        .bind(message)
        .execute(&mut *tx)
        .await?;
    let sealed: Vec<u8> = row.try_get("sealed")?;
    let content: MailContent = open_json(&svc.ctx, tenant, &aad("mail_messages", message, "sealed"), &sealed).await?;
    let fresh = orders::load(&mut tx, tenant, order_id, true).await?;
    if let Some(t) = &content.tracking {
        orders::set_tracking(svc, &mut tx, tenant, &fresh, t).await?;
    }
    audit::append(
        &mut tx,
        who,
        "order.status_from_mail_accepted",
        &format!("order:{order_id}"),
        serde_json::json!({ "from": order.status, "to": to, "message": message }),
    )
    .await?;
    let fresh = orders::load(&mut tx, tenant, order_id, false).await?;
    tx.commit().await?;
    let payload = orders::open_payload(svc, tenant, &fresh).await?;
    Ok(orders::view(&fresh, payload, None))
}

// ---------------------------------------------------------- notifications

/// Send through the tenant's connected mailbox, else SES. Returns the
/// connection used (`None` = SES).
async fn send_for_tenant(svc: &Svc, tenant: TenantId, msg: &OutboundMessage) -> Result<Option<Uuid>> {
    if let Some(conn) = load_connection(svc, tenant, None).await? {
        let access = access_token(svc, tenant, &conn).await?;
        mailbox_api(svc, conn.provider)?.send(access.expose(), msg).await.map_err(upstream)?;
        return Ok(Some(conn.id));
    }
    let ses = match (&svc.cfg.ses_region, &svc.cfg.ses_from) {
        (Some(region), Some(from)) => Ses::new(svc.http.clone(), region, from),
        _ => None,
    }
    .ok_or_else(|| Error::conflict("connect a mailbox (or configure SES) to send customer updates"))?;
    ses.send(msg).await.map_err(upstream)?;
    Ok(None)
}

/// Send the customer a status update for an order, with an optional note.
pub async fn notify_customer(svc: &Svc, who: &Principal, order_id: Uuid, note: Option<&str>) -> Result<()> {
    who.require(Permission::OrdersWrite)?;
    let tenant = who.tenant_id;
    let mut tx = svc.ctx.db.tenant_tx(tenant).await?;
    let order = orders::load(&mut tx, tenant, order_id, false).await?;
    let org_name: Option<String> = sqlx::query_scalar("SELECT name FROM tenants WHERE id = $1")
        .bind(tenant.0)
        .fetch_optional(&mut *tx)
        .await?;
    tx.commit().await?;
    let payload = orders::open_payload(svc, tenant, &order).await?;
    let to = payload
        .customer_email
        .as_deref()
        .ok_or_else(|| Error::conflict("this order has no customer e-mail address"))?;
    let msg = status_notice(&StatusNotice {
        to,
        org_name: org_name.as_deref().unwrap_or(""),
        order_ref: &order.order_ref,
        title: &payload.title,
        status: order.status,
        tracking: payload.tracking.as_ref(),
        note,
    });
    let via = send_for_tenant(svc, tenant, &msg).await?;

    let id = Uuid::new_v4();
    let content = MailContent {
        from: String::new(),
        to: msg.to.clone(),
        subject: msg.subject.clone(),
        text: msg.text.clone(),
        tracking: None,
        attachments: Vec::new(),
    };
    let sealed = seal_json(&svc.ctx, tenant, &aad("mail_messages", id, "sealed"), &content).await?;
    let mut tx = svc.ctx.db.tenant_tx(tenant).await?;
    sqlx::query(
        "INSERT INTO mail_messages (id, tenant_id, connection_id, provider_message, direction, order_id, received_at, kind, sealed) \
         VALUES ($1, $2, $3, $4, 'outbound', $5, now(), 'notification', $6)",
    )
    .bind(id)
    .bind(tenant.0)
    .bind(via)
    .bind(format!("out-{id}"))
    .bind(order_id)
    .bind(&sealed)
    .execute(&mut *tx)
    .await?;
    audit::append(&mut tx, who, "order.customer_notified", &format!("order:{order_id}"), serde_json::json!({ "status": order.status, "message": id })).await?;
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(from: &str, ar: Option<&str>) -> InboundMessage {
        InboundMessage {
            id: "m".into(),
            from: from.into(),
            subject: "Order BP-7K2M9QX4TZ has shipped".into(),
            text: String::new(),
            received_at: OffsetDateTime::UNIX_EPOCH,
            authentication_results: ar.map(Into::into),
            attachments: vec![],
        }
    }

    const PASS: &str = "mx.google.com; dkim=pass; dmarc=pass (p=REJECT) header.from=pcbfab.com";

    #[test]
    fn auto_apply_needs_vendor_domain_dmarc_and_confidence() {
        let ok = msg("Fab <orders@pcbfab.com>", Some(PASS));
        let s = parser::parse(&ok.subject, &ok.text);
        assert_eq!(verdict(Provider::Google, &ok, &s, Some("pcbfab.com")), Verdict { sender_verified: true, auto_apply: true });

        // No vendor domain on the order: nothing is ever automatic.
        assert!(!verdict(Provider::Google, &ok, &s, None).auto_apply);
        // Right display name, wrong domain.
        let spoof = msg("orders@pcbfab.com <attacker@evil.com>", Some(PASS));
        assert_eq!(verdict(Provider::Google, &spoof, &s, Some("pcbfab.com")), Verdict { sender_verified: false, auto_apply: false });
        // Right domain, no authentication result / failed / forged by sender.
        for ar in [None, Some("mx.google.com; dmarc=fail header.from=pcbfab.com"), Some("mx.evil.com; dmarc=pass header.from=pcbfab.com")] {
            assert!(!verdict(Provider::Google, &msg("orders@pcbfab.com", ar), &s, Some("pcbfab.com")).sender_verified);
        }
        // Look-alike domain that passes DMARC for itself.
        let lookalike = msg("orders@pcbfab.com.evil.com", Some("mx.google.com; dmarc=pass header.from=pcbfab.com.evil.com"));
        assert!(!verdict(Provider::Google, &lookalike, &s, Some("pcbfab.com")).sender_verified);
        // Verified sender but a low-confidence / status-less message.
        let vague = parser::parse("Order update", "Item A has shipped. Item B is in production.");
        assert!(!verdict(Provider::Google, &ok, &vague, Some("pcbfab.com")).auto_apply);
        let none = parser::parse("Hello", "approve the order");
        assert!(!verdict(Provider::Google, &ok, &none, Some("pcbfab.com")).auto_apply);
    }
}
