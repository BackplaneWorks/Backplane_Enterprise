//! Stripe billing: seat subscriptions, the billing portal, order payments,
//! Boat VM usage metering and the webhook that confirms all of it.
//!
//! The webhook is the only unauthenticated entry point in this crate. Its
//! rules: verify the signature over the raw bytes first; take the tenant only
//! from metadata we ourselves put on the Stripe object (it is inside the
//! signed payload); process each event id once; and for an order payment,
//! re-check the session id, amount and currency against what we stored when
//! the checkout was opened before the order is placed.

use crate::model::CheckoutResponse;
use crate::orders::{self, TransitionMeta, TransitionOutcome};
use crate::status::{OrderStatus, Source};
use crate::stripe::client::{Checkout, CheckoutParams, StripeClient, StripeError};
use crate::stripe::webhook::{verify_signature, SignatureError, DEFAULT_TOLERANCE_SECS};
use crate::Svc;
use bp_ent_core::{audit, Error, Permission, Principal, Result, TenantId, Tx};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::Row;
use subtle::ConstantTimeEq;
use time::OffsetDateTime;
use uuid::Uuid;

fn stripe(svc: &Svc) -> Result<&StripeClient> {
    svc.stripe.as_ref().ok_or_else(|| Error::conflict("billing is not configured on this server"))
}

fn stripe_err(e: StripeError) -> Error {
    match e {
        StripeError::NotConfigured => Error::conflict("billing is not configured on this server"),
        other => Error::upstream(anyhow::anyhow!("{other}")),
    }
}

/// Binds a checkout session to exactly one order, amount and currency.
pub fn payment_binding(order: Uuid, amount_cents: i64, currency: &str) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(b"bpe-order-payment-v1|");
    h.update(order.as_bytes());
    h.update(amount_cents.to_be_bytes());
    h.update(currency.to_ascii_lowercase().as_bytes());
    h.finalize().to_vec()
}

struct Account {
    customer: Option<String>,
    status: String,
    seats: i32,
    period_end: Option<OffsetDateTime>,
}

async fn account(tx: &mut Tx, tenant: TenantId) -> Result<Account> {
    let row = sqlx::query(
        "SELECT stripe_customer_id, subscription_status, seats, current_period_end \
         FROM billing_accounts WHERE tenant_id = $1",
    )
    .bind(tenant.0)
    .fetch_optional(&mut **tx)
    .await?;
    Ok(match row {
        Some(r) => Account {
            customer: r.try_get("stripe_customer_id")?,
            status: r.try_get("subscription_status")?,
            seats: r.try_get("seats")?,
            period_end: r.try_get("current_period_end")?,
        },
        None => Account { customer: None, status: "none".into(), seats: 0, period_end: None },
    })
}

/// The tenant's Stripe customer id, creating the customer on first use.
async fn ensure_customer(svc: &Svc, who: &Principal) -> Result<String> {
    let tenant = who.tenant_id;
    let mut tx = svc.ctx.db.tenant_tx(tenant).await?;
    let existing = account(&mut tx, tenant).await?.customer;
    let name: Option<String> = sqlx::query_scalar("SELECT name FROM tenants WHERE id = $1")
        .bind(tenant.0)
        .fetch_optional(&mut *tx)
        .await?;
    tx.commit().await?;
    if let Some(c) = existing {
        return Ok(c);
    }
    // Idempotent on Stripe's side (key = tenant id), so a race creates one customer.
    let customer = stripe(svc)?
        .create_customer(tenant.0, name.as_deref(), Some(&who.email))
        .await
        .map_err(stripe_err)?;
    let mut tx = svc.ctx.db.tenant_tx(tenant).await?;
    sqlx::query(
        "INSERT INTO billing_accounts (tenant_id, stripe_customer_id) VALUES ($1, $2) \
         ON CONFLICT (tenant_id) DO UPDATE SET stripe_customer_id = COALESCE(billing_accounts.stripe_customer_id, EXCLUDED.stripe_customer_id), updated_at = now()",
    )
    .bind(tenant.0)
    .bind(&customer.id)
    .execute(&mut *tx)
    .await?;
    audit::append(&mut tx, who, "billing.customer_created", "billing_account", serde_json::json!({})).await?;
    tx.commit().await?;
    Ok(customer.id)
}

fn portal_url(svc: &Svc, path: &str) -> String {
    format!("{}{}", svc.ctx.config.public_origin, path)
}

/// Start (or change) the seat subscription.
pub async fn seats_checkout(svc: &Svc, who: &Principal, seats: u32) -> Result<CheckoutResponse> {
    who.require(Permission::BillingManage)?;
    who.require_interactive()?;
    if !(1..=10_000).contains(&seats) {
        return Err(Error::invalid("seats must be between 1 and 10,000"));
    }
    let seat_price = svc
        .cfg
        .stripe_seat_price
        .as_deref()
        .ok_or_else(|| Error::conflict("billing is not configured on this server"))?;
    let customer = ensure_customer(svc, who).await?;
    let back = portal_url(svc, "/admin/billing");
    let session = stripe(svc)?
        .create_checkout(CheckoutParams {
            tenant_id: who.tenant_id.0,
            customer: &customer,
            success_url: &back,
            cancel_url: &back,
            idempotency_key: &format!("bpe-seats-{}-{}-{}", who.tenant_id, seats, OffsetDateTime::now_utc().unix_timestamp() / 600),
            what: Checkout::Subscription { seat_price, seats, vm_hour_price: svc.cfg.stripe_vm_price.as_deref() },
        })
        .await
        .map_err(stripe_err)?;
    let url = session.url.ok_or_else(|| Error::upstream(anyhow::anyhow!("stripe returned no checkout url")))?;
    let mut tx = svc.ctx.db.tenant_tx(who.tenant_id).await?;
    audit::append(&mut tx, who, "billing.seats_checkout_started", "billing_account", serde_json::json!({ "seats": seats })).await?;
    tx.commit().await?;
    Ok(CheckoutResponse { checkout_url: url })
}

pub async fn billing_portal(svc: &Svc, who: &Principal) -> Result<CheckoutResponse> {
    who.require(Permission::BillingManage)?;
    who.require_interactive()?;
    let customer = ensure_customer(svc, who).await?;
    let session = stripe(svc)?
        .create_portal_session(&customer, &portal_url(svc, "/admin/billing"), &format!("bpe-portal-{}", Uuid::new_v4()))
        .await
        .map_err(stripe_err)?;
    Ok(CheckoutResponse { checkout_url: session.url })
}

/// Open Stripe Checkout for an approved order that needs payment.
pub async fn order_checkout(svc: &Svc, who: &Principal, order_id: Uuid) -> Result<CheckoutResponse> {
    who.require(Permission::OrdersApprove)?;
    who.require_interactive()?;
    let tenant = who.tenant_id;
    let mut tx = svc.ctx.db.tenant_tx(tenant).await?;
    let order = orders::load(&mut tx, tenant, order_id, false).await?;
    tx.commit().await?;
    let payload = orders::open_payload(svc, tenant, &order).await?;
    // Payment is only taken for an order that has passed approval.
    if order.status != OrderStatus::PendingApproval || order.approved_by.is_none() || order.payment_state != "pending" {
        return Err(Error::conflict("the order must be approved and awaiting payment"));
    }
    if payload.total_cents <= 0 {
        return Err(Error::conflict("the order has no amount to pay"));
    }
    let customer = ensure_customer(svc, who).await?;
    let back = portal_url(svc, "/purchasing");
    let session = stripe(svc)?
        .create_checkout(CheckoutParams {
            tenant_id: tenant.0,
            customer: &customer,
            success_url: &back,
            cancel_url: &back,
            // Version in the key: an edited order gets a fresh session.
            idempotency_key: &format!("bpe-order-{}-{}", order_id, order.version),
            what: Checkout::OrderPayment {
                amount_cents: payload.total_cents,
                currency: &payload.currency,
                order_ref: &order.order_ref,
                order_id,
            },
        })
        .await
        .map_err(stripe_err)?;
    let url = session.url.ok_or_else(|| Error::upstream(anyhow::anyhow!("stripe returned no checkout url")))?;
    let mut tx = svc.ctx.db.tenant_tx(tenant).await?;
    let n = sqlx::query(
        "UPDATE orders SET stripe_session_id = $3, payment_binding = $4 \
         WHERE tenant_id = $1 AND id = $2 AND status = 'pending_approval' AND payment_state = 'pending' AND version = $5",
    )
    .bind(tenant.0)
    .bind(order_id)
    .bind(&session.id)
    .bind(payment_binding(order_id, payload.total_cents, &payload.currency))
    .bind(order.version)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if n != 1 {
        return Err(Error::conflict("the order changed while checkout was being opened; try again"));
    }
    audit::append(&mut tx, who, "order.payment_started", &format!("order:{order_id}"), serde_json::json!({})).await?;
    tx.commit().await?;
    Ok(CheckoutResponse { checkout_url: url })
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BillingSummary {
    pub plan_name: String,
    pub seats_active: i64,
    pub seats_included: i32,
    pub vm_hours_this_cycle: f64,
    pub estimated_invoice_usd: f64,
    pub stripe_customer_linked: bool,
    pub subscription_status: String,
    #[serde(with = "time::serde::rfc3339::option")]
    pub current_period_end: Option<OffsetDateTime>,
}

pub async fn summary(svc: &Svc, who: &Principal) -> Result<BillingSummary> {
    who.require(Permission::BillingManage)?;
    let tenant = who.tenant_id;
    let mut tx = svc.ctx.db.tenant_tx(tenant).await?;
    let acct = account(&mut tx, tenant).await?;
    let seats_active: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE tenant_id = $1 AND status = 'active'")
        .bind(tenant.0)
        .fetch_one(&mut *tx)
        .await?;
    let vm_seconds: i64 = sqlx::query_scalar(
        "SELECT COALESCE(sum(seconds), 0)::bigint FROM usage_meter_events \
         WHERE tenant_id = $1 AND stopped_at >= date_trunc('month', now())",
    )
    .bind(tenant.0)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    let vm_hours = vm_seconds as f64 / 3600.0;
    let billed_seats = i64::from(acct.seats).max(seats_active);
    let cents = billed_seats * svc.cfg.seat_price_cents + (vm_hours * svc.cfg.vm_hour_price_cents as f64).round() as i64;
    Ok(BillingSummary {
        plan_name: svc.cfg.plan_name.clone(),
        seats_active,
        seats_included: acct.seats,
        vm_hours_this_cycle: (vm_hours * 100.0).round() / 100.0,
        estimated_invoice_usd: cents as f64 / 100.0,
        stripe_customer_linked: acct.customer.is_some(),
        subscription_status: acct.status,
        current_period_end: acct.period_end,
    })
}

// ------------------------------------------------------------- metering

/// One finished Boat VM run, as reported by the relay.
#[derive(Debug, Clone)]
pub struct VmUsage {
    pub vm_id: Uuid,
    pub started_at: OffsetDateTime,
    pub stopped_at: OffsetDateTime,
    /// Unique per run; a repeat is ignored.
    pub idempotency_key: String,
}

/// Record a VM run for billing, inside the caller's tenant transaction.
/// Returns `false` if this run was already recorded.
pub async fn record_vm_usage(tx: &mut Tx, tenant: TenantId, u: &VmUsage) -> Result<bool> {
    let key_ok = (8..=100).contains(&u.idempotency_key.len())
        && u.idempotency_key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b':');
    if !key_ok || u.stopped_at < u.started_at {
        return Err(Error::invalid("invalid usage record"));
    }
    let seconds = (u.stopped_at - u.started_at).whole_seconds();
    let n = sqlx::query(
        "INSERT INTO usage_meter_events (tenant_id, idempotency_key, vm_id, started_at, stopped_at, seconds) \
         VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (tenant_id, idempotency_key) DO NOTHING",
    )
    .bind(tenant.0)
    .bind(&u.idempotency_key)
    .bind(u.vm_id)
    .bind(u.started_at)
    .bind(u.stopped_at)
    .bind(seconds)
    .execute(&mut **tx)
    .await?
    .rows_affected();
    Ok(n == 1)
}

/// [`record_vm_usage`] in its own tenant transaction, for callers that are
/// not inside one (the relay's usage sink).
pub async fn record_vm_usage_for(svc: &Svc, tenant: TenantId, u: &VmUsage) -> Result<bool> {
    let mut tx = svc.ctx.db.tenant_tx(tenant).await?;
    let fresh = record_vm_usage(&mut tx, tenant, u).await?;
    tx.commit().await?;
    Ok(fresh)
}

/// Whole minutes billed for a run: rounded up, so a short run is not free.
pub fn billable_minutes(seconds: i64) -> u64 {
    (seconds.max(0) as u64).div_ceil(60)
}

/// Report unreported VM usage to Stripe as meter events. Safe to run from
/// several workers and to repeat: the Stripe identifier is the run's key.
pub async fn flush_usage(svc: &Svc, tenant: TenantId) -> Result<usize> {
    let Some(client) = svc.stripe.as_ref() else { return Ok(0) };
    let mut tx = svc.ctx.db.tenant_tx(tenant).await?;
    let customer = account(&mut tx, tenant).await?.customer;
    let rows = sqlx::query(
        "SELECT idempotency_key, seconds, stopped_at FROM usage_meter_events \
         WHERE tenant_id = $1 AND reported_at IS NULL ORDER BY created_at LIMIT 200",
    )
    .bind(tenant.0)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    // No customer yet: keep the usage, report it once billing is set up.
    let Some(customer) = customer else { return Ok(0) };
    let mut sent = 0;
    for r in rows {
        let key: String = r.try_get("idempotency_key")?;
        let seconds: i64 = r.try_get("seconds")?;
        let stopped: OffsetDateTime = r.try_get("stopped_at")?;
        let minutes = billable_minutes(seconds);
        if minutes > 0 {
            let identifier = format!("{}:{}", tenant.0.simple(), key);
            client
                .meter_event(&svc.cfg.stripe_vm_meter_event, &customer, minutes, &identifier, stopped.unix_timestamp())
                .await
                .map_err(stripe_err)?;
        }
        let mut tx = svc.ctx.db.tenant_tx(tenant).await?;
        sqlx::query("UPDATE usage_meter_events SET reported_at = now() WHERE tenant_id = $1 AND idempotency_key = $2")
            .bind(tenant.0)
            .bind(&key)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        sent += 1;
    }
    Ok(sent)
}

/// Flush usage for every tenant. For the API's scheduler.
pub async fn flush_all_usage(svc: &Svc) -> Result<usize> {
    let mut total = 0;
    for tenant in svc.ctx.db.all_tenants().await? {
        match flush_usage(svc, tenant).await {
            Ok(n) => total += n,
            Err(e) => tracing::warn!(%tenant, code = e.code(), "usage metering failed"),
        }
    }
    Ok(total)
}

// -------------------------------------------------------------- webhook

/// What the webhook did, for the HTTP layer and for tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebhookOutcome {
    Processed,
    /// Seen before: acknowledged, nothing done.
    Duplicate,
    /// Valid signature, but not for us (no tenant metadata, unknown tenant,
    /// event type we do not use, or facts that do not match our records).
    Ignored,
}

#[derive(Debug, thiserror::Error)]
pub enum WebhookError {
    #[error("webhook is not configured")]
    NotConfigured,
    #[error("bad signature")]
    Signature(#[from] SignatureError),
    #[error("malformed event")]
    Malformed,
    #[error(transparent)]
    Internal(#[from] Error),
}

fn s<'a>(v: &'a serde_json::Value, path: &[&str]) -> Option<&'a str> {
    path.iter().try_fold(v, |acc, k| acc.get(k))?.as_str()
}

/// The tenant an event is about: only ever from metadata we set ourselves.
fn event_tenant(obj: &serde_json::Value) -> Option<TenantId> {
    [
        &["metadata", "tenant_id"][..],
        &["subscription_details", "metadata", "tenant_id"][..],
        &["parent", "subscription_details", "metadata", "tenant_id"][..],
    ]
    .iter()
    .find_map(|p| s(obj, p))
    .and_then(|t| Uuid::parse_str(t).ok())
    .map(TenantId)
}

fn subscription_status(raw: &str) -> &'static str {
    match raw {
        "incomplete" => "incomplete",
        "trialing" => "trialing",
        "active" => "active",
        "past_due" => "past_due",
        "unpaid" => "unpaid",
        "paused" => "paused",
        "canceled" | "incomplete_expired" => "canceled",
        _ => "none",
    }
}

/// Verify and process one Stripe webhook delivery. `now` is unix seconds.
pub async fn handle_webhook(svc: &Svc, signature: &str, body: &[u8], now: i64) -> std::result::Result<WebhookOutcome, WebhookError> {
    let secret = svc.cfg.stripe_webhook_secret.as_ref().ok_or(WebhookError::NotConfigured)?;
    verify_signature(secret.expose().as_bytes(), signature, body, now, DEFAULT_TOLERANCE_SECS)?;

    let event: serde_json::Value = serde_json::from_slice(body).map_err(|_| WebhookError::Malformed)?;
    let (Some(event_id), Some(kind)) = (s(&event, &["id"]), s(&event, &["type"])) else {
        return Err(WebhookError::Malformed);
    };
    if event_id.len() > 255 || kind.len() > 255 {
        return Err(WebhookError::Malformed);
    }
    let obj = event.get("data").and_then(|d| d.get("object")).ok_or(WebhookError::Malformed)?;
    let Some(tenant) = event_tenant(obj) else {
        return Ok(WebhookOutcome::Ignored);
    };

    let mut tx = svc.ctx.db.tenant_tx(tenant).await?;
    // Replay guard, in the same transaction as the effect: either both
    // commit or neither does, so a failed attempt can be retried by Stripe.
    let first = sqlx::query(
        "INSERT INTO stripe_events (tenant_id, event_id, event_type) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
    )
    .bind(tenant.0)
    .bind(event_id)
    .bind(kind)
    .execute(&mut *tx)
    .await;
    match first {
        Ok(r) if r.rows_affected() == 1 => {}
        Ok(_) => return Ok(WebhookOutcome::Duplicate),
        // Foreign key: no such tenant (deleted, or metadata from elsewhere).
        Err(sqlx::Error::Database(e)) if matches!(e.code().as_deref(), Some("23503") | Some("42501")) => {
            return Ok(WebhookOutcome::Ignored)
        }
        Err(e) => return Err(WebhookError::Internal(e.into())),
    }

    let outcome = match kind {
        "checkout.session.completed" | "checkout.session.async_payment_succeeded" => match s(obj, &["metadata", "purpose"]) {
            Some("order") => order_paid(&mut tx, tenant, obj).await?,
            Some("seats") => seats_started(&mut tx, tenant, obj).await?,
            _ => WebhookOutcome::Ignored,
        },
        "customer.subscription.created" | "customer.subscription.updated" | "customer.subscription.deleted" => {
            subscription_changed(&mut tx, tenant, obj, kind.ends_with("deleted")).await?
        }
        _ => WebhookOutcome::Ignored,
    };
    tx.commit().await.map_err(|e| WebhookError::Internal(e.into()))?;
    Ok(outcome)
}

async fn order_paid(tx: &mut Tx, tenant: TenantId, obj: &serde_json::Value) -> Result<WebhookOutcome> {
    let ignored = |why: &'static str| {
        tracing::warn!(%tenant, why, "stripe order payment event ignored");
        Ok(WebhookOutcome::Ignored)
    };
    if s(obj, &["payment_status"]) != Some("paid") {
        return Ok(WebhookOutcome::Ignored); // e.g. async payment still pending
    }
    let (Some(session_id), Some(order_id), Some(amount), Some(currency)) = (
        s(obj, &["id"]),
        s(obj, &["metadata", "order_id"]).and_then(|o| Uuid::parse_str(o).ok()),
        obj.get("amount_total").and_then(serde_json::Value::as_i64),
        s(obj, &["currency"]),
    ) else {
        return ignored("incomplete session");
    };
    let order = match orders::load(tx, tenant, order_id, true).await {
        Ok(o) => o,
        Err(Error::NotFound) => return ignored("unknown order"),
        Err(e) => return Err(e),
    };
    // The session must be the one we opened for this order, for this amount.
    let session_ok = order.stripe_session_id.as_deref() == Some(session_id);
    let binding_ok = order
        .payment_binding
        .as_deref()
        .is_some_and(|b| bool::from(b.ct_eq(&payment_binding(order_id, amount, currency))));
    if !session_ok || !binding_ok {
        return ignored("session or amount does not match the order");
    }
    if order.approved_by.is_none() {
        return ignored("order is not approved");
    }
    let meta = TransitionMeta { mark_paid: true, ..Default::default() };
    match orders::apply_transition(tx, tenant, &order, OrderStatus::Ordered, Source::Payment, meta).await {
        Ok(()) => {}
        // Paid, but the order moved (cancelled / on hold) meanwhile. Record
        // the payment; a person resolves it (refund or resume).
        Err(TransitionOutcome::Refused(_)) => {
            sqlx::query("UPDATE orders SET payment_state = 'paid', version = version + 1, updated_at = now() WHERE tenant_id = $1 AND id = $2")
                .bind(tenant.0)
                .bind(order_id)
                .execute(&mut **tx)
                .await?;
            audit::append_system(tx, tenant, "stripe-webhook", "order.paid_not_placed", &format!("order:{order_id}"), serde_json::json!({ "status": order.status })).await?;
            return Ok(WebhookOutcome::Processed);
        }
        Err(TransitionOutcome::Failed(e)) => return Err(e),
    }
    audit::append_system(tx, tenant, "stripe-webhook", "order.paid_and_placed", &format!("order:{order_id}"), serde_json::json!({ "from": order.status })).await?;
    Ok(WebhookOutcome::Processed)
}

/// The Stripe customer must be the one on file for this tenant.
async fn customer_matches(tx: &mut Tx, tenant: TenantId, obj: &serde_json::Value) -> Result<bool> {
    let on_file = account(tx, tenant).await?.customer;
    Ok(matches!((on_file.as_deref(), s(obj, &["customer"])), (Some(a), Some(b)) if a == b))
}

async fn seats_started(tx: &mut Tx, tenant: TenantId, obj: &serde_json::Value) -> Result<WebhookOutcome> {
    if !customer_matches(tx, tenant, obj).await? {
        tracing::warn!(%tenant, "stripe subscription event for a customer not on file; ignored");
        return Ok(WebhookOutcome::Ignored);
    }
    sqlx::query(
        "UPDATE billing_accounts SET stripe_subscription_id = COALESCE($2, stripe_subscription_id), \
           subscription_status = CASE WHEN subscription_status IN ('none', 'canceled', 'incomplete') THEN 'active' ELSE subscription_status END, \
           updated_at = now() WHERE tenant_id = $1",
    )
    .bind(tenant.0)
    .bind(s(obj, &["subscription"]))
    .execute(&mut **tx)
    .await?;
    audit::append_system(tx, tenant, "stripe-webhook", "billing.subscription_started", "billing_account", serde_json::json!({})).await?;
    Ok(WebhookOutcome::Processed)
}

async fn subscription_changed(tx: &mut Tx, tenant: TenantId, obj: &serde_json::Value, deleted: bool) -> Result<WebhookOutcome> {
    if !customer_matches(tx, tenant, obj).await? {
        tracing::warn!(%tenant, "stripe subscription event for a customer not on file; ignored");
        return Ok(WebhookOutcome::Ignored);
    }
    let status = if deleted { "canceled" } else { subscription_status(s(obj, &["status"]).unwrap_or("")) };
    let items = obj.get("items").and_then(|i| i.get("data")).and_then(serde_json::Value::as_array);
    // The seat line is the licensed one: it has a quantity (metered lines do not).
    let seats = items
        .into_iter()
        .flatten()
        .filter_map(|it| it.get("quantity").and_then(serde_json::Value::as_i64))
        .max()
        .unwrap_or(0)
        .clamp(0, 1_000_000) as i32;
    let period_end = obj
        .get("current_period_end")
        .or_else(|| items.and_then(|a| a.first()).and_then(|it| it.get("current_period_end")))
        .and_then(serde_json::Value::as_i64)
        .and_then(|t| OffsetDateTime::from_unix_timestamp(t).ok());
    sqlx::query(
        "UPDATE billing_accounts SET stripe_subscription_id = $2, subscription_status = $3, seats = $4, \
           current_period_end = $5, updated_at = now() WHERE tenant_id = $1",
    )
    .bind(tenant.0)
    .bind(s(obj, &["id"]))
    .bind(status)
    .bind(if deleted { 0 } else { seats })
    .bind(period_end)
    .execute(&mut **tx)
    .await?;
    audit::append_system(tx, tenant, "stripe-webhook", "billing.subscription_changed", "billing_account", serde_json::json!({ "status": status, "seats": seats })).await?;
    Ok(WebhookOutcome::Processed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payment_binding_covers_order_amount_and_currency() {
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let base = payment_binding(a, 1000, "usd");
        assert_eq!(base, payment_binding(a, 1000, "USD"));
        assert_ne!(base, payment_binding(b, 1000, "usd"));
        assert_ne!(base, payment_binding(a, 1001, "usd"));
        assert_ne!(base, payment_binding(a, 1000, "eur"));
    }

    #[test]
    fn minutes_round_up() {
        assert_eq!(billable_minutes(0), 0);
        assert_eq!(billable_minutes(1), 1);
        assert_eq!(billable_minutes(60), 1);
        assert_eq!(billable_minutes(61), 2);
        assert_eq!(billable_minutes(-5), 0);
    }

    #[test]
    fn tenant_only_from_our_metadata() {
        let t = Uuid::new_v4();
        let direct = serde_json::json!({ "metadata": { "tenant_id": t.to_string() }, "client_reference_id": Uuid::new_v4().to_string() });
        assert_eq!(event_tenant(&direct), Some(TenantId(t)));
        let invoice = serde_json::json!({ "parent": { "subscription_details": { "metadata": { "tenant_id": t.to_string() } } } });
        assert_eq!(event_tenant(&invoice), Some(TenantId(t)));
        // Customer-editable or unrelated fields are never consulted.
        for v in [
            serde_json::json!({ "client_reference_id": t.to_string() }),
            serde_json::json!({ "customer_details": { "name": t.to_string() } }),
            serde_json::json!({ "metadata": { "tenant_id": "not-a-uuid" } }),
            serde_json::json!({ "metadata": { "tenant_id": 7 } }),
        ] {
            assert_eq!(event_tenant(&v), None, "{v}");
        }
    }

    #[test]
    fn unknown_subscription_status_is_not_active() {
        assert_eq!(subscription_status("active"), "active");
        assert_eq!(subscription_status("incomplete_expired"), "canceled");
        assert_eq!(subscription_status("something_new"), "none");
    }
}
