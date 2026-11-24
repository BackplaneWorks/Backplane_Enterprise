//! The encrypted order ledger.
//!
//! Every query runs in a `tenant_tx` (row-level security) and, on top of
//! that, names `tenant_id` explicitly. Sensitive fields live only inside the
//! sealed payload. Status changes go through [`apply_transition`], which is
//! the single place the state machine, the version check, the event ledger
//! and the audit log meet.

use crate::mail::parser::Tracking;
use crate::model::{OrderEventView, OrderInput, OrderPayload, OrderView};
use crate::sealed::{aad, key_version, open_json, seal_json};
use crate::status::{check_transition, OrderStatus, Source, TransitionError};
use crate::Svc;
use bp_ent_core::policy::{self, Approval, GateKind};
use bp_ent_core::{audit, Error, Permission, Principal, Result, TenantId, Tx};
use rand::Rng;
use sqlx::Row;
use time::OffsetDateTime;
use uuid::Uuid;

pub const LIST_LIMIT: i64 = 200;

/// The clear-text columns of an order plus its sealed blob.
#[derive(Debug, Clone)]
pub struct OrderRow {
    pub id: Uuid,
    pub order_ref: String,
    pub status: OrderStatus,
    pub held_from: Option<OrderStatus>,
    pub vendor_domain: Option<String>,
    pub sealed: Vec<u8>,
    pub payment_state: String,
    pub stripe_session_id: Option<String>,
    pub payment_binding: Option<Vec<u8>>,
    pub created_by: Uuid,
    pub approved_by: Option<Uuid>,
    pub approval_request_id: Option<Uuid>,
    pub version: i32,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

const COLS: &str = "id, order_ref, status, held_from, vendor_domain, sealed, payment_state, \
    stripe_session_id, payment_binding, created_by, approved_by, approval_request_id, version, created_at, updated_at";

fn status_col(row: &sqlx::postgres::PgRow, col: &str) -> Result<OrderStatus> {
    let s: String = row.try_get(col)?;
    OrderStatus::parse(&s).ok_or_else(|| Error::internal(anyhow::anyhow!("unknown order status in database")))
}

fn from_row(r: &sqlx::postgres::PgRow) -> Result<OrderRow> {
    let held: Option<String> = r.try_get("held_from")?;
    Ok(OrderRow {
        id: r.try_get("id")?,
        order_ref: r.try_get("order_ref")?,
        status: status_col(r, "status")?,
        held_from: held.as_deref().and_then(OrderStatus::parse),
        vendor_domain: r.try_get("vendor_domain")?,
        sealed: r.try_get("sealed")?,
        payment_state: r.try_get("payment_state")?,
        stripe_session_id: r.try_get("stripe_session_id")?,
        payment_binding: r.try_get("payment_binding")?,
        created_by: r.try_get("created_by")?,
        approved_by: r.try_get("approved_by")?,
        approval_request_id: r.try_get("approval_request_id")?,
        version: r.try_get("version")?,
        created_at: r.try_get("created_at")?,
        updated_at: r.try_get("updated_at")?,
    })
}

pub fn order_aad(id: Uuid) -> String {
    aad("orders", id, "sealed")
}

pub fn new_order_ref() -> String {
    use crate::mail::parser::{ORDER_REF_ALPHABET, ORDER_REF_LEN};
    let mut rng = rand::rngs::OsRng;
    let body: String = (0..ORDER_REF_LEN)
        .map(|_| ORDER_REF_ALPHABET[rng.gen_range(0..ORDER_REF_ALPHABET.len())] as char)
        .collect();
    format!("BP-{body}")
}

pub fn view(row: &OrderRow, p: OrderPayload, pending_request: Option<Uuid>) -> OrderView {
    let tracking_url = p
        .tracking
        .as_ref()
        .and_then(|t| t.carrier.map(|c| c.tracking_url(&t.number)));
    OrderView {
        id: row.id,
        order_number: row.order_ref.clone(),
        title: p.title,
        board_name: p.board_name,
        quantity: p.quantity,
        currency: p.currency,
        total_cents: p.total_cents,
        state: row.status,
        fab_reference: p.vendor_reference,
        tracking_number: p.tracking.map(|t| t.number),
        tracking_url,
        envelope_key_version: key_version(&row.sealed),
        aad_binding: format!("tenant|{}", order_aad(row.id)),
        approval_required: row.status == OrderStatus::PendingApproval,
        approval_request_id: pending_request.or(row.approval_request_id.filter(|_| row.status == OrderStatus::PendingApproval)),
        payment_required: p.payment_required,
        payment_state: row.payment_state.clone(),
        vendor_name: p.vendor_name,
        vendor_domain: row.vendor_domain.clone(),
        line_items: p.line_items,
        quote_notes: p.quote_notes,
        shipping_address: p.shipping_address,
        customer_email: p.customer_email,
        created_by: row.created_by,
        approved_by: row.approved_by,
        version: row.version,
        created_at: row.created_at,
        updated_at: row.updated_at,
    }
}

pub async fn open_payload(svc: &Svc, tenant: TenantId, row: &OrderRow) -> Result<OrderPayload> {
    open_json(&svc.ctx, tenant, &order_aad(row.id), &row.sealed).await
}

/// Load one order. `lock` takes `FOR UPDATE` for read-modify-write.
pub async fn load(tx: &mut Tx, tenant: TenantId, id: Uuid, lock: bool) -> Result<OrderRow> {
    let sql = format!(
        "SELECT {COLS} FROM orders WHERE tenant_id = $1 AND id = $2{}",
        if lock { " FOR UPDATE" } else { "" }
    );
    let row = sqlx::query(&sql).bind(tenant.0).bind(id).fetch_optional(&mut **tx).await?;
    from_row(&row.ok_or(Error::NotFound)?)
}

pub async fn load_by_ref(tx: &mut Tx, tenant: TenantId, order_ref: &str, lock: bool) -> Result<Option<OrderRow>> {
    let sql = format!(
        "SELECT {COLS} FROM orders WHERE tenant_id = $1 AND order_ref = $2{}",
        if lock { " FOR UPDATE" } else { "" }
    );
    let row = sqlx::query(&sql).bind(tenant.0).bind(order_ref).fetch_optional(&mut **tx).await?;
    row.as_ref().map(from_row).transpose()
}

pub async fn create(svc: &Svc, who: &Principal, input: &OrderInput) -> Result<OrderView> {
    who.require(Permission::OrdersWrite)?;
    let tenant = who.tenant_id;
    let mut payload = OrderPayload { quantity: 1, currency: "USD".into(), ..Default::default() };
    let vendor_domain = payload.apply(input)?.flatten();
    if payload.title.is_empty() {
        return Err(Error::invalid("title is required"));
    }
    let id = Uuid::new_v4();
    let order_ref = new_order_ref();
    let sealed = seal_json(&svc.ctx, tenant, &order_aad(id), &payload).await?;
    let mut tx = svc.ctx.db.tenant_tx(tenant).await?;
    sqlx::query(
        "INSERT INTO orders (id, tenant_id, order_ref, status, vendor_domain, sealed, created_by) \
         VALUES ($1, $2, $3, 'draft', $4, $5, $6)",
    )
    .bind(id)
    .bind(tenant.0)
    .bind(&order_ref)
    .bind(&vendor_domain)
    .bind(&sealed)
    .bind(who.user_id.0)
    .execute(&mut *tx)
    .await?;
    insert_event(&mut tx, tenant, id, None, OrderStatus::Draft, Source::User, Some(who.user_id.0), None, None).await?;
    audit::append(&mut tx, who, "order.created", &format!("order:{id}"), serde_json::json!({ "order_ref": order_ref })).await?;
    let row = load(&mut tx, tenant, id, false).await?;
    tx.commit().await?;
    Ok(view(&row, payload, None))
}

pub async fn get(svc: &Svc, who: &Principal, id: Uuid) -> Result<OrderView> {
    who.require(Permission::OrdersRead)?;
    let mut tx = svc.ctx.db.tenant_tx(who.tenant_id).await?;
    let row = load(&mut tx, who.tenant_id, id, false).await?;
    tx.commit().await?;
    let payload = open_payload(svc, who.tenant_id, &row).await?;
    Ok(view(&row, payload, None))
}

pub async fn list(svc: &Svc, who: &Principal, status: Option<OrderStatus>) -> Result<Vec<OrderView>> {
    who.require(Permission::OrdersRead)?;
    let tenant = who.tenant_id;
    let mut tx = svc.ctx.db.tenant_tx(tenant).await?;
    let sql = format!(
        "SELECT {COLS} FROM orders WHERE tenant_id = $1 AND ($2::text IS NULL OR status = $2) \
         ORDER BY updated_at DESC LIMIT {LIST_LIMIT}"
    );
    let rows = sqlx::query(&sql)
        .bind(tenant.0)
        .bind(status.map(OrderStatus::as_str))
        .fetch_all(&mut *tx)
        .await?;
    tx.commit().await?;
    let mut out = Vec::with_capacity(rows.len());
    for r in &rows {
        let row = from_row(r)?;
        let payload = open_payload(svc, tenant, &row).await?;
        out.push(view(&row, payload, None));
    }
    Ok(out)
}

/// Edit an order's details. Commercial terms are frozen once the order is
/// waiting for approval: what was approved is what gets ordered. After that
/// only the vendor reference, tracking and customer contact may change.
pub async fn update(svc: &Svc, who: &Principal, id: Uuid, input: &OrderInput) -> Result<OrderView> {
    who.require(Permission::OrdersWrite)?;
    let tenant = who.tenant_id;
    let mut tx = svc.ctx.db.tenant_tx(tenant).await?;
    let row = load(&mut tx, tenant, id, true).await?;
    if input.version.is_some_and(|v| v != row.version) {
        return Err(Error::conflict("the order changed since you loaded it"));
    }
    if row.status.is_terminal() {
        return Err(Error::conflict("a finished order cannot be edited"));
    }
    let editable_terms = matches!(row.status, OrderStatus::Draft | OrderStatus::QuoteRequested);
    let touches_terms = input.title.is_some()
        || input.board_name.is_some()
        || input.quantity.is_some()
        || input.currency.is_some()
        || input.total_cents.is_some()
        || input.line_items.is_some()
        || input.vendor_name.is_some()
        || input.vendor_domain.is_some()
        || input.shipping_address.is_some()
        || input.payment_required.is_some()
        || input.quote_notes.is_some();
    if touches_terms && !editable_terms {
        return Err(Error::conflict("order terms are frozen once it is sent for approval; send it back to draft to change them"));
    }
    let mut payload = open_payload(svc, tenant, &row).await?;
    let domain_change = payload.apply(input)?;
    let vendor_domain = domain_change.unwrap_or_else(|| row.vendor_domain.clone());
    let sealed = seal_json(&svc.ctx, tenant, &order_aad(id), &payload).await?;
    sqlx::query(
        "UPDATE orders SET sealed = $3, vendor_domain = $4, version = version + 1, updated_at = now() \
         WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant.0)
    .bind(id)
    .bind(&sealed)
    .bind(&vendor_domain)
    .execute(&mut *tx)
    .await?;
    audit::append(&mut tx, who, "order.updated", &format!("order:{id}"), serde_json::json!({ "status": row.status })).await?;
    let row = load(&mut tx, tenant, id, false).await?;
    tx.commit().await?;
    Ok(view(&row, payload, None))
}

#[allow(clippy::too_many_arguments)]
async fn insert_event(
    tx: &mut Tx,
    tenant: TenantId,
    order: Uuid,
    from: Option<OrderStatus>,
    to: OrderStatus,
    source: Source,
    actor: Option<Uuid>,
    mail_message: Option<Uuid>,
    note_sealed: Option<(Uuid, Vec<u8>)>,
) -> Result<Uuid> {
    let (id, note) = match note_sealed {
        Some((id, n)) => (id, Some(n)),
        None => (Uuid::new_v4(), None),
    };
    let source = match source {
        Source::User => "user",
        Source::Approver => "approver",
        Source::Payment => "payment",
        Source::Mail => "mail",
    };
    sqlx::query(
        "INSERT INTO order_events (id, tenant_id, order_id, from_status, to_status, source, actor, mail_message, note_sealed) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(id)
    .bind(tenant.0)
    .bind(order)
    .bind(from.map(OrderStatus::as_str))
    .bind(to.as_str())
    .bind(source)
    .bind(actor)
    .bind(mail_message)
    .bind(note)
    .execute(&mut **tx)
    .await?;
    Ok(id)
}

pub(crate) fn transition_error(e: TransitionError) -> Error {
    match e {
        TransitionError::Forbidden { .. } => Error::Forbidden,
        other => Error::conflict(other.to_string()),
    }
}

/// Extra facts recorded with a transition.
#[derive(Default)]
pub struct TransitionMeta {
    pub actor: Option<Uuid>,
    pub mail_message: Option<Uuid>,
    /// `(event id, sealed note)`; the event id is fixed first because it is
    /// part of the note's AAD.
    pub note_sealed: Option<(Uuid, Vec<u8>)>,
    pub approved_by: Option<Uuid>,
    pub approval_request_id: Option<Uuid>,
    pub mark_paid: bool,
}

/// Change an order's status inside `tx`. `row` must have been loaded
/// `FOR UPDATE` in the same transaction. This is the only code that writes
/// `orders.status`.
pub async fn apply_transition(
    tx: &mut Tx,
    tenant: TenantId,
    row: &OrderRow,
    to: OrderStatus,
    source: Source,
    meta: TransitionMeta,
) -> std::result::Result<(), TransitionOutcome> {
    check_transition(row.status, to, source, row.held_from).map_err(TransitionOutcome::Refused)?;
    let held_from = (to == OrderStatus::OnHold).then(|| row.status.as_str());
    let done = sqlx::query(
        "UPDATE orders SET status = $3, held_from = $4, version = version + 1, updated_at = now(), \
           approved_by = COALESCE($6, approved_by), \
           approved_at = CASE WHEN $6::uuid IS NULL THEN approved_at ELSE now() END, \
           approval_request_id = COALESCE($7, approval_request_id), \
           payment_state = CASE WHEN $8 THEN 'paid' ELSE payment_state END \
         WHERE tenant_id = $1 AND id = $2 AND version = $5",
    )
    .bind(tenant.0)
    .bind(row.id)
    .bind(to.as_str())
    .bind(held_from)
    .bind(row.version)
    .bind(meta.approved_by)
    .bind(meta.approval_request_id)
    .bind(meta.mark_paid)
    .execute(&mut **tx)
    .await
    .map_err(|e| TransitionOutcome::Failed(e.into()))?;
    if done.rows_affected() != 1 {
        return Err(TransitionOutcome::Failed(Error::conflict("the order changed at the same time; try again")));
    }
    insert_event(tx, tenant, row.id, Some(row.status), to, source, meta.actor, meta.mail_message, meta.note_sealed)
        .await
        .map_err(TransitionOutcome::Failed)?;
    Ok(())
}

#[derive(Debug)]
pub enum TransitionOutcome {
    /// The state machine said no. Nothing was written.
    Refused(TransitionError),
    Failed(Error),
}

impl From<TransitionOutcome> for Error {
    fn from(o: TransitionOutcome) -> Self {
        match o {
            TransitionOutcome::Refused(e) => transition_error(e),
            TransitionOutcome::Failed(e) => e,
        }
    }
}

/// Result of a person asking for a transition.
pub struct Transitioned {
    pub order: OrderView,
    /// Set when the order was not placed because an approval request is
    /// waiting (or payment is still due).
    pub waiting: bool,
}

/// A signed-in caller moves an order. Placing it (`→ ordered`) needs
/// `OrdersApprove` and the org's `place_order` approval gate.
pub async fn transition(svc: &Svc, who: &Principal, id: Uuid, to: OrderStatus, note: Option<&str>) -> Result<Transitioned> {
    let tenant = who.tenant_id;
    let placing = to == OrderStatus::Ordered;
    who.require(if placing { Permission::OrdersApprove } else { Permission::OrdersWrite })?;

    let note = note.map(|n| crate::mail::sanitize::clean_text(n, 2000)).filter(|n| !n.is_empty());
    let event_id = Uuid::new_v4();
    let note_sealed = match &note {
        Some(n) => Some((event_id, seal_json(&svc.ctx, tenant, &aad("order_events", event_id, "note_sealed"), n).await?)),
        None => None,
    };

    let mut tx = svc.ctx.db.tenant_tx(tenant).await?;
    let row = load(&mut tx, tenant, id, true).await?;
    let payload = open_payload(svc, tenant, &row).await?;
    let source = if placing { Source::Approver } else { Source::User };
    // Fail on an impossible step before creating any approval request.
    check_transition(row.status, to, source, row.held_from).map_err(transition_error)?;

    let mut meta = TransitionMeta { actor: Some(who.user_id.0), note_sealed, ..Default::default() };
    if placing {
        if payload.total_cents <= 0 && payload.payment_required {
            return Err(Error::invalid("an order that needs payment must have a total"));
        }
        // The summary is hashed into the approval: change the amount and the
        // approval no longer matches.
        let summary = serde_json::json!({
            "order_ref": row.order_ref,
            "amount_cents": payload.total_cents,
            "currency": payload.currency,
        });
        let approval = policy::require_approval(
            &mut tx,
            who,
            GateKind::PlaceOrder { amount_cents: payload.total_cents },
            &format!("order:{id}"),
            summary,
        )
        .await?;
        match approval {
            Approval::NotRequired => {}
            Approval::Approved { request_id } => meta.approval_request_id = Some(request_id),
            Approval::Pending { request_id } => {
                sqlx::query("UPDATE orders SET approval_request_id = $3 WHERE tenant_id = $1 AND id = $2")
                    .bind(tenant.0)
                    .bind(id)
                    .bind(request_id)
                    .execute(&mut *tx)
                    .await?;
                audit::append(&mut tx, who, "order.approval_requested", &format!("order:{id}"), serde_json::json!({ "request": request_id })).await?;
                tx.commit().await?;
                return Ok(Transitioned { order: view(&row, payload, Some(request_id)), waiting: true });
            }
            Approval::Rejected { .. } => {
                tx.commit().await?;
                return Err(Error::conflict("the approval request for this order was rejected"));
            }
        }
        meta.approved_by = Some(who.user_id.0);

        // Approved, but payment comes first: record the approval and wait
        // for the verified Stripe webhook to place the order.
        if payload.payment_required && row.payment_state != "paid" {
            sqlx::query(
                "UPDATE orders SET approved_by = $3, approved_at = now(), approval_request_id = COALESCE($4, approval_request_id), \
                   payment_state = 'pending', version = version + 1, updated_at = now() \
                 WHERE tenant_id = $1 AND id = $2",
            )
            .bind(tenant.0)
            .bind(id)
            .bind(who.user_id.0)
            .bind(meta.approval_request_id)
            .execute(&mut *tx)
            .await?;
            audit::append(&mut tx, who, "order.approved", &format!("order:{id}"), serde_json::json!({ "awaiting": "payment" })).await?;
            let row = load(&mut tx, tenant, id, false).await?;
            tx.commit().await?;
            return Ok(Transitioned { order: view(&row, payload, None), waiting: true });
        }
    }

    apply_transition(&mut tx, tenant, &row, to, source, meta).await?;
    let action = if placing { "order.placed" } else { "order.status_changed" };
    audit::append(
        &mut tx,
        who,
        action,
        &format!("order:{id}"),
        serde_json::json!({ "from": row.status, "to": to }),
    )
    .await?;
    let row = load(&mut tx, tenant, id, false).await?;
    tx.commit().await?;
    Ok(Transitioned { order: view(&row, payload, None), waiting: false })
}

/// Store tracking found in a verified vendor mail on the order.
pub async fn set_tracking(svc: &Svc, tx: &mut Tx, tenant: TenantId, row: &OrderRow, tracking: &Tracking) -> Result<()> {
    let mut payload = open_payload(svc, tenant, row).await?;
    payload.tracking = Some(tracking.clone());
    let sealed = seal_json(&svc.ctx, tenant, &order_aad(row.id), &payload).await?;
    sqlx::query("UPDATE orders SET sealed = $3, version = version + 1, updated_at = now() WHERE tenant_id = $1 AND id = $2")
        .bind(tenant.0)
        .bind(row.id)
        .bind(&sealed)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

pub async fn events(svc: &Svc, who: &Principal, id: Uuid) -> Result<Vec<OrderEventView>> {
    who.require(Permission::OrdersRead)?;
    let tenant = who.tenant_id;
    let mut tx = svc.ctx.db.tenant_tx(tenant).await?;
    load(&mut tx, tenant, id, false).await?;
    let rows = sqlx::query(
        "SELECT id, from_status, to_status, source, actor, note_sealed, created_at FROM order_events \
         WHERE tenant_id = $1 AND order_id = $2 ORDER BY created_at, id LIMIT 500",
    )
    .bind(tenant.0)
    .bind(id)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let ev_id: Uuid = r.try_get("id")?;
        let from: Option<String> = r.try_get("from_status")?;
        let note_sealed: Option<Vec<u8>> = r.try_get("note_sealed")?;
        let note = match note_sealed {
            Some(b) => Some(open_json::<String>(&svc.ctx, tenant, &aad("order_events", ev_id, "note_sealed"), &b).await?),
            None => None,
        };
        out.push(OrderEventView {
            id: ev_id,
            from_state: from.as_deref().and_then(OrderStatus::parse),
            to_state: status_col(&r, "to_status")?,
            source: r.try_get("source")?,
            actor: r.try_get("actor")?,
            note,
            created_at: r.try_get("created_at")?,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn order_refs_are_valid_and_random() {
        let a = new_order_ref();
        let b = new_order_ref();
        assert_ne!(a, b);
        assert_eq!(crate::mail::parser::find_order_refs(&a), vec![a.clone()]);
        assert_eq!(a.len(), 13);
    }
}
