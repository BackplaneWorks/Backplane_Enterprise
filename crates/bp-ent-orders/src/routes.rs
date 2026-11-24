//! HTTP routes. Thin: each handler extracts the verified [`Principal`],
//! calls one service function (which does the permission check) and returns
//! JSON. The tenant is never read from the path, query or body.

use crate::billing::{self, WebhookError, WebhookOutcome};
use crate::bom::{self, BomLineData};
use crate::documents::{self, DocumentUpload};
use crate::mail::Provider;
use crate::mailbox;
use crate::model::{OrderInput, TransitionInput};
use crate::status::OrderStatus;
use crate::stripe::webhook::MAX_WEBHOOK_BODY;
use crate::{orders, Svc};
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use bp_ent_core::{Error, Permission, Principal, Result};
use serde::Deserialize;
use uuid::Uuid;

/// JSON bodies are small, except document uploads (5 MB as base64).
const JSON_LIMIT: usize = 512 * 1024;
const UPLOAD_LIMIT: usize = 8 * 1024 * 1024;

pub fn router(svc: Svc) -> Router {
    let authed = Router::new()
        .route("/v1/orders", get(list_orders).post(create_order))
        .route("/v1/orders/{id}", get(get_order).patch(update_order))
        .route("/v1/orders/{id}/transition", post(transition_order))
        .route("/v1/orders/{id}/events", get(order_events))
        .route("/v1/orders/{id}/mail", get(order_mail))
        .route("/v1/orders/{id}/documents", get(list_documents))
        .route("/v1/orders/{id}/documents/{doc}", get(download_document))
        .route("/v1/orders/bom/{board}", get(get_bom).put(put_bom))
        .route("/v1/orders/bom/lines/{line}/swap", post(swap_bom))
        .route("/v1/mail/connectors", get(list_connectors))
        .route("/v1/mail/connectors/{id}", delete(delete_connector))
        .route("/v1/mail/connectors/{id}/sync", post(sync_connector))
        .route("/v1/mail/connect/{provider}", post(connect_mailbox))
        .route("/v1/mail/callback/{provider}", get(connect_callback))
        .route("/v1/mail/events", get(list_mail_events))
        .route("/v1/mail/events/{id}/apply", post(apply_mail_event))
        .route("/v1/mail/orders/{id}/notify", post(notify_customer))
        .route("/v1/billing/summary", get(billing_summary))
        .route("/v1/billing/checkout", post(seats_checkout))
        .route("/v1/billing/portal", post(billing_portal))
        .route("/v1/billing/orders/{id}/checkout", post(order_checkout))
        .route("/v1/billing/usage/flush", post(flush_usage))
        .layer(DefaultBodyLimit::max(JSON_LIMIT))
        .merge(
            Router::new()
                .route("/v1/orders/{id}/documents", post(upload_document))
                .layer(DefaultBodyLimit::max(UPLOAD_LIMIT)),
        );
    let authed = bp_ent_core::http::with_auth(authed.with_state(svc.clone()), &svc.ctx);

    // Not authenticated by session or token: authenticated by Stripe's
    // signature over the raw body.
    let webhook = Router::new()
        .route("/v1/webhooks/stripe", post(stripe_webhook))
        .layer(DefaultBodyLimit::max(MAX_WEBHOOK_BODY))
        .with_state(svc);

    authed.merge(webhook).layer(axum::middleware::map_response(no_store))
}

/// Order, mail and billing responses are tenant data: never cached.
async fn no_store(mut res: Response) -> Response {
    let h = res.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("private, no-store"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    res
}

// ---------------------------------------------------------------- orders

#[derive(Deserialize)]
struct ListQuery {
    status: Option<OrderStatus>,
}

async fn list_orders(State(svc): State<Svc>, who: Principal, Query(q): Query<ListQuery>) -> Result<impl IntoResponse> {
    Ok(Json(orders::list(&svc, &who, q.status).await?))
}

async fn create_order(State(svc): State<Svc>, who: Principal, Json(input): Json<OrderInput>) -> Result<impl IntoResponse> {
    Ok((StatusCode::CREATED, Json(orders::create(&svc, &who, &input).await?)))
}

async fn get_order(State(svc): State<Svc>, who: Principal, Path(id): Path<Uuid>) -> Result<impl IntoResponse> {
    Ok(Json(orders::get(&svc, &who, id).await?))
}

async fn update_order(State(svc): State<Svc>, who: Principal, Path(id): Path<Uuid>, Json(input): Json<OrderInput>) -> Result<impl IntoResponse> {
    Ok(Json(orders::update(&svc, &who, id, &input).await?))
}

async fn transition_order(
    State(svc): State<Svc>,
    who: Principal,
    Path(id): Path<Uuid>,
    Json(input): Json<TransitionInput>,
) -> Result<impl IntoResponse> {
    let t = orders::transition(&svc, &who, id, input.state, input.note.as_deref()).await?;
    // 202: accepted, but the order is waiting on an approver or on payment.
    let code = if t.waiting { StatusCode::ACCEPTED } else { StatusCode::OK };
    Ok((code, Json(t.order)))
}

async fn order_events(State(svc): State<Svc>, who: Principal, Path(id): Path<Uuid>) -> Result<impl IntoResponse> {
    Ok(Json(orders::events(&svc, &who, id).await?))
}

async fn order_mail(State(svc): State<Svc>, who: Principal, Path(id): Path<Uuid>) -> Result<impl IntoResponse> {
    Ok(Json(mailbox::list_events(&svc, &who, Some(id)).await?))
}

async fn list_documents(State(svc): State<Svc>, who: Principal, Path(id): Path<Uuid>) -> Result<impl IntoResponse> {
    Ok(Json(documents::list(&svc, &who, id).await?))
}

async fn upload_document(State(svc): State<Svc>, who: Principal, Path(id): Path<Uuid>, Json(up): Json<DocumentUpload>) -> Result<impl IntoResponse> {
    Ok((StatusCode::CREATED, Json(documents::upload(&svc, &who, id, &up).await?)))
}

async fn download_document(State(svc): State<Svc>, who: Principal, Path((id, doc)): Path<(Uuid, Uuid)>) -> Result<Response> {
    let (name, bytes) = documents::download(&svc, &who, id, doc).await?;
    // Always a download of opaque bytes: an uploaded file is never rendered
    // in the portal's origin, whatever it claims to be.
    let disposition = HeaderValue::from_str(&format!("attachment; filename=\"{name}\""))
        .unwrap_or_else(|_| HeaderValue::from_static("attachment"));
    Ok((
        [
            (header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream")),
            (header::CONTENT_DISPOSITION, disposition),
            (header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("default-src 'none'; sandbox")),
        ],
        bytes,
    )
        .into_response())
}

// ------------------------------------------------------------------- BOM

async fn get_bom(State(svc): State<Svc>, who: Principal, Path(board): Path<String>) -> Result<impl IntoResponse> {
    Ok(Json(bom::list(&svc, &who, &board).await?))
}

async fn put_bom(State(svc): State<Svc>, who: Principal, Path(board): Path<String>, Json(lines): Json<Vec<BomLineData>>) -> Result<impl IntoResponse> {
    Ok(Json(bom::replace(&svc, &who, &board, &lines).await?))
}

#[derive(Deserialize)]
struct SwapInput {
    mpn: String,
}

async fn swap_bom(State(svc): State<Svc>, who: Principal, Path(line): Path<Uuid>, Json(input): Json<SwapInput>) -> Result<impl IntoResponse> {
    Ok(Json(bom::swap_alternate(&svc, &who, line, &input.mpn).await?))
}

// ------------------------------------------------------------------ mail

fn provider(raw: &str) -> Result<Provider> {
    Provider::parse(raw).ok_or(Error::NotFound)
}

async fn list_connectors(State(svc): State<Svc>, who: Principal) -> Result<impl IntoResponse> {
    Ok(Json(mailbox::list_connections(&svc, &who).await?))
}

async fn delete_connector(State(svc): State<Svc>, who: Principal, Path(id): Path<Uuid>) -> Result<impl IntoResponse> {
    mailbox::disconnect(&svc, &who, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn sync_connector(State(svc): State<Svc>, who: Principal, Path(id): Path<Uuid>) -> Result<impl IntoResponse> {
    who.require(Permission::MailManage)?;
    Ok(Json(mailbox::sync_connection(&svc, who.tenant_id, Some(id)).await?))
}

async fn connect_mailbox(State(svc): State<Svc>, who: Principal, Path(p): Path<String>) -> Result<impl IntoResponse> {
    let url = mailbox::start_connect(&svc, &who, provider(&p)?).await?;
    Ok(Json(serde_json::json!({ "authorizeUrl": url })))
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
}

/// The provider redirects the browser here. Whatever happens, the browser
/// goes back to a fixed portal page with a fixed result code: no provider
/// text and no caller-supplied URL is ever reflected.
async fn connect_callback(State(svc): State<Svc>, who: Principal, Path(p): Path<String>, Query(q): Query<CallbackQuery>) -> Response {
    let result = async {
        let (Some(code), Some(state)) = (q.code.as_deref(), q.state.as_deref()) else {
            return Err(Error::invalid("the provider did not authorise the connection"));
        };
        mailbox::finish_connect(&svc, &who, provider(&p)?, code, state).await
    }
    .await;
    let outcome = match result {
        Ok(_) => "connected",
        Err(e) => {
            tracing::warn!(tenant = %who.tenant_id, code = e.code(), "mailbox connection failed");
            "failed"
        }
    };
    Redirect::to(&format!("{}/purchasing?mail={outcome}", svc.ctx.config.public_origin)).into_response()
}

async fn list_mail_events(State(svc): State<Svc>, who: Principal) -> Result<impl IntoResponse> {
    Ok(Json(mailbox::list_events(&svc, &who, None).await?))
}

async fn apply_mail_event(State(svc): State<Svc>, who: Principal, Path(id): Path<Uuid>) -> Result<impl IntoResponse> {
    Ok(Json(mailbox::apply_event(&svc, &who, id).await?))
}

#[derive(Deserialize)]
struct NotifyInput {
    #[serde(default)]
    message: Option<String>,
}

async fn notify_customer(State(svc): State<Svc>, who: Principal, Path(id): Path<Uuid>, Json(input): Json<NotifyInput>) -> Result<impl IntoResponse> {
    mailbox::notify_customer(&svc, &who, id, input.message.as_deref()).await?;
    Ok(StatusCode::NO_CONTENT)
}

// --------------------------------------------------------------- billing

async fn billing_summary(State(svc): State<Svc>, who: Principal) -> Result<impl IntoResponse> {
    Ok(Json(billing::summary(&svc, &who).await?))
}

#[derive(Deserialize)]
struct SeatsInput {
    seats: u32,
}

async fn seats_checkout(State(svc): State<Svc>, who: Principal, Json(input): Json<SeatsInput>) -> Result<impl IntoResponse> {
    Ok(Json(billing::seats_checkout(&svc, &who, input.seats).await?))
}

async fn billing_portal(State(svc): State<Svc>, who: Principal) -> Result<impl IntoResponse> {
    Ok(Json(billing::billing_portal(&svc, &who).await?))
}

async fn order_checkout(State(svc): State<Svc>, who: Principal, Path(id): Path<Uuid>) -> Result<impl IntoResponse> {
    Ok(Json(billing::order_checkout(&svc, &who, id).await?))
}

async fn flush_usage(State(svc): State<Svc>, who: Principal) -> Result<impl IntoResponse> {
    who.require(Permission::BillingManage)?;
    let reported = billing::flush_usage(&svc, who.tenant_id).await?;
    Ok(Json(serde_json::json!({ "reported": reported })))
}

/// Stripe webhook. Takes the raw bytes: the signature covers exactly them.
async fn stripe_webhook(State(svc): State<Svc>, headers: HeaderMap, body: Bytes) -> Response {
    let signature = headers.get("stripe-signature").and_then(|v| v.to_str().ok()).unwrap_or("");
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    match billing::handle_webhook(&svc, signature, &body, now).await {
        // Acknowledge everything that verified, so Stripe stops retrying.
        Ok(WebhookOutcome::Processed | WebhookOutcome::Duplicate | WebhookOutcome::Ignored) => StatusCode::OK.into_response(),
        // One answer for every unverifiable request: no detail for a prober.
        Err(WebhookError::Signature(_) | WebhookError::Malformed) => StatusCode::BAD_REQUEST.into_response(),
        Err(WebhookError::NotConfigured) => StatusCode::NOT_FOUND.into_response(),
        // Our failure: 5xx makes Stripe retry later.
        Err(WebhookError::Internal(e)) => e.into_response(),
    }
}
