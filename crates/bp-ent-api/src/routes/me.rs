//! The signed-in caller: profile, own credentials, and the policy answers
//! clients (portal, desktop app, agents) need.

use crate::state::{rfc3339, rfc3339_opt, ApiState};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use bp_ent_core::policy::{self, LlmDecision, LlmProvider};
use bp_ent_core::rbac::Scopes;
use bp_ent_core::{audit, auth, AuthKind, Error, Permission, Principal, Result, Role, TenantId, UserId};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::time::Duration;
use uuid::Uuid;

pub fn router() -> Router<ApiState> {
    Router::new()
        .route("/v1/me", get(me))
        .route("/v1/me/tokens", get(list_tokens).post(create_token))
        .route("/v1/me/tokens/{id}", delete(revoke_token))
        .route("/v1/policy", get(get_policy))
        .route("/v1/llm/authorize", post(llm_authorize))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MeOut {
    tenant_id: TenantId,
    tenant_slug: String,
    tenant_name: String,
    user_id: UserId,
    email: String,
    display_name: String,
    role: Role,
    auth_kind: &'static str,
    /// Token scopes as stored (`*` or `parts:read`…).
    scopes: Vec<String>,
    /// What this credential can actually do: role ∩ scopes. The portal
    /// renders from this; the server enforces it on every route regardless.
    permissions: Vec<Permission>,
}

pub fn auth_kind_str(k: AuthKind) -> &'static str {
    match k {
        AuthKind::Session => "session",
        AuthKind::UserToken => "user_token",
        AuthKind::DeviceToken => "device_token",
    }
}

async fn me(State(st): State<ApiState>, p: Principal) -> Result<Json<MeOut>> {
    let mut tx = st.ctx.db.tenant_tx(p.tenant_id).await?;
    let r = sqlx::query("SELECT o.slug, o.name AS org, u.name FROM tenants o JOIN users u ON u.tenant_id = o.id WHERE o.id = $1 AND u.id = $2")
        .bind(p.tenant_id.0)
        .bind(p.user_id.0)
        .fetch_one(&mut *tx)
        .await?;
    Ok(Json(MeOut {
        tenant_id: p.tenant_id,
        tenant_slug: r.get("slug"),
        tenant_name: r.get("org"),
        user_id: p.user_id,
        email: p.email.clone(),
        display_name: r.get("name"),
        role: p.role,
        auth_kind: auth_kind_str(p.auth),
        scopes: p.scopes.to_strings(),
        permissions: Permission::ALL.into_iter().filter(|x| p.can(*x)).collect(),
    }))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenOut {
    pub id: Uuid,
    pub user_id: UserId,
    pub kind: &'static str,
    pub name: String,
    pub scopes: Vec<String>,
    pub created_at: String,
    pub expires_at: String,
    pub last_used_at: Option<String>,
    pub current: bool,
}

pub fn token_out(r: &sqlx::postgres::PgRow, current: Uuid) -> TokenOut {
    let id: Uuid = r.get("id");
    TokenOut {
        id,
        user_id: UserId(r.get("user_id")),
        kind: match r.get::<String, _>("kind").as_str() {
            "s" => "session",
            "u" => "user_token",
            _ => "device_token",
        },
        name: r.get("name"),
        scopes: r.get("scopes"),
        created_at: rfc3339(r.get("created_at")),
        expires_at: rfc3339(r.get("expires_at")),
        last_used_at: rfc3339_opt(r.get("last_used_at")),
        current: id == current,
    }
}

pub const TOKEN_COLS: &str = "id, user_id, kind, name, scopes, created_at, expires_at, last_used_at";

/// My live credentials: sessions, API tokens and device (KiCad) tokens.
async fn list_tokens(State(st): State<ApiState>, p: Principal) -> Result<Json<Vec<TokenOut>>> {
    let mut tx = st.ctx.db.tenant_tx(p.tenant_id).await?;
    let rows = sqlx::query(&format!(
        "SELECT {TOKEN_COLS} FROM auth_tokens WHERE tenant_id = $1 AND user_id = $2 AND revoked_at IS NULL AND expires_at > now() ORDER BY created_at DESC"
    ))
    .bind(p.tenant_id.0)
    .bind(p.user_id.0)
    .fetch_all(&mut *tx)
    .await?;
    Ok(Json(rows.iter().map(|r| token_out(r, p.token_id)).collect()))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateTokenReq {
    name: String,
    /// Scope strings (`parts:read`); omit for everything the role allows.
    #[serde(default)]
    scopes: Option<Vec<String>>,
    #[serde(default)]
    ttl_days: Option<u32>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateTokenResp {
    token: String,
    token_id: Uuid,
    expires_at: String,
}

/// Mint an API token for scripts and agents. Only from a browser session:
/// a token cannot mint further tokens.
async fn create_token(State(st): State<ApiState>, p: Principal, Json(req): Json<CreateTokenReq>) -> Result<(StatusCode, Json<CreateTokenResp>)> {
    p.require_interactive()?;
    let name = req.name.trim();
    if name.is_empty() || name.len() > 100 {
        return Err(Error::invalid("name must be 1-100 characters"));
    }
    let scopes = match req.scopes {
        None => Scopes::All,
        Some(list) => {
            let mut perms = Vec::new();
            for s in &list {
                let perm = Permission::from_scope(s).ok_or_else(|| Error::invalid(format!("unknown scope {s}")))?;
                // Asking for a scope the role lacks is an error, not a silent no-op.
                if !p.role.has(perm) {
                    return Err(Error::Forbidden);
                }
                perms.push(perm);
            }
            if perms.is_empty() {
                return Err(Error::invalid("scopes cannot be empty"));
            }
            Scopes::Only(perms)
        }
    };
    let days = req.ttl_days.unwrap_or(90);
    if !(1..=366).contains(&days) {
        return Err(Error::invalid("ttlDays must be between 1 and 366"));
    }
    let ttl = Duration::from_secs(days as u64 * 86_400);
    let mut tx = st.ctx.db.tenant_tx(p.tenant_id).await?;
    let (id, token) = auth::issue_token(&mut tx, p.tenant_id, p.user_id, AuthKind::UserToken, name, &scopes, ttl).await?;
    audit::append(&mut tx, &p, "token.created", &format!("token:{id}"), serde_json::json!({ "name": name, "scopes": scopes.to_strings(), "ttlDays": days })).await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(CreateTokenResp { token: token.expose().clone(), token_id: id, expires_at: rfc3339(time::OffsetDateTime::now_utc() + ttl) }),
    ))
}

async fn revoke_token(State(st): State<ApiState>, p: Principal, Path(id): Path<Uuid>) -> Result<StatusCode> {
    let mut tx = st.ctx.db.tenant_tx(p.tenant_id).await?;
    let n = sqlx::query("UPDATE auth_tokens SET revoked_at = now() WHERE tenant_id = $1 AND id = $2 AND user_id = $3 AND revoked_at IS NULL")
        .bind(p.tenant_id.0)
        .bind(id)
        .bind(p.user_id.0)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(Error::NotFound);
    }
    audit::append(&mut tx, &p, "token.revoked", &format!("token:{id}"), serde_json::json!({})).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PolicyOut {
    llm_policy: policy::LlmPolicy,
    approval_gates: policy::ApprovalGates,
}

/// The org's governance policy, readable by every member so clients can
/// explain a refusal before attempting the action.
async fn get_policy(State(st): State<ApiState>, p: Principal) -> Result<Json<PolicyOut>> {
    if p.auth == AuthKind::DeviceToken {
        return Err(Error::Forbidden);
    }
    let mut tx = st.ctx.db.tenant_tx(p.tenant_id).await?;
    let (llm_policy, approval_gates) = policy::load(&mut tx, p.tenant_id).await?;
    Ok(Json(PolicyOut { llm_policy, approval_gates }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LlmAuthorizeReq {
    provider: LlmProvider,
    model: String,
    #[serde(default)]
    base_url: Option<String>,
}

/// Ask whether an LLM call is allowed under the org policy (provider/model
/// allowlist, optional ZDR-only rule, pinned endpoints). Clients call this
/// before routing a request; refusals are audited.
async fn llm_authorize(State(st): State<ApiState>, p: Principal, Json(req): Json<LlmAuthorizeReq>) -> Result<Json<LlmDecision>> {
    p.require(Permission::LlmUse)?;
    let mut tx = st.ctx.db.tenant_tx(p.tenant_id).await?;
    let llm = policy::load_llm_policy(&mut tx, p.tenant_id).await?;
    let decision = llm.evaluate(req.provider, &req.model, req.base_url.as_deref());
    if let LlmDecision::Deny { reason } = &decision {
        let model: String = req.model.chars().take(200).collect();
        audit::append(&mut tx, &p, "llm.denied", "llm_policy", serde_json::json!({ "provider": req.provider, "model": model, "reason": reason })).await?;
        tx.commit().await?;
    }
    Ok(Json(decision))
}
