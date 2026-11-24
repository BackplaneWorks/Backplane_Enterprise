//! Admin console: users and roles, SSO providers, LLM policy, approval
//! gates and the approval queue, audit log, encryption keys.
//!
//! Reads need the matching permission. Every change needs a browser session
//! (`require_interactive`): an agent holding an admin's API token cannot
//! promote users, rewire SSO or loosen policy.

use crate::routes::me::{token_out, TokenOut, TOKEN_COLS};
use crate::routes::sso::client_secret_aad;
use crate::state::{rfc3339, rfc3339_opt, ApiState};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, patch, post, put};
use axum::{Json, Router};
use bp_ent_core::policy::{self, ApprovalGates, GateRule, LlmPolicy};
use bp_ent_core::{audit, auth, Error, Permission, Principal, Result, Role, Tx, UserId};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::collections::HashMap;
use uuid::Uuid;

pub fn router() -> Router<ApiState> {
    Router::new()
        .route("/v1/admin/org", get(get_org))
        .route("/v1/admin/users", get(list_users).post(invite_user))
        .route("/v1/admin/users/{id}", delete(delete_user))
        .route("/v1/admin/users/{id}/role", patch(set_role))
        .route("/v1/admin/users/{id}/status", patch(set_status))
        .route("/v1/admin/tokens", get(list_tokens))
        .route("/v1/admin/tokens/{id}", delete(revoke_token))
        .route("/v1/admin/idp", get(list_idps).post(create_idp))
        .route("/v1/admin/idp/{id}", put(update_idp).delete(delete_idp))
        .route("/v1/admin/llm-policy", get(get_llm).put(put_llm))
        .route("/v1/admin/approval-gates", get(list_gates).put(put_gates))
        .route("/v1/admin/approval-gates/{gate}", patch(patch_gate))
        .route("/v1/admin/approvals", get(list_approvals))
        .route("/v1/admin/approvals/{id}/decide", post(decide_approval))
        .route("/v1/admin/audit", get(list_audit))
        .route("/v1/admin/audit/verify", get(verify_audit))
        .route("/v1/admin/keys", get(get_keys))
        .route("/v1/admin/keys/rotate", post(rotate_key))
}

fn admin_write(p: &Principal) -> Result<()> {
    p.require(Permission::AdminManage)?;
    p.require_interactive()
}

// -------------------------------------------------------------------- org

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OrgOut {
    id: Uuid,
    name: String,
    slug: String,
    created_at: String,
    active_seats: i64,
}

async fn get_org(State(st): State<ApiState>, p: Principal) -> Result<Json<OrgOut>> {
    p.require(Permission::AdminManage)?;
    let mut tx = st.ctx.db.tenant_tx(p.tenant_id).await?;
    let r = sqlx::query("SELECT id, name, slug, created_at, (SELECT count(*) FROM users WHERE tenant_id = $1 AND status = 'active') AS seats FROM tenants WHERE id = $1")
        .bind(p.tenant_id.0)
        .fetch_one(&mut *tx)
        .await?;
    Ok(Json(OrgOut { id: r.get("id"), name: r.get("name"), slug: r.get("slug"), created_at: rfc3339(r.get("created_at")), active_seats: r.get("seats") }))
}

// ------------------------------------------------------------------ users

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UserOut {
    id: Uuid,
    email: String,
    display_name: String,
    role: String,
    status: String,
    last_login_at: Option<String>,
    created_at: String,
}

const USER_COLS: &str = "id, email, name, role, status, last_login_at, created_at";

fn user_out(r: &sqlx::postgres::PgRow) -> UserOut {
    UserOut {
        id: r.get("id"),
        email: r.get("email"),
        display_name: r.get("name"),
        role: r.get("role"),
        status: r.get("status"),
        last_login_at: rfc3339_opt(r.get("last_login_at")),
        created_at: rfc3339(r.get("created_at")),
    }
}

async fn list_users(State(st): State<ApiState>, p: Principal) -> Result<Json<Vec<UserOut>>> {
    p.require(Permission::AdminManage)?;
    let mut tx = st.ctx.db.tenant_tx(p.tenant_id).await?;
    let rows = sqlx::query(&format!("SELECT {USER_COLS} FROM users WHERE tenant_id = $1 ORDER BY email")).bind(p.tenant_id.0).fetch_all(&mut *tx).await?;
    Ok(Json(rows.iter().map(user_out).collect()))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct InviteReq {
    email: String,
    #[serde(default)]
    display_name: String,
    role: Role,
}

/// Pre-provision a member. They become active on their first SSO login with
/// that e-mail address.
async fn invite_user(State(st): State<ApiState>, p: Principal, Json(req): Json<InviteReq>) -> Result<(StatusCode, Json<UserOut>)> {
    admin_write(&p)?;
    let email = crate::routes::sso::normalize_email(&req.email).map_err(|_| Error::invalid("invalid e-mail address"))?;
    if req.display_name.len() > 200 {
        return Err(Error::invalid("displayName is too long"));
    }
    let id = Uuid::new_v4();
    let mut tx = st.ctx.db.tenant_tx(p.tenant_id).await?;
    let r = sqlx::query(&format!("INSERT INTO users (id, tenant_id, email, name, role, status) VALUES ($1, $2, $3, $4, $5, 'invited') RETURNING {USER_COLS}"))
        .bind(id)
        .bind(p.tenant_id.0)
        .bind(&email)
        .bind(req.display_name.trim())
        .bind(req.role.as_str())
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| match Error::from(e) {
            Error::Conflict(_) => Error::conflict("a user with this e-mail already exists"),
            other => other,
        })?;
    audit::append(&mut tx, &p, "user.invited", &format!("user:{id}"), serde_json::json!({ "role": req.role })).await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(user_out(&r))))
}

/// Refuse a change that would leave the org with no active admin.
async fn ensure_another_admin(tx: &mut Tx, p: &Principal, leaving: Uuid) -> Result<()> {
    let others: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE tenant_id = $1 AND role = 'org_admin' AND status = 'active' AND id <> $2")
        .bind(p.tenant_id.0)
        .bind(leaving)
        .fetch_one(&mut **tx)
        .await?;
    if others == 0 {
        return Err(Error::conflict("this is the last active org admin"));
    }
    Ok(())
}

async fn lock_user(tx: &mut Tx, p: &Principal, id: Uuid) -> Result<(String, String)> {
    // Serialise admin changes per tenant so two concurrent demotions cannot
    // both pass the last-admin check.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('bpe-admins:' || $1, 0))").bind(p.tenant_id.0.to_string()).execute(&mut **tx).await?;
    let r = sqlx::query("SELECT role, status FROM users WHERE tenant_id = $1 AND id = $2 FOR UPDATE")
        .bind(p.tenant_id.0)
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(Error::NotFound)?;
    Ok((r.get("role"), r.get("status")))
}

#[derive(Deserialize)]
struct RoleReq {
    role: Role,
}

async fn set_role(State(st): State<ApiState>, p: Principal, Path(id): Path<Uuid>, Json(req): Json<RoleReq>) -> Result<Json<UserOut>> {
    admin_write(&p)?;
    let mut tx = st.ctx.db.tenant_tx(p.tenant_id).await?;
    let (old, status) = lock_user(&mut tx, &p, id).await?;
    if old == "org_admin" && req.role != Role::OrgAdmin && status == "active" {
        ensure_another_admin(&mut tx, &p, id).await?;
    }
    let r = sqlx::query(&format!("UPDATE users SET role = $3 WHERE tenant_id = $1 AND id = $2 RETURNING {USER_COLS}"))
        .bind(p.tenant_id.0)
        .bind(id)
        .bind(req.role.as_str())
        .fetch_one(&mut *tx)
        .await?;
    // Existing API tokens were minted under the old role's judgement: end
    // them. (Sessions pick the new role up on the next request.)
    if old != req.role.as_str() {
        sqlx::query("UPDATE auth_tokens SET revoked_at = now() WHERE tenant_id = $1 AND user_id = $2 AND kind <> 's' AND revoked_at IS NULL")
            .bind(p.tenant_id.0)
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    audit::append(&mut tx, &p, "user.role_changed", &format!("user:{id}"), serde_json::json!({ "from": old, "to": req.role })).await?;
    tx.commit().await?;
    Ok(Json(user_out(&r)))
}

#[derive(Deserialize)]
struct StatusReq {
    status: String,
}

async fn set_status(State(st): State<ApiState>, p: Principal, Path(id): Path<Uuid>, Json(req): Json<StatusReq>) -> Result<Json<UserOut>> {
    admin_write(&p)?;
    if !matches!(req.status.as_str(), "active" | "suspended") {
        return Err(Error::invalid("status must be active or suspended"));
    }
    let mut tx = st.ctx.db.tenant_tx(p.tenant_id).await?;
    let (role, old) = lock_user(&mut tx, &p, id).await?;
    if req.status == "suspended" {
        if role == "org_admin" && old == "active" {
            ensure_another_admin(&mut tx, &p, id).await?;
        }
        auth::revoke_user_tokens(&mut tx, p.tenant_id, UserId(id)).await?;
    }
    let r = sqlx::query(&format!("UPDATE users SET status = $3 WHERE tenant_id = $1 AND id = $2 RETURNING {USER_COLS}"))
        .bind(p.tenant_id.0)
        .bind(id)
        .bind(&req.status)
        .fetch_one(&mut *tx)
        .await?;
    audit::append(&mut tx, &p, "user.status_changed", &format!("user:{id}"), serde_json::json!({ "from": old, "to": req.status })).await?;
    tx.commit().await?;
    Ok(Json(user_out(&r)))
}

async fn delete_user(State(st): State<ApiState>, p: Principal, Path(id): Path<Uuid>) -> Result<StatusCode> {
    admin_write(&p)?;
    let mut tx = st.ctx.db.tenant_tx(p.tenant_id).await?;
    let (role, status) = lock_user(&mut tx, &p, id).await?;
    if role == "org_admin" && status == "active" {
        ensure_another_admin(&mut tx, &p, id).await?;
    }
    sqlx::query("DELETE FROM users WHERE tenant_id = $1 AND id = $2").bind(p.tenant_id.0).bind(id).execute(&mut *tx).await?;
    audit::append(&mut tx, &p, "user.deleted", &format!("user:{id}"), serde_json::json!({ "role": role })).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

// ----------------------------------------------------------------- tokens

/// Every live credential in the org (sessions, API tokens, KiCad device tokens).
async fn list_tokens(State(st): State<ApiState>, p: Principal) -> Result<Json<Vec<TokenOut>>> {
    p.require(Permission::AdminManage)?;
    let mut tx = st.ctx.db.tenant_tx(p.tenant_id).await?;
    let rows = sqlx::query(&format!("SELECT {TOKEN_COLS} FROM auth_tokens WHERE tenant_id = $1 AND revoked_at IS NULL AND expires_at > now() ORDER BY created_at DESC LIMIT 1000"))
        .bind(p.tenant_id.0)
        .fetch_all(&mut *tx)
        .await?;
    Ok(Json(rows.iter().map(|r| token_out(r, p.token_id)).collect()))
}

async fn revoke_token(State(st): State<ApiState>, p: Principal, Path(id): Path<Uuid>) -> Result<StatusCode> {
    admin_write(&p)?;
    let mut tx = st.ctx.db.tenant_tx(p.tenant_id).await?;
    if !auth::revoke_token(&mut tx, p.tenant_id, id).await? {
        return Err(Error::NotFound);
    }
    audit::append(&mut tx, &p, "token.revoked_by_admin", &format!("token:{id}"), serde_json::json!({})).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

// -------------------------------------------------------------------- idp

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct IdpOut {
    id: Uuid,
    /// `google` | `microsoft` | `oidc` | `saml`
    provider: String,
    display_name: String,
    enabled: bool,
    issuer: Option<String>,
    client_id: Option<String>,
    /// Never the secret itself.
    has_client_secret: bool,
    directory_id: Option<String>,
    allowed_domains: Vec<String>,
    /// First allowed domain, for compact display.
    domain: String,
    saml_entity_id: Option<String>,
    saml_sso_url: Option<String>,
    has_saml_certificate: bool,
    auto_provision: bool,
    default_role: String,
    trust_email: bool,
    /// There is no password login: SSO is always enforced.
    enforced_sso: bool,
    /// What to register at the identity provider.
    redirect_uri: String,
    created_at: String,
}

const IDP_COLS: &str = "id, kind, display_name, enabled, issuer, client_id, client_secret_enc IS NOT NULL AS has_secret, directory_id, \
                        allowed_domains, saml_entity_id, saml_sso_url, saml_cert_pem IS NOT NULL AS has_cert, auto_provision, default_role, trust_email, created_at";

fn idp_out(st: &ApiState, r: &sqlx::postgres::PgRow) -> IdpOut {
    let kind: String = r.get("kind");
    let domains: Vec<String> = r.get("allowed_domains");
    IdpOut {
        id: r.get("id"),
        redirect_uri: if kind == "saml" { format!("{}/v1/auth/saml/acs", st.ctx.config.api_base_url) } else { crate::routes::sso::callback_url(&st.ctx) },
        provider: kind,
        display_name: r.get("display_name"),
        enabled: r.get("enabled"),
        issuer: r.get("issuer"),
        client_id: r.get("client_id"),
        has_client_secret: r.get("has_secret"),
        directory_id: r.get("directory_id"),
        domain: domains.first().cloned().unwrap_or_default(),
        allowed_domains: domains,
        saml_entity_id: r.get("saml_entity_id"),
        saml_sso_url: r.get("saml_sso_url"),
        has_saml_certificate: r.get("has_cert"),
        auto_provision: r.get("auto_provision"),
        default_role: r.get("default_role"),
        trust_email: r.get("trust_email"),
        enforced_sso: true,
        created_at: rfc3339(r.get("created_at")),
    }
}

async fn list_idps(State(st): State<ApiState>, p: Principal) -> Result<Json<Vec<IdpOut>>> {
    p.require(Permission::AdminManage)?;
    let mut tx = st.ctx.db.tenant_tx(p.tenant_id).await?;
    let rows = sqlx::query(&format!("SELECT {IDP_COLS} FROM identity_providers WHERE tenant_id = $1 ORDER BY created_at")).bind(p.tenant_id.0).fetch_all(&mut *tx).await?;
    Ok(Json(rows.iter().map(|r| idp_out(&st, r)).collect()))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdpReq {
    pub provider: String,
    pub display_name: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default)]
    pub issuer: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    /// Write-only. Omit on update to keep the stored secret.
    #[serde(default)]
    pub client_secret: Option<bp_ent_core::Secret<String>>,
    /// Google Workspace domain (`hd`) or Microsoft Entra tenant id (`tid`).
    #[serde(default)]
    pub directory_id: Option<String>,
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    #[serde(default)]
    pub saml_entity_id: Option<String>,
    #[serde(default)]
    pub saml_sso_url: Option<String>,
    #[serde(default)]
    pub saml_cert_pem: Option<String>,
    #[serde(default)]
    pub auto_provision: bool,
    #[serde(default)]
    pub default_role: Option<Role>,
    /// Generic OIDC only: accept ID tokens that carry no `email_verified`.
    #[serde(default)]
    pub trust_email: bool,
}

fn yes() -> bool {
    true
}

/// The validated, normalised provider settings.
pub struct IdpFields {
    pub kind: String,
    pub issuer: Option<String>,
    pub client_id: Option<String>,
    pub directory_id: Option<String>,
    pub allowed_domains: Vec<String>,
    pub default_role: Role,
}

fn valid_domain(d: &str) -> bool {
    d.len() <= 253 && d.contains('.') && d.split('.').all(|l| !l.is_empty() && l.len() <= 63 && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') && !l.starts_with('-') && !l.ends_with('-'))
}

pub fn validate_idp(http: &bp_ent_core::SafeHttp, req: &IdpReq, has_stored_secret: bool) -> Result<IdpFields> {
    let name = req.display_name.trim();
    if name.is_empty() || name.len() > 100 {
        return Err(Error::invalid("displayName must be 1-100 characters"));
    }
    let allowed_domains: Vec<String> = req.allowed_domains.iter().map(|d| d.trim().to_ascii_lowercase()).collect();
    if allowed_domains.len() > 50 || !allowed_domains.iter().all(|d| valid_domain(d)) {
        return Err(Error::invalid("allowedDomains must be valid domain names"));
    }
    let default_role = req.default_role.unwrap_or(Role::Engineer);
    if default_role == Role::OrgAdmin {
        return Err(Error::invalid("auto-provisioned users cannot default to org_admin"));
    }
    let directory_id = req.directory_id.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(str::to_ascii_lowercase);
    let need_client = |issuer: String| -> Result<(Option<String>, Option<String>)> {
        let cid = req.client_id.as_deref().map(str::trim).filter(|s| !s.is_empty() && s.len() <= 300).ok_or_else(|| Error::invalid("clientId is required"))?;
        if req.client_secret.is_none() && !has_stored_secret {
            return Err(Error::invalid("clientSecret is required"));
        }
        Ok((Some(issuer), Some(cid.to_string())))
    };
    let (issuer, client_id) = match req.provider.as_str() {
        "google" => {
            // A Workspace login must be pinned to the customer's Workspace,
            // or any Google account with a matching-looking address would do.
            let hd = directory_id.as_deref().ok_or_else(|| Error::invalid("directoryId (your Google Workspace domain) is required"))?;
            if !valid_domain(hd) {
                return Err(Error::invalid("directoryId must be your Google Workspace domain"));
            }
            need_client("https://accounts.google.com".into())?
        }
        "microsoft" => {
            let tid = directory_id.as_deref().ok_or_else(|| Error::invalid("directoryId (your Entra tenant id) is required"))?;
            // `common` / `organizations` would accept any Microsoft account.
            if Uuid::try_parse(tid).is_err() {
                return Err(Error::invalid("directoryId must be your Entra tenant id (a GUID)"));
            }
            need_client(format!("https://login.microsoftonline.com/{tid}/v2.0"))?
        }
        "oidc" => {
            let iss = req.issuer.as_deref().map(|s| s.trim().trim_end_matches('/')).filter(|s| !s.is_empty()).ok_or_else(|| Error::invalid("issuer is required"))?;
            http.check_url(iss)?;
            if allowed_domains.is_empty() {
                return Err(Error::invalid("allowedDomains is required for a generic OIDC provider"));
            }
            need_client(iss.to_string())?
        }
        "saml" => {
            let sso = req.saml_sso_url.as_deref().ok_or_else(|| Error::invalid("samlSsoUrl is required"))?;
            http.check_url(sso)?;
            let ent = req.saml_entity_id.as_deref().map(str::trim).filter(|s| !s.is_empty() && s.len() <= 1000).ok_or_else(|| Error::invalid("samlEntityId is required"))?;
            let _ = ent;
            if let Some(pem) = &req.saml_cert_pem {
                crate::saml::parse_certificate(pem)?;
            } else if !has_stored_secret {
                return Err(Error::invalid("samlCertPem (the IdP signing certificate) is required"));
            }
            if allowed_domains.is_empty() {
                return Err(Error::invalid("allowedDomains is required for a SAML provider"));
            }
            (None, None)
        }
        _ => return Err(Error::invalid("provider must be google, microsoft, oidc or saml")),
    };
    Ok(IdpFields { kind: req.provider.clone(), issuer, client_id, directory_id, allowed_domains, default_role })
}

async fn create_idp(State(st): State<ApiState>, p: Principal, Json(req): Json<IdpReq>) -> Result<(StatusCode, Json<IdpOut>)> {
    admin_write(&p)?;
    let f = validate_idp(&st.ctx.http, &req, false)?;
    let id = Uuid::new_v4();
    let secret_enc = match &req.client_secret {
        Some(s) => Some(st.ctx.cipher.seal(p.tenant_id, &client_secret_aad(id), s.expose().as_bytes()).await?),
        None => None,
    };
    let mut tx = st.ctx.db.tenant_tx(p.tenant_id).await?;
    let r = sqlx::query(&format!(
        "INSERT INTO identity_providers (id, tenant_id, kind, display_name, enabled, issuer, client_id, client_secret_enc, directory_id, allowed_domains, \
                                         saml_entity_id, saml_sso_url, saml_cert_pem, auto_provision, default_role, trust_email) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16) RETURNING {IDP_COLS}"
    ))
    .bind(id)
    .bind(p.tenant_id.0)
    .bind(&f.kind)
    .bind(req.display_name.trim())
    .bind(req.enabled)
    .bind(&f.issuer)
    .bind(&f.client_id)
    .bind(&secret_enc)
    .bind(&f.directory_id)
    .bind(&f.allowed_domains)
    .bind(req.saml_entity_id.as_deref().map(str::trim))
    .bind(&req.saml_sso_url)
    .bind(&req.saml_cert_pem)
    .bind(req.auto_provision)
    .bind(f.default_role.as_str())
    .bind(req.trust_email && f.kind == "oidc")
    .fetch_one(&mut *tx)
    .await?;
    audit::append(&mut tx, &p, "idp.created", &format!("idp:{id}"), serde_json::json!({ "provider": f.kind, "issuer": f.issuer, "allowedDomains": f.allowed_domains, "autoProvision": req.auto_provision, "trustEmail": req.trust_email })).await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(idp_out(&st, &r))))
}

async fn update_idp(State(st): State<ApiState>, p: Principal, Path(id): Path<Uuid>, Json(req): Json<IdpReq>) -> Result<Json<IdpOut>> {
    admin_write(&p)?;
    let mut tx = st.ctx.db.tenant_tx(p.tenant_id).await?;
    let cur = sqlx::query("SELECT kind, client_secret_enc IS NOT NULL OR saml_cert_pem IS NOT NULL AS has_secret FROM identity_providers WHERE tenant_id = $1 AND id = $2 FOR UPDATE")
        .bind(p.tenant_id.0)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(Error::NotFound)?;
    if cur.get::<String, _>("kind") != req.provider {
        return Err(Error::invalid("the provider type cannot be changed; create a new provider instead"));
    }
    let f = validate_idp(&st.ctx.http, &req, cur.get("has_secret"))?;
    let secret_enc = match &req.client_secret {
        Some(s) => Some(st.ctx.cipher.seal(p.tenant_id, &client_secret_aad(id), s.expose().as_bytes()).await?),
        None => None,
    };
    let r = sqlx::query(&format!(
        "UPDATE identity_providers SET display_name = $3, enabled = $4, issuer = $5, client_id = $6, \
                client_secret_enc = COALESCE($7, client_secret_enc), directory_id = $8, allowed_domains = $9, \
                saml_entity_id = $10, saml_sso_url = $11, saml_cert_pem = COALESCE($12, saml_cert_pem), auto_provision = $13, default_role = $14, trust_email = $15 \
         WHERE tenant_id = $1 AND id = $2 RETURNING {IDP_COLS}"
    ))
    .bind(p.tenant_id.0)
    .bind(id)
    .bind(req.display_name.trim())
    .bind(req.enabled)
    .bind(&f.issuer)
    .bind(&f.client_id)
    .bind(&secret_enc)
    .bind(&f.directory_id)
    .bind(&f.allowed_domains)
    .bind(req.saml_entity_id.as_deref().map(str::trim))
    .bind(&req.saml_sso_url)
    .bind(&req.saml_cert_pem)
    .bind(req.auto_provision)
    .bind(f.default_role.as_str())
    .bind(req.trust_email && f.kind == "oidc")
    .fetch_one(&mut *tx)
    .await?;
    audit::append(&mut tx, &p, "idp.updated", &format!("idp:{id}"), serde_json::json!({ "enabled": req.enabled, "issuer": f.issuer, "allowedDomains": f.allowed_domains, "autoProvision": req.auto_provision, "trustEmail": req.trust_email, "secretChanged": secret_enc.is_some() })).await?;
    tx.commit().await?;
    Ok(Json(idp_out(&st, &r)))
}

async fn delete_idp(State(st): State<ApiState>, p: Principal, Path(id): Path<Uuid>) -> Result<StatusCode> {
    admin_write(&p)?;
    let mut tx = st.ctx.db.tenant_tx(p.tenant_id).await?;
    // Deleting the only way in would lock the whole org out.
    let others: i64 = sqlx::query_scalar("SELECT count(*) FROM identity_providers WHERE tenant_id = $1 AND enabled AND id <> $2").bind(p.tenant_id.0).bind(id).fetch_one(&mut *tx).await?;
    if others == 0 {
        return Err(Error::conflict("this is the only enabled sign-in provider"));
    }
    let n = sqlx::query("DELETE FROM identity_providers WHERE tenant_id = $1 AND id = $2").bind(p.tenant_id.0).bind(id).execute(&mut *tx).await?.rows_affected();
    if n == 0 {
        return Err(Error::NotFound);
    }
    audit::append(&mut tx, &p, "idp.deleted", &format!("idp:{id}"), serde_json::json!({})).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

// ----------------------------------------------------------------- policy

async fn get_llm(State(st): State<ApiState>, p: Principal) -> Result<Json<LlmPolicy>> {
    p.require(Permission::AdminManage)?;
    let mut tx = st.ctx.db.tenant_tx(p.tenant_id).await?;
    Ok(Json(policy::load_llm_policy(&mut tx, p.tenant_id).await?))
}

async fn put_llm(State(st): State<ApiState>, p: Principal, Json(new): Json<LlmPolicy>) -> Result<Json<LlmPolicy>> {
    admin_write(&p)?;
    let mut tx = st.ctx.db.tenant_tx(p.tenant_id).await?;
    policy::save_llm_policy(&mut tx, &p, &new).await?;
    tx.commit().await?;
    Ok(Json(new))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GateOut {
    id: &'static str,
    kind: &'static str,
    description: &'static str,
    #[serde(flatten)]
    rule: GateRule,
}

fn gate_description(gate: &str) -> &'static str {
    match gate {
        "place_order" => "Placing a purchase order (optionally only above a threshold)",
        "modify_released_part" => "Changing or deleting a Released library part",
        "modify_released_board" => "Changing a released board revision",
        "enable_external_mcp" => "Connecting an agent to an external MCP server",
        _ => "Spending beyond the monthly LLM budget",
    }
}

fn gates_out(g: &ApprovalGates) -> Vec<GateOut> {
    ApprovalGates::GATES
        .iter()
        .map(|name| GateOut { id: name, kind: name, description: gate_description(name), rule: g.rule(name).expect("known gate").clone() })
        .collect()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GatesOut {
    gates: Vec<GateOut>,
    allow_self_approval: bool,
    ttl_hours: u32,
}

async fn list_gates(State(st): State<ApiState>, p: Principal) -> Result<Json<GatesOut>> {
    p.require(Permission::AdminManage)?;
    let mut tx = st.ctx.db.tenant_tx(p.tenant_id).await?;
    let (_, g) = policy::load(&mut tx, p.tenant_id).await?;
    Ok(Json(GatesOut { gates: gates_out(&g), allow_self_approval: g.allow_self_approval, ttl_hours: g.ttl_hours }))
}

async fn put_gates(State(st): State<ApiState>, p: Principal, Json(new): Json<ApprovalGates>) -> Result<Json<GatesOut>> {
    admin_write(&p)?;
    let mut tx = st.ctx.db.tenant_tx(p.tenant_id).await?;
    policy::save_approval_gates(&mut tx, &p, &new).await?;
    tx.commit().await?;
    Ok(Json(GatesOut { gates: gates_out(&new), allow_self_approval: new.allow_self_approval, ttl_hours: new.ttl_hours }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GatePatch {
    #[serde(default)]
    enabled: Option<bool>,
    /// `null` clears the threshold (always require approval).
    #[serde(default, deserialize_with = "double_option")]
    threshold_cents: Option<Option<i64>>,
    #[serde(default)]
    approvers: Option<Vec<Role>>,
    #[serde(default)]
    agents_only: Option<bool>,
}

fn double_option<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Option<Option<i64>>, D::Error> {
    Option::<i64>::deserialize(d).map(Some)
}

async fn patch_gate(State(st): State<ApiState>, p: Principal, Path(gate): Path<String>, Json(patch): Json<GatePatch>) -> Result<Json<GatesOut>> {
    admin_write(&p)?;
    let mut tx = st.ctx.db.tenant_tx(p.tenant_id).await?;
    let (_, mut g) = policy::load(&mut tx, p.tenant_id).await?;
    {
        let rule = g.rule_mut(&gate).ok_or(Error::NotFound)?;
        if let Some(v) = patch.enabled {
            rule.enabled = v;
        }
        if let Some(v) = patch.threshold_cents {
            rule.threshold_cents = v;
        }
        if let Some(v) = patch.approvers {
            rule.approvers = v;
        }
        if let Some(v) = patch.agents_only {
            rule.agents_only = v;
        }
    }
    policy::save_approval_gates(&mut tx, &p, &g).await?;
    tx.commit().await?;
    Ok(Json(GatesOut { gates: gates_out(&g), allow_self_approval: g.allow_self_approval, ttl_hours: g.ttl_hours }))
}

// -------------------------------------------------------------- approvals

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ApprovalOut {
    id: Uuid,
    gate_kind: String,
    subject: String,
    summary: serde_json::Value,
    status: String,
    requested_by: Uuid,
    requested_by_email: Option<String>,
    /// `user` (browser), `token` (agent/API) or `device`.
    requested_via: String,
    decided_by: Option<Uuid>,
    decided_at: Option<String>,
    reason: Option<String>,
    created_at: String,
    expires_at: String,
    /// Whether the caller is allowed to decide this one.
    can_decide: bool,
}

#[derive(Deserialize)]
struct ApprovalsQuery {
    #[serde(default)]
    status: Option<String>,
}

/// The approval queue. Visible to admins and to any role that is an approver
/// for at least one gate; each caller only sees the gates they can approve.
async fn list_approvals(State(st): State<ApiState>, p: Principal, Query(q): Query<ApprovalsQuery>) -> Result<Json<Vec<ApprovalOut>>> {
    let mut tx = st.ctx.db.tenant_tx(p.tenant_id).await?;
    let (_, gates) = policy::load(&mut tx, p.tenant_id).await?;
    let admin = p.can(Permission::AdminManage);
    let my_gates: Vec<String> = ApprovalGates::GATES
        .iter()
        .filter(|g| gates.rule(g).map(|r| r.approvers.contains(&p.role)).unwrap_or(false))
        .map(|g| g.to_string())
        .collect();
    if !admin && my_gates.is_empty() {
        return Err(Error::Forbidden);
    }
    let status = q.status.unwrap_or_else(|| "pending".into());
    if !matches!(status.as_str(), "pending" | "approved" | "rejected" | "consumed" | "expired" | "all") {
        return Err(Error::invalid("unknown status"));
    }
    let rows = sqlx::query(
        "SELECT a.id, a.gate, a.subject, a.summary, \
                CASE WHEN a.status IN ('pending', 'approved') AND a.expires_at < now() THEN 'expired' ELSE a.status END AS status, \
                a.requested_by, u.email AS requester, a.requested_via, a.decided_by, a.decided_at, a.reason, a.created_at, a.expires_at \
         FROM approval_requests a LEFT JOIN users u ON u.tenant_id = a.tenant_id AND u.id = a.requested_by \
         WHERE a.tenant_id = $1 AND ($2 OR a.gate = ANY($3)) ORDER BY a.created_at DESC LIMIT 500",
    )
    .bind(p.tenant_id.0)
    .bind(admin)
    .bind(&my_gates)
    .fetch_all(&mut *tx)
    .await?;
    let interactive = p.require_interactive().is_ok();
    let out = rows
        .iter()
        .map(|r| {
            let gate: String = r.get("gate");
            let st: String = r.get("status");
            let requested_by: Uuid = r.get("requested_by");
            ApprovalOut {
                can_decide: interactive && st == "pending" && my_gates.contains(&gate) && (gates.allow_self_approval || requested_by != p.user_id.0),
                id: r.get("id"),
                gate_kind: gate,
                subject: r.get("subject"),
                summary: r.get("summary"),
                status: st,
                requested_by,
                requested_by_email: r.get("requester"),
                requested_via: r.get("requested_via"),
                decided_by: r.get("decided_by"),
                decided_at: rfc3339_opt(r.get("decided_at")),
                reason: r.get("reason"),
                created_at: rfc3339(r.get("created_at")),
                expires_at: rfc3339(r.get("expires_at")),
            }
        })
        .filter(|a| status == "all" || a.status == status)
        .collect();
    Ok(Json(out))
}

#[derive(Deserialize)]
struct DecideReq {
    /// `approved` or `rejected`
    decision: String,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Serialize)]
struct DecideOut {
    id: Uuid,
    status: String,
}

async fn decide_approval(State(st): State<ApiState>, p: Principal, Path(id): Path<Uuid>, Json(req): Json<DecideReq>) -> Result<Json<DecideOut>> {
    let approve = match req.decision.as_str() {
        "approved" | "approve" => true,
        "rejected" | "reject" => false,
        _ => return Err(Error::invalid("decision must be approved or rejected")),
    };
    let mut tx = st.ctx.db.tenant_tx(p.tenant_id).await?;
    // All the rules (session, approver role, four-eyes, still pending) live in core.
    policy::decide(&mut tx, &p, id, approve, req.reason.as_deref()).await?;
    tx.commit().await?;
    Ok(Json(DecideOut { id, status: if approve { "approved".into() } else { "rejected".into() } }))
}

// ------------------------------------------------------------------ audit

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditOut {
    seq: i64,
    timestamp: String,
    actor_kind: String,
    actor: String,
    actor_email: Option<String>,
    action: String,
    target: String,
    details: serde_json::Value,
    prev_hash: String,
    entry_hash: String,
}

#[derive(Deserialize)]
struct AuditQuery {
    #[serde(default)]
    before: Option<i64>,
    #[serde(default)]
    limit: Option<i64>,
}

async fn list_audit(State(st): State<ApiState>, p: Principal, Query(q): Query<AuditQuery>) -> Result<Json<Vec<AuditOut>>> {
    p.require(Permission::AuditRead)?;
    let mut tx = st.ctx.db.tenant_tx(p.tenant_id).await?;
    let entries = audit::list(&mut tx, p.tenant_id, q.before, q.limit.unwrap_or(100)).await?;
    let emails: HashMap<String, String> = sqlx::query("SELECT id::text AS id, email FROM users WHERE tenant_id = $1")
        .bind(p.tenant_id.0)
        .fetch_all(&mut *tx)
        .await?
        .iter()
        .map(|r| (r.get("id"), r.get("email")))
        .collect();
    Ok(Json(
        entries
            .into_iter()
            .map(|e| AuditOut {
                seq: e.seq,
                timestamp: time::OffsetDateTime::from_unix_timestamp_nanos(e.at_us as i128 * 1000).map(rfc3339).unwrap_or_default(),
                actor_email: emails.get(&e.actor).cloned(),
                actor_kind: e.actor_kind,
                actor: e.actor,
                action: e.action,
                target: e.target,
                details: serde_json::from_str(&e.details).unwrap_or(serde_json::Value::Null),
                prev_hash: hex(&e.prev_hash),
                entry_hash: hex(&e.hash),
            })
            .collect(),
    ))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VerifyOut {
    ok: bool,
    entries: u64,
    /// Latest sequence number and hash: record these outside the database
    /// (SIEM, object-lock bucket) to make removal of recent entries detectable.
    head_seq: Option<i64>,
    head_hash: Option<String>,
    error: Option<String>,
}

/// Recompute the whole hash chain.
async fn verify_audit(State(st): State<ApiState>, p: Principal) -> Result<Json<VerifyOut>> {
    p.require(Permission::AuditRead)?;
    let mut tx = st.ctx.db.tenant_tx(p.tenant_id).await?;
    let head = audit::head(&mut tx, p.tenant_id).await?;
    let (head_seq, head_hash) = (head.as_ref().map(|h| h.0), head.as_ref().map(|h| hex(&h.1)));
    Ok(Json(match audit::verify_chain(&mut tx, p.tenant_id).await {
        Ok(n) => VerifyOut { ok: true, entries: n, head_seq, head_hash, error: None },
        Err(Error::Conflict(msg)) => VerifyOut { ok: false, entries: 0, head_seq, head_hash, error: Some(msg) },
        Err(e) => return Err(e),
    }))
}

// ------------------------------------------------------------------- keys

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct KeyVersionOut {
    version: i32,
    kek_id: String,
    created_at: String,
    /// SHA-256 prefix of the *wrapped* key: identifies the row, reveals nothing.
    wrapped_dek_fingerprint: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct KeysOut {
    active_version: i32,
    /// `aws_kms` or `local_kek`
    provider: &'static str,
    kek_id: String,
    last_rotated_at: Option<String>,
    wrapped_dek_fingerprint: String,
    versions: Vec<KeyVersionOut>,
}

async fn keys_out(st: &ApiState, p: &Principal) -> Result<KeysOut> {
    // Make sure the tenant has a key before describing it.
    st.ctx.cipher.seal(p.tenant_id, b"probe", b"").await?;
    let mut tx = st.ctx.db.tenant_tx(p.tenant_id).await?;
    let rows = sqlx::query("SELECT version, kek_id, created_at, encode(substring(sha256(wrapped_dek) for 8), 'hex') AS fp FROM tenant_keys WHERE tenant_id = $1 ORDER BY version DESC")
        .bind(p.tenant_id.0)
        .fetch_all(&mut *tx)
        .await?;
    let versions: Vec<KeyVersionOut> = rows
        .iter()
        .map(|r| KeyVersionOut { version: r.get("version"), kek_id: r.get("kek_id"), created_at: rfc3339(r.get("created_at")), wrapped_dek_fingerprint: r.get("fp") })
        .collect();
    let top = versions.first().ok_or_else(|| Error::internal(anyhow::anyhow!("tenant has no key")))?;
    Ok(KeysOut {
        active_version: top.version,
        provider: if top.kek_id.starts_with("aws-kms:") { "aws_kms" } else { "local_kek" },
        kek_id: top.kek_id.clone(),
        last_rotated_at: Some(top.created_at.clone()),
        wrapped_dek_fingerprint: top.wrapped_dek_fingerprint.clone(),
        versions,
    })
}

async fn get_keys(State(st): State<ApiState>, p: Principal) -> Result<Json<KeysOut>> {
    p.require(Permission::AdminManage)?;
    Ok(Json(keys_out(&st, &p).await?))
}

/// Start a new data-encryption key version for the org. New data is sealed
/// under it; existing data stays readable under the earlier versions.
async fn rotate_key(State(st): State<ApiState>, p: Principal) -> Result<Json<KeysOut>> {
    admin_write(&p)?;
    let version = st.ctx.cipher.rotate_dek(p.tenant_id).await?;
    let mut tx = st.ctx.db.tenant_tx(p.tenant_id).await?;
    audit::append(&mut tx, &p, "keys.dek_rotated", "tenant_keys", serde_json::json!({ "version": version })).await?;
    tx.commit().await?;
    Ok(Json(keys_out(&st, &p).await?))
}
