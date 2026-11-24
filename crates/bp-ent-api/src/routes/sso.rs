//! Sign-in: org SSO (OIDC / SAML) for the browser portal and the desktop app.
//!
//! Browser: `start` -> IdP -> `callback` -> session cookie -> portal.
//! Desktop: the same flow in the system browser, ending in a one-time code
//! sent to the app's loopback listener, which the app exchanges (with its
//! PKCE-style verifier) for an API token. No VPN, no pasted secrets.

use crate::oidc::{pkce_challenge, IdClaims, OidcClient};
use crate::state::{client_ip, rfc3339, ApiState};
use axum::extract::{ConnectInfo, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use bp_ent_core::crypto::{ct_eq, random_token, sha256};
use bp_ent_core::rbac::Scopes;
use bp_ent_core::{audit, auth, AppCtx, AuthKind, Error, Principal, Result, Role, TenantId, Tx, UserId};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::net::SocketAddr;
use std::time::Duration;
use uuid::Uuid;

const LOGIN_TTL_SECS: i64 = 600;
const DESKTOP_CODE_TTL_SECS: i64 = 120;
const DESKTOP_TOKEN_TTL: Duration = Duration::from_secs(30 * 24 * 3600);

pub fn router() -> Router<ApiState> {
    Router::new()
        .route("/v1/auth/providers", get(providers))
        .route("/v1/auth/oauth/start", post(start_post).get(start_get))
        .route("/v1/auth/callback", get(callback))
        .route("/v1/auth/saml/acs", post(crate::saml::acs))
        .route("/v1/auth/saml/{idp_id}/metadata", get(crate::saml::metadata))
        .route("/v1/auth/desktop/token", post(desktop_token))
        .route("/v1/auth/logout", post(logout))
}

// ------------------------------------------------------------------ model

#[derive(Clone)]
pub struct Idp {
    pub id: Uuid,
    pub kind: String,
    pub issuer: Option<String>,
    pub client_id: Option<String>,
    pub client_secret_enc: Option<Vec<u8>>,
    pub directory_id: Option<String>,
    pub allowed_domains: Vec<String>,
    pub trust_email: bool,
    pub saml_entity_id: Option<String>,
    pub saml_sso_url: Option<String>,
    pub saml_cert_pem: Option<String>,
    pub auto_provision: bool,
    pub default_role: String,
}

const IDP_COLS: &str = "id, kind, issuer, client_id, client_secret_enc, directory_id, allowed_domains, trust_email, \
                        saml_entity_id, saml_sso_url, saml_cert_pem, auto_provision, default_role";

fn idp_from(r: &sqlx::postgres::PgRow) -> Idp {
    Idp {
        id: r.get("id"),
        kind: r.get("kind"),
        issuer: r.get("issuer"),
        client_id: r.get("client_id"),
        client_secret_enc: r.get("client_secret_enc"),
        directory_id: r.get("directory_id"),
        allowed_domains: r.get("allowed_domains"),
        trust_email: r.get("trust_email"),
        saml_entity_id: r.get("saml_entity_id"),
        saml_sso_url: r.get("saml_sso_url"),
        saml_cert_pem: r.get("saml_cert_pem"),
        auto_provision: r.get("auto_provision"),
        default_role: r.get("default_role"),
    }
}

pub async fn load_idp(tx: &mut Tx, tenant: TenantId, id: Uuid) -> Result<Idp> {
    let r = sqlx::query(&format!("SELECT {IDP_COLS} FROM identity_providers WHERE tenant_id = $1 AND id = $2 AND enabled"))
        .bind(tenant.0)
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(Error::NotFound)?;
    Ok(idp_from(&r))
}

pub fn client_secret_aad(idp_id: Uuid) -> Vec<u8> {
    format!("identity_providers|{idp_id}|client_secret").into_bytes()
}

pub fn callback_url(ctx: &AppCtx) -> String {
    format!("{}/v1/auth/callback", ctx.config.api_base_url)
}

/// What the identity provider asserted about the person, after its
/// signature has been verified.
#[derive(Clone, Debug)]
pub struct Identity {
    pub subject: String,
    pub email: String,
    pub name: String,
}

/// Turn verified OIDC claims into an identity, applying the checks that tie
/// the account to the customer's own directory.
pub fn identity_from_claims(idp: &Idp, c: &IdClaims) -> Result<Identity> {
    let email = match idp.kind.as_str() {
        "google" => {
            if c.email_verified() != Some(true) {
                return Err(Error::Forbidden);
            }
            // A Workspace-pinned provider must see that Workspace's `hd`.
            if let Some(hd) = &idp.directory_id {
                if c.hd.as_deref().map(str::to_ascii_lowercase) != Some(hd.to_ascii_lowercase()) {
                    return Err(Error::Forbidden);
                }
            }
            c.email.clone()
        }
        "microsoft" => {
            // Entra does not send email_verified; the directory (tid) pin is
            // what proves the account belongs to the customer.
            let want = idp.directory_id.as_deref().ok_or(Error::Forbidden)?;
            if c.tid.as_deref().map(str::to_ascii_lowercase) != Some(want.to_ascii_lowercase()) {
                return Err(Error::Forbidden);
            }
            c.email.clone().or_else(|| c.preferred_username.clone())
        }
        _ => {
            // Invited users are matched by e-mail on first login, so the
            // address must be one the IdP vouches for. An absent claim only
            // passes if the admin declared this IdP trustworthy for e-mail.
            match c.email_verified() {
                Some(true) => {}
                None if idp.trust_email => {}
                _ => return Err(Error::Forbidden),
            }
            c.email.clone()
        }
    };
    let email = normalize_email(email.as_deref().unwrap_or_default())?;
    check_domain(idp, &email)?;
    Ok(Identity { subject: c.sub.clone(), email, name: c.name.clone().unwrap_or_default() })
}

pub fn normalize_email(raw: &str) -> Result<String> {
    let e = raw.trim().to_ascii_lowercase();
    let ok = e.len() <= 320
        && e.split_once('@').map(|(l, d)| !l.is_empty() && d.contains('.') && !d.starts_with('.') && !d.ends_with('.') && !d.contains('@')).unwrap_or(false)
        && !e.chars().any(|c| c.is_whitespace() || c.is_control());
    if ok {
        Ok(e)
    } else {
        Err(Error::Forbidden)
    }
}

pub fn check_domain(idp: &Idp, email: &str) -> Result<()> {
    if idp.allowed_domains.is_empty() {
        return Ok(());
    }
    let domain = email.rsplit_once('@').map(|(_, d)| d).unwrap_or_default();
    if idp.allowed_domains.iter().any(|d| d.eq_ignore_ascii_case(domain)) {
        Ok(())
    } else {
        Err(Error::Forbidden)
    }
}

/// Map an identity to a user of this tenant:
/// 1. already linked to this IdP subject -> that user;
/// 2. pre-provisioned (invited) by e-mail and not yet linked -> link it;
/// 3. unknown and the IdP has auto-provisioning on -> create with the default role;
/// 4. otherwise refuse.
///
/// A user linked to one IdP subject is never re-linked by e-mail alone, so
/// someone who later controls the same address at the IdP cannot take over
/// the account.
pub async fn resolve_user(tx: &mut Tx, tenant: TenantId, idp: &Idp, who: &Identity) -> Result<(UserId, Role)> {
    let linked = sqlx::query("SELECT id, role, status FROM users WHERE tenant_id = $1 AND idp_id = $2 AND idp_subject = $3")
        .bind(tenant.0)
        .bind(idp.id)
        .bind(&who.subject)
        .fetch_optional(&mut **tx)
        .await?;
    let (id, role, status): (Uuid, String, String) = if let Some(r) = linked {
        (r.get("id"), r.get("role"), r.get("status"))
    } else {
        let by_email = sqlx::query("SELECT id, role, status, idp_subject FROM users WHERE tenant_id = $1 AND email = $2 FOR UPDATE")
            .bind(tenant.0)
            .bind(&who.email)
            .fetch_optional(&mut **tx)
            .await?;
        match by_email {
            Some(r) => {
                if r.get::<Option<String>, _>("idp_subject").is_some() {
                    return Err(Error::Forbidden);
                }
                let id: Uuid = r.get("id");
                sqlx::query("UPDATE users SET idp_id = $3, idp_subject = $4 WHERE tenant_id = $1 AND id = $2")
                    .bind(tenant.0)
                    .bind(id)
                    .bind(idp.id)
                    .bind(&who.subject)
                    .execute(&mut **tx)
                    .await?;
                (id, r.get("role"), r.get("status"))
            }
            None if idp.auto_provision => {
                let id = Uuid::new_v4();
                // default_role can never be org_admin (schema CHECK).
                sqlx::query("INSERT INTO users (id, tenant_id, email, name, role, status, idp_id, idp_subject) VALUES ($1, $2, $3, $4, $5, 'active', $6, $7)")
                    .bind(id)
                    .bind(tenant.0)
                    .bind(&who.email)
                    .bind(&who.name)
                    .bind(&idp.default_role)
                    .bind(idp.id)
                    .bind(&who.subject)
                    .execute(&mut **tx)
                    .await?;
                audit::append_system(tx, tenant, "sso", "user.provisioned", &format!("user:{id}"), serde_json::json!({ "role": idp.default_role, "idp": idp.id })).await?;
                (id, idp.default_role.clone(), "active".into())
            }
            None => return Err(Error::Forbidden),
        }
    };
    if status == "suspended" {
        return Err(Error::Forbidden);
    }
    sqlx::query("UPDATE users SET status = 'active', last_login_at = now(), name = CASE WHEN name = '' THEN $3 ELSE name END WHERE tenant_id = $1 AND id = $2")
        .bind(tenant.0)
        .bind(id)
        .bind(&who.name)
        .execute(&mut **tx)
        .await?;
    Ok((UserId(id), Role::parse(&role)?))
}

// ------------------------------------------------------------- start

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartReq {
    /// Org slug (`acme`). Accepts `org` as well.
    #[serde(alias = "org")]
    org_slug: String,
    /// `google` | `microsoft` | `oidc` | `saml`, or use `idpId`.
    #[serde(default)]
    provider: Option<String>,
    #[serde(default)]
    idp_id: Option<Uuid>,
    /// Portal path to land on after login.
    #[serde(default)]
    return_to: Option<String>,
    /// Desktop sign-in: loopback URL of the app's listener and its S256 challenge.
    #[serde(default)]
    desktop_redirect: Option<String>,
    #[serde(default)]
    desktop_challenge: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StartResp {
    authorize_url: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProviderOut {
    id: Uuid,
    provider: String,
    display_name: String,
}

#[derive(Deserialize)]
struct OrgQuery {
    org: String,
}

/// Which sign-in buttons to show for an org. Unknown orgs get an empty list
/// (no way to tell "no such org" from "no providers").
async fn providers(State(st): State<ApiState>, Query(q): Query<OrgQuery>) -> Result<Json<Vec<ProviderOut>>> {
    let Some(tenant) = st.ctx.db.tenant_by_slug(&q.org).await? else {
        return Ok(Json(vec![]));
    };
    let mut tx = st.ctx.db.tenant_tx(tenant).await?;
    let rows = sqlx::query("SELECT id, kind, display_name FROM identity_providers WHERE tenant_id = $1 AND enabled ORDER BY created_at")
        .bind(tenant.0)
        .fetch_all(&mut *tx)
        .await?;
    Ok(Json(rows.iter().map(|r| ProviderOut { id: r.get("id"), provider: r.get("kind"), display_name: r.get("display_name") }).collect()))
}

/// A path inside the portal: starts with one `/`, no scheme tricks.
pub fn safe_return_path(p: Option<&str>) -> String {
    match p {
        Some(p) if p.starts_with('/') && !p.starts_with("//") && !p.contains('\\') && !p.chars().any(|c| c.is_control()) && p.len() <= 512 => p.to_string(),
        _ => "/".to_string(),
    }
}

/// Desktop redirect targets must be a loopback listener on the user's own machine.
pub fn check_desktop_redirect(raw: &str) -> Result<String> {
    let u = url::Url::parse(raw).map_err(|_| Error::invalid("invalid desktop redirect"))?;
    let loopback = match u.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        _ => false,
    };
    if u.scheme() != "http" || !loopback || u.port().is_none() || !u.username().is_empty() || u.password().is_some() || u.fragment().is_some() {
        return Err(Error::invalid("desktop redirect must be http://127.0.0.1:<port>/..."));
    }
    Ok(u.into())
}

fn login_cookie_name(ctx: &AppCtx) -> &'static str {
    if ctx.config.cookie_secure {
        "__Host-bpe_login"
    } else {
        "bpe_login"
    }
}

pub fn set_cookie(ctx: &AppCtx, name: &str, value: &str, max_age_secs: i64) -> HeaderValue {
    cookie_with(ctx, name, value, max_age_secs, "Lax")
}

fn cookie_with(ctx: &AppCtx, name: &str, value: &str, max_age_secs: i64, same_site: &str) -> HeaderValue {
    let secure = if ctx.config.cookie_secure { "; Secure" } else { "" };
    HeaderValue::from_str(&format!("{name}={value}; Path=/; HttpOnly; SameSite={same_site}; Max-Age={max_age_secs}{secure}")).expect("cookie value is token68")
}

fn rate_limit(st: &ApiState, headers: &HeaderMap, peer: Option<SocketAddr>) -> Result<()> {
    let key = client_ip(headers, peer, st.cfg.trusted_proxy_hops).map(|ip| ip.to_string()).unwrap_or_else(|| "unknown".into());
    if st.limiter.allow(&key) {
        Ok(())
    } else {
        Err(Error::TooManyRequests)
    }
}

async fn start_inner(st: &ApiState, req: StartReq) -> Result<(String, HeaderValue)> {
    let ctx = &st.ctx;
    // Unknown org and unknown provider look the same from outside.
    let tenant = ctx.db.tenant_by_slug(&req.org_slug).await?.ok_or(Error::NotFound)?;
    let mut tx = ctx.db.tenant_tx(tenant).await?;
    let row = match (req.idp_id, req.provider.as_deref()) {
        (Some(id), _) => sqlx::query(&format!("SELECT {IDP_COLS} FROM identity_providers WHERE tenant_id = $1 AND id = $2 AND enabled"))
            .bind(tenant.0)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?,
        (None, Some(kind)) => sqlx::query(&format!("SELECT {IDP_COLS} FROM identity_providers WHERE tenant_id = $1 AND kind = $2 AND enabled ORDER BY created_at LIMIT 1"))
            .bind(tenant.0)
            .bind(kind)
            .fetch_optional(&mut *tx)
            .await?,
        (None, None) => return Err(Error::invalid("provider or idpId is required")),
    };
    let idp = idp_from(&row.ok_or(Error::NotFound)?);

    let desktop = match (&req.desktop_redirect, &req.desktop_challenge) {
        (Some(r), Some(c)) => {
            if c.len() != 43 || !c.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_') {
                return Err(Error::invalid("desktopChallenge must be a base64url SHA-256"));
            }
            Some((check_desktop_redirect(r)?, c.clone()))
        }
        (None, None) => None,
        _ => return Err(Error::invalid("desktopRedirect and desktopChallenge go together")),
    };

    let secret = random_token(32);
    let state = format!("{}.{}", tenant.0.simple(), secret);
    let nonce = random_token(24);
    let verifier = random_token(48);
    let state_hash = sha256(state.as_bytes());
    let verifier_enc = ctx.cipher.seal(tenant, b"login_states|pkce", verifier.as_bytes()).await?;

    sqlx::query("DELETE FROM login_states WHERE tenant_id = $1 AND expires_at < now()").bind(tenant.0).execute(&mut *tx).await?;
    sqlx::query(
        "INSERT INTO login_states (tenant_id, state_hash, idp_id, pkce_verifier_enc, nonce, return_to, desktop_redirect, desktop_challenge, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now() + make_interval(secs => $9))",
    )
    .bind(tenant.0)
    .bind(state_hash.as_slice())
    .bind(idp.id)
    .bind(&verifier_enc)
    .bind(&nonce)
    .bind(safe_return_path(req.return_to.as_deref()))
    .bind(desktop.as_ref().map(|d| d.0.clone()))
    .bind(desktop.as_ref().map(|d| d.1.clone()))
    .bind(LOGIN_TTL_SECS as f64)
    .execute(&mut *tx)
    .await?;

    let url = if idp.kind == "saml" {
        crate::saml::authn_request_url(ctx, &idp, &state)?
    } else {
        let issuer = idp.issuer.as_deref().ok_or(Error::NotFound)?;
        let (disco, _) = st.oidc.provider(&ctx.http, issuer).await?;
        let hd = (idp.kind == "google").then_some(idp.directory_id.as_deref()).flatten();
        OidcClient::authorize_url(&disco, idp.client_id.as_deref().unwrap_or_default(), &callback_url(ctx), &state, &nonce, &verifier, hd)?
    };
    tx.commit().await?;
    // Binds the flow to this browser: the callback must present the same value.
    // A SAML response comes back as a cross-site POST, which a Lax cookie
    // would not accompany; that short-lived binding cookie (never the
    // session) is SameSite=None, which browsers only accept over https.
    let same_site = if idp.kind == "saml" {
        if !ctx.config.cookie_secure {
            return Err(Error::invalid("SAML sign-in needs https"));
        }
        "None"
    } else {
        "Lax"
    };
    Ok((url, cookie_with(ctx, login_cookie_name(ctx), &secret, LOGIN_TTL_SECS, same_site)))
}

async fn start_post(State(st): State<ApiState>, ConnectInfo(peer): ConnectInfo<SocketAddr>, headers: HeaderMap, Json(req): Json<StartReq>) -> Result<Response> {
    rate_limit(&st, &headers, Some(peer))?;
    let (url, cookie) = start_inner(&st, req).await?;
    Ok(([(header::SET_COOKIE, cookie)], Json(StartResp { authorize_url: url })).into_response())
}

/// Same as POST, for plain navigation (the desktop app opens this URL in the browser).
async fn start_get(State(st): State<ApiState>, ConnectInfo(peer): ConnectInfo<SocketAddr>, headers: HeaderMap, Query(req): Query<StartReq>) -> Result<Response> {
    rate_limit(&st, &headers, Some(peer))?;
    let (url, cookie) = start_inner(&st, req).await?;
    Ok(([(header::SET_COOKIE, cookie)], Redirect::to(&url)).into_response())
}

// ---------------------------------------------------------- callback

#[derive(Deserialize)]
struct CallbackQuery {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

pub struct PendingLogin {
    pub tenant: TenantId,
    pub idp_id: Uuid,
    pub pkce_verifier: String,
    pub nonce: String,
    pub return_to: String,
    pub desktop: Option<(String, String)>,
}

/// Consume the in-flight login named by `state` (single use), checking that
/// it is being finished in the browser that started it.
pub async fn take_pending_login(ctx: &AppCtx, headers: &HeaderMap, state: &str) -> Result<PendingLogin> {
    let (tenant_hex, secret) = state.split_once('.').ok_or(Error::Unauthorized)?;
    let tenant = TenantId(Uuid::try_parse(tenant_hex).map_err(|_| Error::Unauthorized)?);
    let cookie = bp_ent_core::http::cookie(headers, login_cookie_name(ctx)).ok_or(Error::Unauthorized)?;
    if !ct_eq(cookie.as_bytes(), secret.as_bytes()) {
        return Err(Error::Unauthorized);
    }
    let mut tx = ctx.db.tenant_tx(tenant).await?;
    let row = sqlx::query(
        "DELETE FROM login_states WHERE tenant_id = $1 AND state_hash = $2 AND expires_at > now() \
         RETURNING idp_id, pkce_verifier_enc, nonce, return_to, desktop_redirect, desktop_challenge",
    )
    .bind(tenant.0)
    .bind(sha256(state.as_bytes()).as_slice())
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(Error::Unauthorized)?;
    tx.commit().await?;
    let verifier = ctx.cipher.open_str(tenant, b"login_states|pkce", &row.get::<Vec<u8>, _>("pkce_verifier_enc")).await?;
    let desktop = match (row.get::<Option<String>, _>("desktop_redirect"), row.get::<Option<String>, _>("desktop_challenge")) {
        (Some(r), Some(c)) => Some((r, c)),
        _ => None,
    };
    Ok(PendingLogin {
        tenant,
        idp_id: row.get("idp_id"),
        pkce_verifier: verifier,
        nonce: row.get("nonce"),
        return_to: row.get::<Option<String>, _>("return_to").unwrap_or_else(|| "/".into()),
        desktop,
    })
}

/// The identity is verified: find the user, open a session (browser) or mint
/// a one-time code (desktop), and say where to send the browser.
pub async fn complete_login(ctx: &AppCtx, pending: &PendingLogin, idp: &Idp, who: &Identity) -> Result<Response> {
    let tenant = pending.tenant;
    let mut tx = ctx.db.tenant_tx(tenant).await?;
    let (user, role) = match resolve_user(&mut tx, tenant, idp, who).await {
        Ok(v) => v,
        Err(e) => {
            // Record the refusal (in its own transaction: the failed one is rolled back).
            tx.rollback().await.ok();
            let mut t2 = ctx.db.tenant_tx(tenant).await?;
            audit::append_system(&mut t2, tenant, "sso", "auth.login_refused", &format!("idp:{}", idp.id), serde_json::json!({ "reason": "not a member" })).await?;
            t2.commit().await?;
            return Err(e);
        }
    };
    let clear_login = set_cookie(ctx, login_cookie_name(ctx), "", 0);

    if let Some((redirect, challenge)) = &pending.desktop {
        let code = format!("{}.{}", tenant.0.simple(), random_token(32));
        sqlx::query("INSERT INTO desktop_codes (tenant_id, code_hash, user_id, challenge, expires_at) VALUES ($1, $2, $3, $4, now() + make_interval(secs => $5))")
            .bind(tenant.0)
            .bind(sha256(code.as_bytes()).as_slice())
            .bind(user.0)
            .bind(challenge)
            .bind(DESKTOP_CODE_TTL_SECS as f64)
            .execute(&mut *tx)
            .await?;
        audit::append_system(&mut tx, tenant, "sso", "auth.desktop_code_issued", &format!("user:{user}"), serde_json::json!({ "idp": idp.id })).await?;
        tx.commit().await?;
        let mut u = url::Url::parse(redirect).map_err(Error::internal)?;
        u.query_pairs_mut().append_pair("code", &code);
        return Ok(([(header::SET_COOKIE, clear_login)], Redirect::to(u.as_str())).into_response());
    }

    let (token_id, token) = auth::issue_token(&mut tx, tenant, user, AuthKind::Session, "browser session", &Scopes::All, ctx.config.session_ttl).await?;
    audit::append_system(&mut tx, tenant, "sso", "auth.login", &format!("user:{user}"), serde_json::json!({ "idp": idp.id, "role": role.as_str(), "session": token_id })).await?;
    tx.commit().await?;

    let session = set_cookie(ctx, ctx.config.session_cookie_name(), token.expose(), ctx.config.session_ttl.as_secs() as i64);
    let target = format!("{}{}", ctx.config.public_origin, pending.return_to);
    let mut resp = Redirect::to(&target).into_response();
    resp.headers_mut().append(header::SET_COOKIE, session);
    resp.headers_mut().append(header::SET_COOKIE, clear_login);
    Ok(resp)
}

/// Failed logins land on the portal's login page with a generic code; the
/// reason stays in the server log / audit trail.
pub fn login_failed(ctx: &AppCtx, e: &Error) -> Response {
    let code = match e {
        Error::Forbidden => "not_allowed",
        Error::TooManyRequests => "rate_limited",
        Error::Upstream(_) => "idp_unavailable",
        _ => "failed",
    };
    if let Error::Internal(c) | Error::Upstream(c) = e {
        tracing::warn!(cause = format!("{c:#}"), "login failed");
    }
    Redirect::to(&format!("{}/login?error={code}", ctx.config.public_origin)).into_response()
}

async fn callback(State(st): State<ApiState>, ConnectInfo(peer): ConnectInfo<SocketAddr>, headers: HeaderMap, Query(q): Query<CallbackQuery>) -> Response {
    let ctx = &st.ctx;
    let run = async {
        rate_limit(&st, &headers, Some(peer))?;
        let state = q.state.as_deref().ok_or(Error::Unauthorized)?;
        // Consume the state first, also when the IdP reports an error.
        let pending = take_pending_login(ctx, &headers, state).await?;
        if q.error.is_some() {
            return Err(Error::Forbidden);
        }
        let code = q.code.as_deref().ok_or(Error::Unauthorized)?;
        let mut tx = ctx.db.tenant_tx(pending.tenant).await?;
        let idp = load_idp(&mut tx, pending.tenant, pending.idp_id).await?;
        tx.commit().await?;
        if idp.kind == "saml" {
            return Err(Error::Unauthorized);
        }
        let secret = match &idp.client_secret_enc {
            Some(enc) => ctx.cipher.open_str(pending.tenant, &client_secret_aad(idp.id), enc).await?,
            None => String::new(),
        };
        let claims = st
            .oidc
            .exchange(
                &ctx.http,
                idp.issuer.as_deref().ok_or(Error::Unauthorized)?,
                idp.client_id.as_deref().unwrap_or_default(),
                &secret,
                &callback_url(ctx),
                code,
                &pending.pkce_verifier,
                &pending.nonce,
            )
            .await?;
        let who = identity_from_claims(&idp, &claims)?;
        complete_login(ctx, &pending, &idp, &who).await
    };
    match run.await {
        Ok(resp) => resp,
        Err(e) => login_failed(ctx, &e),
    }
}

// ----------------------------------------------------- desktop + logout

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DesktopTokenReq {
    code: String,
    code_verifier: String,
    #[serde(default)]
    device_name: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DesktopTokenResp {
    token: String,
    token_id: Uuid,
    expires_at: String,
    tenant_id: TenantId,
    user_id: UserId,
}

/// The desktop app trades its one-time code for an API token. The code alone
/// is not enough: the caller must also know the verifier whose hash was
/// registered when the flow started, so a code intercepted on the loopback
/// redirect is useless to another process.
async fn desktop_token(State(st): State<ApiState>, ConnectInfo(peer): ConnectInfo<SocketAddr>, headers: HeaderMap, Json(req): Json<DesktopTokenReq>) -> Result<Json<DesktopTokenResp>> {
    rate_limit(&st, &headers, Some(peer))?;
    let ctx = &st.ctx;
    let (tenant_hex, _) = req.code.split_once('.').ok_or(Error::Unauthorized)?;
    let tenant = TenantId(Uuid::try_parse(tenant_hex).map_err(|_| Error::Unauthorized)?);
    let mut tx = ctx.db.tenant_tx(tenant).await?;
    // Single use, whether or not the verifier turns out to match.
    let row = sqlx::query("DELETE FROM desktop_codes WHERE tenant_id = $1 AND code_hash = $2 AND expires_at > now() RETURNING user_id, challenge")
        .bind(tenant.0)
        .bind(sha256(req.code.as_bytes()).as_slice())
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(Error::Unauthorized)?;
    let challenge: String = row.get("challenge");
    if !ct_eq(pkce_challenge(&req.code_verifier).as_bytes(), challenge.as_bytes()) {
        tx.commit().await?;
        return Err(Error::Unauthorized);
    }
    let user = UserId(row.get("user_id"));
    let active: bool = sqlx::query_scalar("SELECT status = 'active' FROM users WHERE tenant_id = $1 AND id = $2")
        .bind(tenant.0)
        .bind(user.0)
        .fetch_optional(&mut *tx)
        .await?
        .unwrap_or(false);
    if !active {
        return Err(Error::Unauthorized);
    }
    let name: String = req.device_name.as_deref().unwrap_or("Backplane desktop").chars().filter(|c| !c.is_control()).take(100).collect();
    let (token_id, token) = auth::issue_token(&mut tx, tenant, user, AuthKind::UserToken, &name, &Scopes::All, DESKTOP_TOKEN_TTL).await?;
    audit::append_system(&mut tx, tenant, "sso", "auth.desktop_token_issued", &format!("user:{user}"), serde_json::json!({ "token": token_id })).await?;
    tx.commit().await?;
    Ok(Json(DesktopTokenResp {
        token: token.expose().clone(),
        token_id,
        expires_at: rfc3339(time::OffsetDateTime::now_utc() + DESKTOP_TOKEN_TTL),
        tenant_id: tenant,
        user_id: user,
    }))
}

/// End the current session (or revoke the bearer token used to call this).
async fn logout(State(st): State<ApiState>, headers: HeaderMap) -> Result<Response> {
    let ctx = &st.ctx;
    let clear = set_cookie(ctx, ctx.config.session_cookie_name(), "", 0);
    // Not behind `with_auth`: an expired session must still be able to clear its cookie.
    if let Ok(p) = bp_ent_core::http::authenticate(ctx, &axum::http::Method::POST, &headers).await {
        let mut tx = ctx.db.tenant_tx(p.tenant_id).await?;
        auth::revoke_token(&mut tx, p.tenant_id, p.token_id).await?;
        audit::append(&mut tx, &p, "auth.logout", &format!("user:{}", p.user_id), serde_json::json!({})).await?;
        tx.commit().await?;
    }
    Ok((StatusCode::NO_CONTENT, [(header::SET_COOKIE, clear)]).into_response())
}

pub async fn session_for_tests(ctx: &AppCtx, p: &Principal) -> String {
    let mut tx = ctx.db.tenant_tx(p.tenant_id).await.unwrap();
    let (_, t) = auth::issue_token(&mut tx, p.tenant_id, p.user_id, AuthKind::Session, "test", &Scopes::All, Duration::from_secs(600)).await.unwrap();
    tx.commit().await.unwrap();
    t.expose().clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn idp(kind: &str, directory: Option<&str>, domains: &[&str]) -> Idp {
        Idp {
            id: Uuid::new_v4(),
            kind: kind.into(),
            issuer: None,
            client_id: None,
            client_secret_enc: None,
            directory_id: directory.map(String::from),
            allowed_domains: domains.iter().map(|s| s.to_string()).collect(),
            trust_email: false,
            saml_entity_id: None,
            saml_sso_url: None,
            saml_cert_pem: None,
            auto_provision: false,
            default_role: "engineer".into(),
        }
    }

    fn claims(v: serde_json::Value) -> IdClaims {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn google_requires_verified_email_and_matching_hosted_domain() {
        let g = idp("google", Some("acme.com"), &[]);
        let ok = claims(serde_json::json!({ "sub": "1", "email": "Ann@Acme.com", "email_verified": true, "hd": "acme.com" }));
        assert_eq!(identity_from_claims(&g, &ok).unwrap().email, "ann@acme.com");
        for bad in [
            serde_json::json!({ "sub": "1", "email": "ann@acme.com", "email_verified": false, "hd": "acme.com" }),
            serde_json::json!({ "sub": "1", "email": "ann@acme.com", "hd": "acme.com" }),
            serde_json::json!({ "sub": "1", "email": "ann@acme.com", "email_verified": true, "hd": "evil.com" }),
            // personal Gmail account: no hd at all
            serde_json::json!({ "sub": "1", "email": "ann@gmail.com", "email_verified": true }),
            serde_json::json!({ "sub": "1", "email_verified": true, "hd": "acme.com" }),
        ] {
            assert!(identity_from_claims(&g, &claims(bad.clone())).is_err(), "{bad}");
        }
    }

    #[test]
    fn microsoft_requires_the_pinned_directory() {
        let m = idp("microsoft", Some("11111111-2222-3333-4444-555555555555"), &["acme.com"]);
        let ok = claims(serde_json::json!({ "sub": "1", "preferred_username": "ann@acme.com", "tid": "11111111-2222-3333-4444-555555555555" }));
        assert!(identity_from_claims(&m, &ok).is_ok());
        let other_tid = claims(serde_json::json!({ "sub": "1", "email": "ann@acme.com", "tid": "99999999-2222-3333-4444-555555555555" }));
        assert!(identity_from_claims(&m, &other_tid).is_err());
        let no_tid = claims(serde_json::json!({ "sub": "1", "email": "ann@acme.com" }));
        assert!(identity_from_claims(&m, &no_tid).is_err());
        let wrong_domain = claims(serde_json::json!({ "sub": "1", "email": "ann@other.com", "tid": "11111111-2222-3333-4444-555555555555" }));
        assert!(identity_from_claims(&m, &wrong_domain).is_err());
        // A provider with no directory pinned accepts nobody.
        assert!(identity_from_claims(&idp("microsoft", None, &[]), &ok).is_err());
    }

    #[test]
    fn generic_oidc_rejects_unverified_and_foreign_domains() {
        let o = idp("oidc", None, &["acme.com"]);
        assert!(identity_from_claims(&o, &claims(serde_json::json!({ "sub": "1", "email": "a@acme.com", "email_verified": true }))).is_ok());
        assert!(identity_from_claims(&o, &claims(serde_json::json!({ "sub": "1", "email": "a@acme.com", "email_verified": "true" }))).is_ok());
        // No claim at all: refused unless the admin opted this IdP in.
        let bare = claims(serde_json::json!({ "sub": "1", "email": "a@acme.com" }));
        assert!(identity_from_claims(&o, &bare).is_err());
        let mut trusted = idp("oidc", None, &["acme.com"]);
        trusted.trust_email = true;
        assert!(identity_from_claims(&trusted, &bare).is_ok());
        assert!(identity_from_claims(&trusted, &claims(serde_json::json!({ "sub": "1", "email": "a@acme.com", "email_verified": false }))).is_err());
        assert!(identity_from_claims(&o, &claims(serde_json::json!({ "sub": "1", "email": "a@acme.com", "email_verified": false }))).is_err());
        assert!(identity_from_claims(&o, &claims(serde_json::json!({ "sub": "1", "email": "a@acme.com.evil.com", "email_verified": true }))).is_err());
        assert!(identity_from_claims(&o, &claims(serde_json::json!({ "sub": "1", "email": "a@evil.com@acme.com", "email_verified": true }))).is_err());
        assert!(identity_from_claims(&o, &claims(serde_json::json!({ "sub": "1" }))).is_err());
    }

    #[test]
    fn return_path_cannot_leave_the_portal() {
        assert_eq!(safe_return_path(Some("/boards/1?tab=bom")), "/boards/1?tab=bom");
        for bad in ["//evil.example", "https://evil.example", "/\\evil.example", "evil", "", "/a\nb"] {
            assert_eq!(safe_return_path(Some(bad)), "/", "{bad:?}");
        }
        assert_eq!(safe_return_path(None), "/");
    }

    #[test]
    fn desktop_redirect_must_be_loopback() {
        assert!(check_desktop_redirect("http://127.0.0.1:49152/callback").is_ok());
        assert!(check_desktop_redirect("http://[::1]:49152/cb").is_ok());
        for bad in [
            "https://evil.example/cb",
            "http://evil.example:8080/cb",
            "http://127.0.0.1/cb",
            "http://localhost:8080/cb",
            "http://127.0.0.1.evil.example:8080/",
            "http://user@127.0.0.1:8080/",
            "backplane://cb",
            "http://10.0.0.1:8080/",
        ] {
            assert!(check_desktop_redirect(bad).is_err(), "{bad}");
        }
    }
}
