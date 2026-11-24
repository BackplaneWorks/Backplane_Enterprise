//! Bearer credentials: sessions, user API tokens and device tokens.
//!
//! A token is `bpe_<kind>_<tenant-hex>_<secret>`. The tenant in it is only a
//! *claim* that tells the verifier which tenant to look in: verification runs
//! inside that tenant's RLS scope and looks up the SHA-256 of the whole
//! token, so a token with a forged tenant simply matches nothing. No query
//! ever needs to search across tenants, and the database stores no token,
//! only its hash.

use crate::crypto::{ct_eq, random_token, sha256};
use crate::rbac::Scopes;
use crate::{AppCtx, AuthKind, Db, Error, Principal, Result, Role, Secret, TenantId, Tx, UserId};
use sqlx::Row;
use std::time::Duration;
use uuid::Uuid;

/// Longest lifetime any credential may be issued with.
pub const MAX_TOKEN_TTL: Duration = Duration::from_secs(366 * 24 * 3600);

fn kind_char(kind: AuthKind) -> &'static str {
    match kind {
        AuthKind::Session => "s",
        AuthKind::UserToken => "u",
        AuthKind::DeviceToken => "d",
    }
}

fn kind_from(s: &str) -> Option<AuthKind> {
    Some(match s {
        "s" => AuthKind::Session,
        "u" => AuthKind::UserToken,
        "d" => AuthKind::DeviceToken,
        _ => return None,
    })
}

/// Split a token into its claimed kind and tenant. Says nothing about validity.
pub fn parse_token(token: &str) -> Option<(AuthKind, TenantId)> {
    let mut parts = token.split('_');
    if parts.next()? != "bpe" {
        return None;
    }
    let kind = kind_from(parts.next()?)?;
    let tenant_hex = parts.next()?;
    let secret = parts.next()?;
    // The secret is base64url and may itself contain '_': accept the rest.
    let rest_ok = secret.len() + parts.map(|p| p.len() + 1).sum::<usize>() >= 32;
    if tenant_hex.len() != 32 || !rest_ok || token.len() > 200 {
        return None;
    }
    Some((kind, TenantId(Uuid::try_parse(tenant_hex).ok()?)))
}

/// Create a credential for `user`. Returns its id and the token, which is
/// shown once and cannot be recovered.
pub async fn issue_token(
    tx: &mut Tx,
    tenant: TenantId,
    user: UserId,
    kind: AuthKind,
    name: &str,
    scopes: &Scopes,
    ttl: Duration,
) -> Result<(Uuid, Secret<String>)> {
    if ttl.is_zero() || ttl > MAX_TOKEN_TTL {
        return Err(Error::invalid("token lifetime must be between 1 second and 366 days"));
    }
    if name.len() > 200 {
        return Err(Error::invalid("token name is too long"));
    }
    let token = format!("bpe_{}_{}_{}", kind_char(kind), tenant.0.simple(), random_token(32));
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO auth_tokens (id, tenant_id, user_id, kind, name, token_hash, scopes, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, now() + make_interval(secs => $8))",
    )
    .bind(id)
    .bind(tenant.0)
    .bind(user.0)
    .bind(kind_char(kind))
    .bind(name)
    .bind(sha256(token.as_bytes()).as_slice())
    .bind(scopes.to_strings())
    .bind(ttl.as_secs_f64())
    .execute(&mut **tx)
    .await?;
    Ok((id, Secret::new(token)))
}

/// Verify a bearer token and return who it belongs to. Every failure is the
/// same `Unauthorized`.
pub async fn verify_bearer(ctx: &AppCtx, token: &str) -> Result<Principal> {
    verify_token(&ctx.db, token).await
}

pub async fn verify_token(db: &Db, token: &str) -> Result<Principal> {
    let (kind, tenant) = parse_token(token).ok_or(Error::Unauthorized)?;
    let hash = sha256(token.as_bytes());
    let mut tx = db.tenant_tx(tenant).await?;
    let row = sqlx::query(
        "SELECT t.id, t.token_hash, t.kind, t.scopes, t.user_id, u.email, u.role, \
                (t.last_used_at IS NULL OR t.last_used_at < now() - interval '5 minutes') AS stale \
         FROM auth_tokens t \
         JOIN users u ON u.tenant_id = t.tenant_id AND u.id = t.user_id \
         JOIN tenants o ON o.id = t.tenant_id \
         WHERE t.tenant_id = $1 AND t.token_hash = $2 \
           AND t.revoked_at IS NULL AND t.expires_at > now() \
           AND u.status = 'active' AND o.status = 'active'",
    )
    .bind(tenant.0)
    .bind(hash.as_slice())
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(Error::Unauthorized)?;

    let stored: Vec<u8> = row.get("token_hash");
    if !ct_eq(&stored, &hash) || row.get::<String, _>("kind") != kind_char(kind) {
        return Err(Error::Unauthorized);
    }
    let id: Uuid = row.get("id");
    if row.get::<bool, _>("stale") {
        sqlx::query("UPDATE auth_tokens SET last_used_at = now() WHERE tenant_id = $1 AND id = $2")
            .bind(tenant.0)
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    let principal = Principal {
        tenant_id: tenant,
        user_id: UserId(row.get("user_id")),
        role: Role::parse(&row.get::<String, _>("role")).map_err(|_| Error::Unauthorized)?,
        email: row.get("email"),
        auth: kind,
        scopes: Scopes::parse(&row.get::<Vec<String>, _>("scopes")),
        token_id: id,
    };
    tx.commit().await?;
    Ok(principal)
}

/// Revoke one credential (logout, token deletion). Returns whether it existed.
pub async fn revoke_token(tx: &mut Tx, tenant: TenantId, token_id: Uuid) -> Result<bool> {
    let n = sqlx::query("UPDATE auth_tokens SET revoked_at = now() WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL")
        .bind(tenant.0)
        .bind(token_id)
        .execute(&mut **tx)
        .await?
        .rows_affected();
    Ok(n > 0)
}

/// Revoke everything a user holds (suspension, role change, offboarding).
pub async fn revoke_user_tokens(tx: &mut Tx, tenant: TenantId, user: UserId) -> Result<u64> {
    Ok(sqlx::query("UPDATE auth_tokens SET revoked_at = now() WHERE tenant_id = $1 AND user_id = $2 AND revoked_at IS NULL")
        .bind(tenant.0)
        .bind(user.0)
        .execute(&mut **tx)
        .await?
        .rows_affected())
}

/// Delete credentials that expired or were revoked more than 30 days ago.
pub async fn purge_expired(tx: &mut Tx, tenant: TenantId) -> Result<u64> {
    Ok(sqlx::query(
        "DELETE FROM auth_tokens WHERE tenant_id = $1 AND (expires_at < now() - interval '30 days' OR revoked_at < now() - interval '30 days')",
    )
    .bind(tenant.0)
    .execute(&mut **tx)
    .await?
    .rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_only_well_formed_tokens() {
        let t = TenantId::new();
        let good = format!("bpe_u_{}_{}", t.0.simple(), random_token(32));
        assert_eq!(parse_token(&good), Some((AuthKind::UserToken, t)));
        // base64url secrets may contain '_' and '-'
        let good = format!("bpe_s_{}_{}", t.0.simple(), "a_b-".repeat(11));
        assert_eq!(parse_token(&good), Some((AuthKind::Session, t)));

        for bad in [
            String::new(),
            "bpe".into(),
            format!("xxx_u_{}_{}", t.0.simple(), random_token(32)),
            format!("bpe_z_{}_{}", t.0.simple(), random_token(32)),
            format!("bpe_u_{}_{}", "not-a-uuid", random_token(32)),
            format!("bpe_u_{}_short", t.0.simple()),
            format!("bpe_u_{}", t.0.simple()),
            format!("bpe_u_{}_{}", t.0.simple(), "a".repeat(300)),
        ] {
            assert_eq!(parse_token(&bad), None, "{bad}");
        }
    }
}
