//! Envelope encryption helpers for bridge secrets, configs, and quarantined payloads.

use bp_ent_core::{AppCtx, Error, Result, TenantId};
use serde::de::DeserializeOwned;
use serde::Serialize;
use uuid::Uuid;

/// `table|row_id|column`
pub fn aad(table: &str, row: Uuid, column: &str) -> String {
    format!("{table}|{row}|{column}")
}

pub async fn seal_bytes(ctx: &AppCtx, tenant: TenantId, aad: &str, plain: &[u8]) -> Result<Vec<u8>> {
    ctx.cipher.seal(tenant, aad.as_bytes(), plain).await
}

pub async fn open_bytes(ctx: &AppCtx, tenant: TenantId, aad: &str, blob: &[u8]) -> Result<Vec<u8>> {
    ctx.cipher.open(tenant, aad.as_bytes(), blob).await
}

pub async fn seal_str(ctx: &AppCtx, tenant: TenantId, aad: &str, plain: &str) -> Result<Vec<u8>> {
    ctx.cipher.seal_str(tenant, aad.as_bytes(), plain).await
}

pub async fn open_str(ctx: &AppCtx, tenant: TenantId, aad: &str, blob: &[u8]) -> Result<String> {
    ctx.cipher.open_str(tenant, aad.as_bytes(), blob).await
}

pub async fn seal_json<T: Serialize>(ctx: &AppCtx, tenant: TenantId, aad: &str, value: &T) -> Result<Vec<u8>> {
    let plain = serde_json::to_vec(value).map_err(Error::internal)?;
    ctx.cipher.seal(tenant, aad.as_bytes(), &plain).await
}

pub async fn open_json<T: DeserializeOwned>(ctx: &AppCtx, tenant: TenantId, aad: &str, blob: &[u8]) -> Result<T> {
    let plain = ctx.cipher.open(tenant, aad.as_bytes(), blob).await?;
    serde_json::from_slice(&plain)
        .map_err(|_| Error::internal(anyhow::anyhow!("sealed bridge payload has an unexpected shape")))
}

/// Produce a non-sensitive display hint for a secret without leaking it.
pub fn secret_hint(secret: &str) -> String {
    let n = secret.chars().count();
    if n >= 8 {
        let suffix: String = secret.chars().skip(n - 4).collect();
        format!("...{suffix}")
    } else if n > 0 {
        "configured".to_string()
    } else {
        "unset".to_string()
    }
}
