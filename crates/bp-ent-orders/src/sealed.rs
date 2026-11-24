//! Sealing helpers: JSON payload ⇄ envelope ciphertext with a bound AAD.
//!
//! The AAD names the table, row and column a blob belongs to. Core adds the
//! tenant id and key version on top, so a ciphertext only opens for the
//! tenant, row and column it was sealed for.

use bp_ent_core::{AppCtx, Error, Result, TenantId};
use serde::de::DeserializeOwned;
use serde::Serialize;
use uuid::Uuid;

/// `table|row_id|column`
pub fn aad(table: &str, row: Uuid, column: &str) -> String {
    format!("{table}|{row}|{column}")
}

pub async fn seal_json<T: Serialize>(ctx: &AppCtx, tenant: TenantId, aad: &str, value: &T) -> Result<Vec<u8>> {
    let plain = serde_json::to_vec(value).map_err(Error::internal)?;
    ctx.cipher.seal(tenant, aad.as_bytes(), &plain).await
}

pub async fn open_json<T: DeserializeOwned>(ctx: &AppCtx, tenant: TenantId, aad: &str, blob: &[u8]) -> Result<T> {
    let plain = ctx.cipher.open(tenant, aad.as_bytes(), blob).await?;
    // A decode failure must not echo plaintext into the error chain.
    serde_json::from_slice(&plain).map_err(|_| Error::internal(anyhow::anyhow!("sealed payload has an unexpected shape")))
}

pub fn key_version(blob: &[u8]) -> u32 {
    bp_ent_core::EnvelopeCipher::blob_key_version(blob).unwrap_or(0)
}
