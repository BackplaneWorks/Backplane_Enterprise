//! Order documents (quotes, purchase orders, invoices), sealed at rest.
//!
//! Bytes are encrypted before they reach PostgreSQL and are only ever served
//! back as an opaque download (`application/octet-stream`, `attachment`,
//! `nosniff`): the portal never renders an uploaded file.

use crate::model::MAX_DOCUMENT_BYTES;
use crate::orders;
use crate::sealed::{aad, open_json, seal_json};
use crate::Svc;
use base64::Engine;
use bp_ent_core::{audit, Error, Permission, Principal, Result};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use time::OffsetDateTime;
use uuid::Uuid;

const KINDS: [&str; 4] = ["quote", "purchase_order", "invoice", "other"];

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DocumentUpload {
    pub kind: String,
    pub file_name: String,
    #[serde(default)]
    pub media_type: String,
    /// Standard base64.
    pub content_base64: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Meta {
    file_name: String,
    media_type: String,
    size: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DocumentView {
    pub id: Uuid,
    pub kind: String,
    pub file_name: String,
    pub media_type: String,
    pub size: usize,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// A file name safe to put in `Content-Disposition`: no path, no quotes, no
/// control characters.
pub fn safe_file_name(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or("");
    let cleaned: String = base
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ' ' | '(' | ')'))
        .take(120)
        .collect();
    let cleaned = cleaned.trim().trim_start_matches('.').to_string();
    if cleaned.is_empty() {
        "document".into()
    } else {
        cleaned
    }
}

pub async fn upload(svc: &Svc, who: &Principal, order: Uuid, up: &DocumentUpload) -> Result<DocumentView> {
    who.require(Permission::OrdersWrite)?;
    let tenant = who.tenant_id;
    if !KINDS.contains(&up.kind.as_str()) {
        return Err(Error::invalid("unknown document kind"));
    }
    if up.content_base64.len() > MAX_DOCUMENT_BYTES * 4 / 3 + 8 {
        return Err(Error::invalid("document is larger than 5 MB"));
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(up.content_base64.trim())
        .map_err(|_| Error::invalid("document content is not valid base64"))?;
    if bytes.is_empty() || bytes.len() > MAX_DOCUMENT_BYTES {
        return Err(Error::invalid("document is empty or larger than 5 MB"));
    }
    let media_type = if up.media_type.len() <= 100
        && up.media_type.bytes().all(|b| b.is_ascii_alphanumeric() || b"/.+-".contains(&b))
    {
        up.media_type.to_ascii_lowercase()
    } else {
        String::new()
    };
    let meta = Meta { file_name: safe_file_name(&up.file_name), media_type, size: bytes.len() };
    let id = Uuid::new_v4();
    let meta_sealed = seal_json(&svc.ctx, tenant, &aad("order_documents", id, "meta_sealed"), &meta).await?;
    let content_sealed = svc
        .ctx
        .cipher
        .seal(tenant, aad("order_documents", id, "content_sealed").as_bytes(), &bytes)
        .await?;

    let mut tx = svc.ctx.db.tenant_tx(tenant).await?;
    orders::load(&mut tx, tenant, order, false).await?;
    let created_at: OffsetDateTime = sqlx::query(
        "INSERT INTO order_documents (id, tenant_id, order_id, kind, meta_sealed, content_sealed, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING created_at",
    )
    .bind(id)
    .bind(tenant.0)
    .bind(order)
    .bind(&up.kind)
    .bind(&meta_sealed)
    .bind(&content_sealed)
    .bind(who.user_id.0)
    .fetch_one(&mut *tx)
    .await?
    .try_get("created_at")?;
    audit::append(&mut tx, who, "order.document_added", &format!("order:{order}"), serde_json::json!({ "document": id, "kind": up.kind })).await?;
    tx.commit().await?;
    Ok(DocumentView { id, kind: up.kind.clone(), file_name: meta.file_name, media_type: meta.media_type, size: meta.size, created_at })
}

pub async fn list(svc: &Svc, who: &Principal, order: Uuid) -> Result<Vec<DocumentView>> {
    who.require(Permission::OrdersRead)?;
    let tenant = who.tenant_id;
    let mut tx = svc.ctx.db.tenant_tx(tenant).await?;
    orders::load(&mut tx, tenant, order, false).await?;
    let rows = sqlx::query(
        "SELECT id, kind, meta_sealed, created_at FROM order_documents WHERE tenant_id = $1 AND order_id = $2 ORDER BY created_at LIMIT 200",
    )
    .bind(tenant.0)
    .bind(order)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let id: Uuid = r.try_get("id")?;
        let blob: Vec<u8> = r.try_get("meta_sealed")?;
        let meta: Meta = open_json(&svc.ctx, tenant, &aad("order_documents", id, "meta_sealed"), &blob).await?;
        out.push(DocumentView {
            id,
            kind: r.try_get("kind")?,
            file_name: meta.file_name,
            media_type: meta.media_type,
            size: meta.size,
            created_at: r.try_get("created_at")?,
        });
    }
    Ok(out)
}

/// Returns `(file name, bytes)`.
pub async fn download(svc: &Svc, who: &Principal, order: Uuid, doc: Uuid) -> Result<(String, Vec<u8>)> {
    who.require(Permission::OrdersRead)?;
    let tenant = who.tenant_id;
    let mut tx = svc.ctx.db.tenant_tx(tenant).await?;
    let row = sqlx::query(
        "SELECT meta_sealed, content_sealed FROM order_documents WHERE tenant_id = $1 AND order_id = $2 AND id = $3",
    )
    .bind(tenant.0)
    .bind(order)
    .bind(doc)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(Error::NotFound)?;
    audit::append(&mut tx, who, "order.document_downloaded", &format!("order:{order}"), serde_json::json!({ "document": doc })).await?;
    tx.commit().await?;
    let meta_blob: Vec<u8> = row.try_get("meta_sealed")?;
    let content_blob: Vec<u8> = row.try_get("content_sealed")?;
    let meta: Meta = open_json(&svc.ctx, tenant, &aad("order_documents", doc, "meta_sealed"), &meta_blob).await?;
    let bytes = svc
        .ctx
        .cipher
        .open(tenant, aad("order_documents", doc, "content_sealed").as_bytes(), &content_blob)
        .await?;
    Ok((safe_file_name(&meta.file_name), bytes))
}

#[cfg(test)]
mod tests {
    use super::safe_file_name;

    #[test]
    fn file_names_are_neutralised() {
        assert_eq!(safe_file_name("../../etc/passwd"), "passwd");
        assert_eq!(safe_file_name("C:\\x\\quote (v2).pdf"), "quote (v2).pdf");
        assert_eq!(safe_file_name("a\"; filename=\"evil.html\r\nX: y"), "a filenameevil.htmlX y");
        assert_eq!(safe_file_name("..."), "document");
        assert_eq!(safe_file_name(".htaccess"), "htaccess");
    }
}
