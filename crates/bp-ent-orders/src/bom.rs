//! Purchasing BOM workspace: the bill of materials per board, with supplier
//! pricing, stock and alternates as entered or synced by purchasing.
//! A BOM is customer IP, so each line is sealed like an order.

use crate::sealed::{aad, open_json, seal_json};
use crate::Svc;
use bp_ent_core::{audit, Error, Permission, Principal, Result, TenantId};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

pub const MAX_BOM_LINES: usize = 2000;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Alternate {
    pub mpn: String,
    #[serde(default)]
    pub manufacturer: String,
    #[serde(default)]
    pub unit_price_usd: f64,
    #[serde(default)]
    pub fab_stock_qty: u64,
    #[serde(default)]
    pub drop_in_compatible: bool,
    #[serde(default)]
    pub notes: String,
}

/// The sealed content of one BOM line (also the request shape).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BomLineData {
    pub refdes: Vec<String>,
    pub qty_per_board: u32,
    pub mpn: String,
    #[serde(default)]
    pub manufacturer: String,
    #[serde(default)]
    pub description: String,
    /// `Draft` | `In Review` | `Released` | `Obsolete`
    #[serde(default = "default_lifecycle")]
    pub lifecycle: String,
    #[serde(default)]
    pub unit_price_usd: f64,
    #[serde(default)]
    pub fab_stock_qty: u64,
    #[serde(default)]
    pub alternates: Vec<Alternate>,
}

fn default_lifecycle() -> String {
    "Released".into()
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BomLineView {
    pub id: Uuid,
    pub board_id: String,
    #[serde(flatten)]
    pub data: BomLineData,
}

fn short(s: &str, max: usize) -> bool {
    s.len() <= max && !s.chars().any(char::is_control)
}

fn validate(d: &BomLineData) -> Result<()> {
    let price_ok = |p: f64| p.is_finite() && (0.0..=1.0e9).contains(&p);
    let ok = !d.mpn.trim().is_empty()
        && short(&d.mpn, 120)
        && short(&d.manufacturer, 200)
        && short(&d.description, 500)
        && ["Draft", "In Review", "Released", "Obsolete"].contains(&d.lifecycle.as_str())
        && d.refdes.len() <= 5000
        && d.refdes.iter().all(|r| !r.is_empty() && short(r, 32))
        && d.qty_per_board <= 1_000_000
        && price_ok(d.unit_price_usd)
        && d.alternates.len() <= 50
        && d.alternates.iter().all(|a| {
            !a.mpn.trim().is_empty() && short(&a.mpn, 120) && short(&a.manufacturer, 200) && short(&a.notes, 1000) && price_ok(a.unit_price_usd)
        });
    if ok {
        Ok(())
    } else {
        Err(Error::invalid("a BOM line has a missing or out-of-range value"))
    }
}

fn board_key(board: &str) -> Result<&str> {
    let b = board.trim();
    if b.is_empty() || b.len() > 200 || b.chars().any(char::is_control) {
        return Err(Error::invalid("invalid board id"));
    }
    Ok(b)
}

fn line_aad(id: Uuid) -> String {
    aad("bom_lines", id, "sealed")
}

async fn open_line(svc: &Svc, tenant: TenantId, id: Uuid, board: String, blob: &[u8]) -> Result<BomLineView> {
    Ok(BomLineView { id, board_id: board, data: open_json(&svc.ctx, tenant, &line_aad(id), blob).await? })
}

pub async fn list(svc: &Svc, who: &Principal, board: &str) -> Result<Vec<BomLineView>> {
    who.require(Permission::OrdersRead)?;
    let tenant = who.tenant_id;
    let board = board_key(board)?;
    let mut tx = svc.ctx.db.tenant_tx(tenant).await?;
    let rows = sqlx::query("SELECT id, sealed FROM bom_lines WHERE tenant_id = $1 AND board_key = $2 ORDER BY position, id")
        .bind(tenant.0)
        .bind(board)
        .fetch_all(&mut *tx)
        .await?;
    tx.commit().await?;
    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let blob: Vec<u8> = r.try_get("sealed")?;
        out.push(open_line(svc, tenant, r.try_get("id")?, board.to_string(), &blob).await?);
    }
    Ok(out)
}

/// Replace a board's BOM with `lines`.
pub async fn replace(svc: &Svc, who: &Principal, board: &str, lines: &[BomLineData]) -> Result<Vec<BomLineView>> {
    who.require(Permission::OrdersWrite)?;
    let tenant = who.tenant_id;
    let board = board_key(board)?;
    if lines.len() > MAX_BOM_LINES {
        return Err(Error::invalid("too many BOM lines"));
    }
    let mut sealed = Vec::with_capacity(lines.len());
    for d in lines {
        validate(d)?;
        let id = Uuid::new_v4();
        sealed.push((id, seal_json(&svc.ctx, tenant, &line_aad(id), d).await?));
    }
    let mut tx = svc.ctx.db.tenant_tx(tenant).await?;
    sqlx::query("DELETE FROM bom_lines WHERE tenant_id = $1 AND board_key = $2")
        .bind(tenant.0)
        .bind(board)
        .execute(&mut *tx)
        .await?;
    for (pos, (id, blob)) in sealed.iter().enumerate() {
        sqlx::query("INSERT INTO bom_lines (id, tenant_id, board_key, position, sealed, updated_by) VALUES ($1, $2, $3, $4, $5, $6)")
            .bind(id)
            .bind(tenant.0)
            .bind(board)
            .bind(pos as i32)
            .bind(blob)
            .bind(who.user_id.0)
            .execute(&mut *tx)
            .await?;
    }
    audit::append(&mut tx, who, "bom.replaced", &format!("board:{board}"), serde_json::json!({ "lines": lines.len() })).await?;
    tx.commit().await?;
    Ok(sealed
        .into_iter()
        .zip(lines)
        .map(|((id, _), d)| BomLineView { id, board_id: board.to_string(), data: d.clone() })
        .collect())
}

/// Swap a line's part for one of its listed alternates. The old part
/// becomes an alternate, so the swap can be undone.
pub async fn swap_alternate(svc: &Svc, who: &Principal, line: Uuid, mpn: &str) -> Result<BomLineView> {
    who.require(Permission::OrdersWrite)?;
    let tenant = who.tenant_id;
    let mut tx = svc.ctx.db.tenant_tx(tenant).await?;
    let row = sqlx::query("SELECT board_key, sealed FROM bom_lines WHERE tenant_id = $1 AND id = $2 FOR UPDATE")
        .bind(tenant.0)
        .bind(line)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(Error::NotFound)?;
    let board: String = row.try_get("board_key")?;
    let blob: Vec<u8> = row.try_get("sealed")?;
    let mut d: BomLineData = open_json(&svc.ctx, tenant, &line_aad(line), &blob).await?;
    let idx = d
        .alternates
        .iter()
        .position(|a| a.mpn == mpn)
        .ok_or_else(|| Error::invalid("that part is not a listed alternate for this line"))?;
    let alt = d.alternates.remove(idx);
    let previous = Alternate {
        mpn: std::mem::replace(&mut d.mpn, alt.mpn),
        manufacturer: std::mem::replace(&mut d.manufacturer, alt.manufacturer),
        unit_price_usd: std::mem::replace(&mut d.unit_price_usd, alt.unit_price_usd),
        fab_stock_qty: std::mem::replace(&mut d.fab_stock_qty, alt.fab_stock_qty),
        drop_in_compatible: alt.drop_in_compatible,
        notes: "Previous selection".into(),
    };
    d.alternates.insert(idx, previous);
    let sealed = seal_json(&svc.ctx, tenant, &line_aad(line), &d).await?;
    sqlx::query("UPDATE bom_lines SET sealed = $3, updated_by = $4, updated_at = now() WHERE tenant_id = $1 AND id = $2")
        .bind(tenant.0)
        .bind(line)
        .bind(&sealed)
        .bind(who.user_id.0)
        .execute(&mut *tx)
        .await?;
    audit::append(&mut tx, who, "bom.alternate_swapped", &format!("bom_line:{line}"), serde_json::json!({ "board": board })).await?;
    tx.commit().await?;
    Ok(BomLineView { id: line, board_id: board, data: d })
}
