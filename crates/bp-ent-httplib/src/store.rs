//! Tenant-scoped PostgreSQL persistence for the Private KiCad HTTP Library and Web Librarian.
//!
//! Every function requires a `&mut Tx` opened via [`bp_ent_core::Db::tenant_tx`]
//! so PostgreSQL Row-Level Security (`bp_tenant()`) is enforced on every query.

use crate::ipc7351::{generate_cad_assets, GeneratedCadAssets};
use crate::kicad_protocol::{
    part_to_kicad_detail, KiCadCategory, KiCadPartDetail, KiCadPartSummary,
};
use crate::model::{
    ArtifactKind, ClonePartRequest, CreateCategoryRequest, CreatePartRequest, CreateTokenResponse,
    HttpLibTokenSummary, Ipc7351Spec, LibraryCategory, LibraryPart, ListPartsQuery, PartLifecycle,
    UpdatePartRequest, UpsertWhereUsedRequest, WhereUsedEntry,
};
use crate::url_guard::validate_public_https_url;
use bp_ent_core::policy::{self, Approval, GateKind};
use bp_ent_core::rbac::Scopes;
use bp_ent_core::{auth, AuthKind, Error, Permission, Principal, Result, TenantId, Tx};
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::collections::{BTreeMap, HashMap};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub enum GateOutcome<T> {
    Completed(T),
    PendingApproval(Uuid),
}

async fn check_released_part_gate(
    tx: &mut Tx,
    principal: &Principal,
    part: &LibraryPart,
    action: &str,
    summary: serde_json::Value,
) -> Result<Option<Uuid>> {
    if part.lifecycle != PartLifecycle::Released {
        return Ok(None);
    }
    principal.require(Permission::PartsRelease)?;
    let approval = policy::require_approval(
        tx,
        principal,
        GateKind::ModifyReleasedPart,
        &format!("part:{}", part.id),
        serde_json::json!({
            "action": action,
            "part_number": part.part_number,
            "mpn": part.mpn,
            "changes": summary,
        }),
    )
    .await?;
    match approval {
        a if a.may_proceed() => Ok(None),
        Approval::Pending { request_id } => Ok(Some(request_id)),
        Approval::Rejected { .. } => Err(Error::Forbidden),
        _ => Err(Error::Forbidden),
    }
}

#[derive(Clone, Debug)]
pub struct TenantInfo {
    pub id: TenantId,
    pub name: String,
    pub slug: String,
}

#[derive(Clone, Debug)]
pub struct StoredArtifact {
    pub kind: ArtifactKind,
    pub name: String,
    pub content: String,
    pub sha256_hex: String,
}

fn format_ts(ts: OffsetDateTime) -> String {
    ts.format(&Rfc3339).unwrap_or_else(|_| ts.to_string())
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Resolves the caller's tenant row under RLS and verifies that the `{tenant}`
/// URL parameter matches the authenticated principal's tenant slug or UUID.
///
/// Returns `Error::NotFound` (404, never 403) on mismatch to prevent any
/// cross-tenant existence oracle.
pub async fn resolve_and_verify_tenant_path(
    tx: &mut Tx,
    principal: &Principal,
    tenant_param: &str,
) -> Result<TenantInfo> {
    let row = sqlx::query("SELECT id, name, slug FROM tenants WHERE id = $1")
        .bind(principal.tenant_id.0)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(Error::NotFound)?;

    let id = TenantId(row.get("id"));
    let name: String = row.get("name");
    let slug: String = row.get("slug");

    let param_norm = tenant_param.trim().to_ascii_lowercase();
    if param_norm != slug && param_norm != id.0.to_string() {
        return Err(Error::NotFound);
    }

    Ok(TenantInfo { id, name, slug })
}

pub async fn get_tenant_info(tx: &mut Tx, tenant_id: TenantId) -> Result<TenantInfo> {
    let row = sqlx::query("SELECT id, name, slug FROM tenants WHERE id = $1")
        .bind(tenant_id.0)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(Error::NotFound)?;
    Ok(TenantInfo {
        id: TenantId(row.get("id")),
        name: row.get("name"),
        slug: row.get("slug"),
    })
}

pub async fn list_categories(tx: &mut Tx) -> Result<Vec<LibraryCategory>> {
    let rows = sqlx::query(
        "SELECT id, name, description, created_at FROM library_categories ORDER BY name ASC",
    )
    .fetch_all(&mut **tx)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| LibraryCategory {
            id: r.get("id"),
            name: r.get("name"),
            description: r.get("description"),
            created_at: format_ts(r.get("created_at")),
        })
        .collect())
}

pub async fn create_category(
    tx: &mut Tx,
    principal: &Principal,
    req: &CreateCategoryRequest,
) -> Result<LibraryCategory> {
    let name = req.name.trim();
    if name.is_empty() || name.len() > 120 {
        return Err(Error::invalid("category name must be 1..=120 characters"));
    }
    let id = Uuid::new_v4();
    let row = sqlx::query(
        "INSERT INTO library_categories (id, tenant_id, name, description)
         VALUES ($1, $2, $3, $4)
         RETURNING id, name, description, created_at",
    )
    .bind(id)
    .bind(principal.tenant_id.0)
    .bind(name)
    .bind(req.description.trim())
    .fetch_one(&mut **tx)
    .await?;

    Ok(LibraryCategory {
        id: row.get("id"),
        name: row.get("name"),
        description: row.get("description"),
        created_at: format_ts(row.get("created_at")),
    })
}

async fn get_or_create_category(
    tx: &mut Tx,
    tenant_id: TenantId,
    category_name: &str,
) -> Result<(Uuid, String)> {
    let clean = category_name.trim();
    if clean.is_empty() || clean.len() > 120 {
        return Err(Error::invalid("category name must be 1..=120 characters"));
    }
    if let Some(row) = sqlx::query("SELECT id, name FROM library_categories WHERE name = $1")
        .bind(clean)
        .fetch_optional(&mut **tx)
        .await?
    {
        return Ok((row.get("id"), row.get("name")));
    }

    let id = Uuid::new_v4();
    let row = sqlx::query(
        "INSERT INTO library_categories (id, tenant_id, name, description)
         VALUES ($1, $2, $3, '')
         ON CONFLICT (tenant_id, name) DO UPDATE SET name = EXCLUDED.name
         RETURNING id, name",
    )
    .bind(id)
    .bind(tenant_id.0)
    .bind(clean)
    .fetch_one(&mut **tx)
    .await?;
    Ok((row.get("id"), row.get("name")))
}

async fn load_where_used_map(
    tx: &mut Tx,
    part_ids: &[Uuid],
) -> Result<HashMap<Uuid, Vec<WhereUsedEntry>>> {
    let mut map: HashMap<Uuid, Vec<WhereUsedEntry>> = HashMap::new();
    if part_ids.is_empty() {
        return Ok(map);
    }
    let rows = sqlx::query(
        "SELECT part_id, board_id, board_name, revision_tag, refdes_list
         FROM part_where_used
         WHERE part_id = ANY($1)
         ORDER BY board_name ASC, revision_tag ASC",
    )
    .bind(part_ids)
    .fetch_all(&mut **tx)
    .await?;

    for r in rows {
        let part_id: Uuid = r.get("part_id");
        map.entry(part_id).or_default().push(WhereUsedEntry {
            board_id: r.get("board_id"),
            board_name: r.get("board_name"),
            revision_tag: r.get("revision_tag"),
            refdes_list: r.get("refdes_list"),
        });
    }
    Ok(map)
}

fn part_from_row(
    r: &sqlx::postgres::PgRow,
    where_used: Vec<WhereUsedEntry>,
) -> Result<LibraryPart> {
    let lifecycle_raw: String = r.get("lifecycle");
    let lifecycle = PartLifecycle::parse(&lifecycle_raw)?;
    let attrs_val: serde_json::Value = r.get("attributes");
    let attributes: BTreeMap<String, String> =
        serde_json::from_value(attrs_val).unwrap_or_default();
    let ipc_val: Option<serde_json::Value> = r.get("ipc_spec");
    let ipc_spec: Option<Ipc7351Spec> = match ipc_val {
        Some(v) if !v.is_null() => serde_json::from_value(v).ok(),
        _ => None,
    };
    let cents: i64 = r.get("unit_price_cents");

    Ok(LibraryPart {
        id: r.get("id"),
        part_number: r.get("part_number"),
        mpn: r.get("mpn"),
        manufacturer: r.get("manufacturer"),
        category: r.get("category_name"),
        category_id: r.get("category_id"),
        value: r.get("value"),
        package_name: r.get("package_name"),
        lifecycle,
        preferred_by_fab: r.get("preferred_by_fab"),
        fab_stock_qty: r.get("fab_stock_qty"),
        unit_price_usd: (cents as f64) / 100.0,
        datasheet_url: r.get("datasheet_url"),
        description: r.get("description"),
        symbol_ref: r.get("symbol_ref"),
        footprint_ref: r.get("footprint_ref"),
        model_3d_key: r.get("model_3d_key"),
        exclude_from_bom: r.get("exclude_from_bom"),
        exclude_from_board: r.get("exclude_from_board"),
        attributes,
        ipc_spec,
        where_used,
        updated_at: format_ts(r.get("updated_at")),
    })
}

const PART_SELECT: &str = "
    SELECT p.id, p.category_id, c.name AS category_name, p.part_number, p.mpn,
           p.manufacturer, p.value, p.package_name, p.description, p.lifecycle,
           p.symbol_ref, p.footprint_ref, p.model_3d_key, p.datasheet_url,
           p.preferred_by_fab, p.fab_stock_qty, p.unit_price_cents, p.attributes,
           p.ipc_spec, p.exclude_from_bom, p.exclude_from_board, p.updated_at
    FROM library_parts p
    JOIN library_categories c
      ON c.tenant_id = p.tenant_id AND c.id = p.category_id
";

pub fn escape_like_pattern(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    if trimmed.chars().count() > 100 {
        return Err(Error::invalid("search query must be <= 100 characters"));
    }
    let mut escaped = String::with_capacity(trimmed.len() + 2);
    escaped.push('%');
    for ch in trimmed.to_ascii_lowercase().chars() {
        match ch {
            '\\' | '%' | '_' => {
                escaped.push('\\');
                escaped.push(ch);
            }
            c => escaped.push(c),
        }
    }
    escaped.push('%');
    Ok(escaped)
}

pub async fn list_parts(tx: &mut Tx, query: &ListPartsQuery) -> Result<Vec<LibraryPart>> {
    let q_like = match query.q.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) => Some(escape_like_pattern(s)?),
        None => None,
    };

    let lifecycle_filter = match query.lifecycle.as_deref().map(str::trim) {
        Some("") | None => None,
        Some(raw) => Some(PartLifecycle::parse(raw)?.as_str().to_string()),
    };

    let category_filter = query
        .category
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let sql = format!(
        "{PART_SELECT}
         WHERE ($1::text IS NULL OR lower(p.mpn) LIKE $1 ESCAPE '\\' OR lower(p.part_number) LIKE $1 ESCAPE '\\'
                OR lower(p.manufacturer) LIKE $1 ESCAPE '\\' OR lower(c.name) LIKE $1 ESCAPE '\\')
           AND ($2::text IS NULL OR p.lifecycle = $2)
           AND ($3::text IS NULL OR c.name = $3)
         ORDER BY p.updated_at DESC, p.part_number ASC
         LIMIT 500"
    );

    let rows = sqlx::query(&sql)
        .bind(q_like)
        .bind(lifecycle_filter)
        .bind(category_filter)
        .fetch_all(&mut **tx)
        .await?;

    let part_ids: Vec<Uuid> = rows.iter().map(|r| r.get("id")).collect();
    let mut wu_map = load_where_used_map(tx, &part_ids).await?;

    let mut out = Vec::with_capacity(rows.len());
    for r in &rows {
        let id: Uuid = r.get("id");
        let wu = wu_map.remove(&id).unwrap_or_default();
        out.push(part_from_row(r, wu)?);
    }
    Ok(out)
}

pub async fn get_part(tx: &mut Tx, part_id: Uuid) -> Result<LibraryPart> {
    let sql = format!("{PART_SELECT} WHERE p.id = $1");
    let row = sqlx::query(&sql)
        .bind(part_id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(Error::NotFound)?;

    let mut wu_map = load_where_used_map(tx, &[part_id]).await?;
    let wu = wu_map.remove(&part_id).unwrap_or_default();
    part_from_row(&row, wu)
}

pub async fn list_kicad_categories(tx: &mut Tx) -> Result<Vec<KiCadCategory>> {
    let rows = sqlx::query(
        "SELECT id, name, description FROM library_categories ORDER BY name ASC",
    )
    .fetch_all(&mut **tx)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| KiCadCategory {
            id: r.get::<Uuid, _>("id").to_string(),
            name: r.get("name"),
            description: r.get("description"),
        })
        .collect())
}

pub async fn list_kicad_parts_in_category(
    tx: &mut Tx,
    category_id: Uuid,
    include_draft: bool,
) -> Result<Vec<KiCadPartSummary>> {
    let exists: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM library_categories WHERE id = $1")
            .bind(category_id)
            .fetch_optional(&mut **tx)
            .await?;
    if exists.is_none() {
        return Err(Error::NotFound);
    }

    let sql = if include_draft {
        "SELECT id, part_number, mpn, description
         FROM library_parts
         WHERE category_id = $1 AND lifecycle IN ('Draft', 'In Review', 'Released')
         ORDER BY part_number ASC"
    } else {
        "SELECT id, part_number, mpn, description
         FROM library_parts
         WHERE category_id = $1 AND lifecycle = 'Released'
         ORDER BY part_number ASC"
    };

    let rows = sqlx::query(sql)
        .bind(category_id)
        .fetch_all(&mut **tx)
        .await?;

    Ok(rows
        .into_iter()
        .map(|r| {
            let mpn: String = r.get("mpn");
            let desc: String = r.get("description");
            KiCadPartSummary {
                id: r.get::<Uuid, _>("id").to_string(),
                name: r.get("part_number"),
                description: if desc.is_empty() { mpn } else { desc },
            }
        })
        .collect())
}

fn ensure_kicad_visible(lifecycle: PartLifecycle, include_draft: bool) -> Result<()> {
    match lifecycle {
        PartLifecycle::Released => Ok(()),
        PartLifecycle::Draft | PartLifecycle::InReview if include_draft => Ok(()),
        _ => Err(Error::NotFound),
    }
}

pub async fn get_kicad_part_detail(
    tx: &mut Tx,
    part_id: Uuid,
    include_draft: bool,
) -> Result<KiCadPartDetail> {
    let part = get_part(tx, part_id).await?;
    ensure_kicad_visible(part.lifecycle, include_draft)?;
    Ok(part_to_kicad_detail(&part))
}

pub async fn get_kicad_artifact(
    tx: &mut Tx,
    part_id: Uuid,
    kind: ArtifactKind,
    include_draft: bool,
) -> Result<StoredArtifact> {
    let part = get_part(tx, part_id).await?;
    ensure_kicad_visible(part.lifecycle, include_draft)?;
    get_artifact(tx, part_id, kind).await
}

fn validate_nonempty_len(field: &str, val: &str, max: usize) -> Result<String> {
    let trimmed = val.trim();
    if trimmed.is_empty() || trimmed.len() > max {
        return Err(Error::invalid(format!(
            "{field} must be between 1 and {max} characters"
        )));
    }
    Ok(trimmed.to_string())
}

fn usd_to_cents(usd: f64) -> Result<i64> {
    if !usd.is_finite() || usd < 0.0 || usd > 1_000_000.0 {
        return Err(Error::invalid("unitPriceUsd must be finite and >= 0"));
    }
    Ok((usd * 100.0).round() as i64)
}

fn validate_model_3d_key(tenant_id: TenantId, key: Option<&str>) -> Result<Option<String>> {
    match key.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(rel) => Ok(Some(tenant_id.s3_key(rel)?)),
    }
}

pub async fn upsert_artifact(
    tx: &mut Tx,
    tenant_id: TenantId,
    part_id: Uuid,
    kind: ArtifactKind,
    name: &str,
    content: &str,
    s3_key: Option<&str>,
) -> Result<()> {
    let validated_s3 = match s3_key.map(str::trim).filter(|s| !s.is_empty()) {
        Some(rel) => Some(tenant_id.s3_key(rel)?),
        None => None,
    };
    let digest = sha256_hex(content.as_bytes());
    let id = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO library_part_artifacts (id, tenant_id, part_id, kind, name, content, s3_key, sha256_hex, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())
         ON CONFLICT (tenant_id, part_id, kind) DO UPDATE
           SET name = EXCLUDED.name,
               content = EXCLUDED.content,
               s3_key = EXCLUDED.s3_key,
               sha256_hex = EXCLUDED.sha256_hex,
               updated_at = now()",
    )
    .bind(id)
    .bind(tenant_id.0)
    .bind(part_id)
    .bind(kind.as_str())
    .bind(name)
    .bind(content)
    .bind(validated_s3)
    .bind(digest)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn store_generated_cad_assets(
    tx: &mut Tx,
    tenant_id: TenantId,
    part_id: Uuid,
    assets: &GeneratedCadAssets,
) -> Result<()> {
    upsert_artifact(
        tx,
        tenant_id,
        part_id,
        ArtifactKind::FootprintKicad,
        &format!("{}.kicad_mod", assets.footprint_name),
        &assets.footprint_kicad_mod,
        None,
    )
    .await?;
    upsert_artifact(
        tx,
        tenant_id,
        part_id,
        ArtifactKind::SymbolKicad,
        &format!("{}.kicad_sym", assets.symbol_name),
        &assets.symbol_kicad_sym,
        None,
    )
    .await?;
    upsert_artifact(
        tx,
        tenant_id,
        part_id,
        ArtifactKind::FootprintSvg,
        &format!("{}_fp.svg", assets.footprint_name),
        &assets.footprint_svg,
        None,
    )
    .await?;
    upsert_artifact(
        tx,
        tenant_id,
        part_id,
        ArtifactKind::SymbolSvg,
        &format!("{}_sym.svg", assets.symbol_name),
        &assets.symbol_svg,
        None,
    )
    .await?;
    Ok(())
}

pub async fn get_artifact(
    tx: &mut Tx,
    part_id: Uuid,
    kind: ArtifactKind,
) -> Result<StoredArtifact> {
    let row = sqlx::query(
        "SELECT name, content, sha256_hex
         FROM library_part_artifacts
         WHERE part_id = $1 AND kind = $2",
    )
    .bind(part_id)
    .bind(kind.as_str())
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(Error::NotFound)?;

    let content: Option<String> = row.get("content");
    Ok(StoredArtifact {
        kind,
        name: row.get("name"),
        content: content.ok_or(Error::NotFound)?,
        sha256_hex: row.get("sha256_hex"),
    })
}

pub async fn create_part(
    tx: &mut Tx,
    principal: &Principal,
    req: &CreatePartRequest,
) -> Result<LibraryPart> {
    let part_number = validate_nonempty_len("partNumber", &req.part_number, 120)?;
    let mpn = validate_nonempty_len("mpn", &req.mpn, 200)?;
    let manufacturer = validate_nonempty_len("manufacturer", &req.manufacturer, 200)?;
    if req.fab_stock_qty < 0 {
        return Err(Error::invalid("fabStockQty must be >= 0"));
    }
    let price_cents = usd_to_cents(req.unit_price_usd)?;
    let datasheet_url = validate_public_https_url(&req.datasheet_url)?;
    let model_3d_key = validate_model_3d_key(principal.tenant_id, req.model_3d_key.as_deref())?;
    if let Some(spec) = &req.ipc_spec {
        spec.validate()?;
    }

    let (category_id, _) =
        get_or_create_category(tx, principal.tenant_id, &req.category).await?;
    let id = Uuid::new_v4();

    let mut symbol_ref = req.symbol_ref.trim().to_string();
    let mut footprint_ref = req.footprint_ref.trim().to_string();
    let mut package_name = req.package_name.trim().to_string();

    let generated = if let Some(spec) = &req.ipc_spec {
        let assets = generate_cad_assets(
            spec,
            &mpn,
            &req.value,
            &footprint_ref,
            &datasheet_url,
            &req.description,
        )?;
        if symbol_ref.is_empty() {
            symbol_ref = format!("Backplane_Enterprise:{}", assets.symbol_name);
        }
        if footprint_ref.is_empty() {
            footprint_ref = format!("Backplane_Enterprise:{}", assets.footprint_name);
        }
        if package_name.is_empty() {
            package_name = assets.footprint_name.clone();
        }
        Some(assets)
    } else {
        None
    };

    let attrs_json = serde_json::to_value(&req.attributes)
        .map_err(|e| Error::invalid(format!("invalid attributes: {e}")))?;
    let ipc_json = match &req.ipc_spec {
        Some(s) => Some(
            serde_json::to_value(s)
                .map_err(|e| Error::invalid(format!("invalid ipcSpec: {e}")))?,
        ),
        None => None,
    };

    sqlx::query(
        "INSERT INTO library_parts (
            id, tenant_id, category_id, part_number, mpn, manufacturer, value,
            package_name, description, lifecycle, symbol_ref, footprint_ref,
            model_3d_key, datasheet_url, preferred_by_fab, fab_stock_qty,
            unit_price_cents, attributes, ipc_spec, exclude_from_bom,
            exclude_from_board, created_by, updated_by
         ) VALUES (
            $1, $2, $3, $4, $5, $6, $7,
            $8, $9, 'Draft', $10, $11,
            $12, $13, $14, $15,
            $16, $17, $18, $19,
            $20, $21, $21
         )",
    )
    .bind(id)
    .bind(principal.tenant_id.0)
    .bind(category_id)
    .bind(part_number)
    .bind(mpn)
    .bind(manufacturer)
    .bind(req.value.trim())
    .bind(package_name)
    .bind(req.description.trim())
    .bind(symbol_ref)
    .bind(footprint_ref)
    .bind(model_3d_key)
    .bind(datasheet_url)
    .bind(req.preferred_by_fab)
    .bind(req.fab_stock_qty)
    .bind(price_cents)
    .bind(attrs_json)
    .bind(ipc_json)
    .bind(req.exclude_from_bom)
    .bind(req.exclude_from_board)
    .bind(principal.user_id.0)
    .execute(&mut **tx)
    .await?;

    if let Some(assets) = &generated {
        store_generated_cad_assets(tx, principal.tenant_id, id, assets).await?;
    }

    get_part(tx, id).await
}

pub async fn update_part(
    tx: &mut Tx,
    principal: &Principal,
    part_id: Uuid,
    req: &UpdatePartRequest,
) -> Result<GateOutcome<LibraryPart>> {
    let existing = get_part(tx, part_id).await?;
    if existing.lifecycle == PartLifecycle::Obsolete {
        return Err(Error::conflict(
            "obsolete parts are read-only; clone into a new Draft part",
        ));
    }
    if let Some(request_id) = check_released_part_gate(
        tx,
        principal,
        &existing,
        "update_part",
        serde_json::json!({
            "mpn": req.mpn,
            "manufacturer": req.manufacturer,
            "package_name": req.package_name,
        }),
    )
    .await?
    {
        return Ok(GateOutcome::PendingApproval(request_id));
    }

    let mpn = match &req.mpn {
        Some(v) => validate_nonempty_len("mpn", v, 200)?,
        None => existing.mpn.clone(),
    };
    let manufacturer = match &req.manufacturer {
        Some(v) => validate_nonempty_len("manufacturer", v, 200)?,
        None => existing.manufacturer.clone(),
    };
    let category_id = match &req.category {
        Some(cat) => get_or_create_category(tx, principal.tenant_id, cat).await?.0,
        None => existing.category_id,
    };
    let value = req
        .value
        .as_deref()
        .map(str::trim)
        .unwrap_or(&existing.value)
        .to_string();
    let package_name = req
        .package_name
        .as_deref()
        .map(str::trim)
        .unwrap_or(&existing.package_name)
        .to_string();
    let description = req
        .description
        .as_deref()
        .map(str::trim)
        .unwrap_or(&existing.description)
        .to_string();
    let symbol_ref = req
        .symbol_ref
        .as_deref()
        .map(str::trim)
        .unwrap_or(&existing.symbol_ref)
        .to_string();
    let footprint_ref = req
        .footprint_ref
        .as_deref()
        .map(str::trim)
        .unwrap_or(&existing.footprint_ref)
        .to_string();
    let datasheet_url = match &req.datasheet_url {
        Some(u) => validate_public_https_url(u)?,
        None => existing.datasheet_url.clone(),
    };
    let model_3d_key = match &req.model_3d_key {
        Some(inner) => validate_model_3d_key(principal.tenant_id, inner.as_deref())?,
        None => existing.model_3d_key.clone(),
    };
    let preferred_by_fab = req.preferred_by_fab.unwrap_or(existing.preferred_by_fab);
    let fab_stock_qty = req.fab_stock_qty.unwrap_or(existing.fab_stock_qty);
    if fab_stock_qty < 0 {
        return Err(Error::invalid("fabStockQty must be >= 0"));
    }
    let unit_price_cents = match req.unit_price_usd {
        Some(u) => usd_to_cents(u)?,
        None => (existing.unit_price_usd * 100.0).round() as i64,
    };
    let exclude_from_bom = req.exclude_from_bom.unwrap_or(existing.exclude_from_bom);
    let exclude_from_board = req.exclude_from_board.unwrap_or(existing.exclude_from_board);
    let attributes = req.attributes.clone().unwrap_or(existing.attributes);
    let ipc_spec = match &req.ipc_spec {
        Some(inner) => {
            if let Some(s) = inner {
                s.validate()?;
            }
            inner.clone()
        }
        None => existing.ipc_spec.clone(),
    };

    let attrs_json = serde_json::to_value(&attributes)
        .map_err(|e| Error::invalid(format!("invalid attributes: {e}")))?;
    let ipc_json = match &ipc_spec {
        Some(s) => Some(
            serde_json::to_value(s)
                .map_err(|e| Error::invalid(format!("invalid ipcSpec: {e}")))?,
        ),
        None => None,
    };

    sqlx::query(
        "UPDATE library_parts
         SET category_id = $2,
             mpn = $3,
             manufacturer = $4,
             value = $5,
             package_name = $6,
             description = $7,
             symbol_ref = $8,
             footprint_ref = $9,
             model_3d_key = $10,
             datasheet_url = $11,
             preferred_by_fab = $12,
             fab_stock_qty = $13,
             unit_price_cents = $14,
             attributes = $15,
             ipc_spec = $16,
             exclude_from_bom = $17,
             exclude_from_board = $18,
             updated_by = $19,
             updated_at = now()
         WHERE id = $1",
    )
    .bind(part_id)
    .bind(category_id)
    .bind(&mpn)
    .bind(&manufacturer)
    .bind(&value)
    .bind(&package_name)
    .bind(&description)
    .bind(&symbol_ref)
    .bind(&footprint_ref)
    .bind(&model_3d_key)
    .bind(&datasheet_url)
    .bind(preferred_by_fab)
    .bind(fab_stock_qty)
    .bind(unit_price_cents)
    .bind(attrs_json)
    .bind(ipc_json)
    .bind(exclude_from_bom)
    .bind(exclude_from_board)
    .bind(principal.user_id.0)
    .execute(&mut **tx)
    .await?;

    if let Some(spec) = &ipc_spec {
        let assets = generate_cad_assets(
            spec,
            &mpn,
            &value,
            &footprint_ref,
            &datasheet_url,
            &description,
        )?;
        store_generated_cad_assets(tx, principal.tenant_id, part_id, &assets).await?;
    }

    get_part(tx, part_id).await.map(GateOutcome::Completed)
}

pub async fn clone_part(
    tx: &mut Tx,
    principal: &Principal,
    source_part_id: Uuid,
    req: &ClonePartRequest,
) -> Result<LibraryPart> {
    let source = get_part(tx, source_part_id).await?;
    let part_number = validate_nonempty_len("partNumber", &req.part_number, 120)?;
    let mpn = match &req.mpn {
        Some(m) => validate_nonempty_len("mpn", m, 200)?,
        None => source.mpn.clone(),
    };

    let create_req = CreatePartRequest {
        part_number,
        mpn,
        manufacturer: source.manufacturer,
        category: source.category,
        value: source.value,
        package_name: source.package_name,
        preferred_by_fab: source.preferred_by_fab,
        fab_stock_qty: source.fab_stock_qty,
        unit_price_usd: source.unit_price_usd,
        datasheet_url: source.datasheet_url,
        description: source.description,
        symbol_ref: source.symbol_ref,
        footprint_ref: source.footprint_ref,
        model_3d_key: source.model_3d_key,
        exclude_from_bom: source.exclude_from_bom,
        exclude_from_board: source.exclude_from_board,
        attributes: source.attributes,
        ipc_spec: source.ipc_spec,
    };

    create_part(tx, principal, &create_req).await
}

pub async fn delete_part(
    tx: &mut Tx,
    principal: &Principal,
    part_id: Uuid,
) -> Result<GateOutcome<()>> {
    let existing = get_part(tx, part_id).await?;
    if let Some(request_id) = check_released_part_gate(
        tx,
        principal,
        &existing,
        "delete_part",
        serde_json::json!({ "part_id": part_id }),
    )
    .await?
    {
        return Ok(GateOutcome::PendingApproval(request_id));
    }
    let res = sqlx::query("DELETE FROM library_parts WHERE id = $1")
        .bind(part_id)
        .execute(&mut **tx)
        .await?;
    if res.rows_affected() == 0 {
        return Err(Error::NotFound);
    }
    Ok(GateOutcome::Completed(()))
}

pub async fn transition_lifecycle(
    tx: &mut Tx,
    principal: &Principal,
    part_id: Uuid,
    next: PartLifecycle,
) -> Result<LibraryPart> {
    let existing = get_part(tx, part_id).await?;
    PartLifecycle::validate_transition(existing.lifecycle, next, principal)?;

    sqlx::query(
        "UPDATE library_parts
         SET lifecycle = $2, updated_by = $3, updated_at = now()
         WHERE id = $1",
    )
    .bind(part_id)
    .bind(next.as_str())
    .bind(principal.user_id.0)
    .execute(&mut **tx)
    .await?;

    get_part(tx, part_id).await
}

pub async fn list_where_used(tx: &mut Tx, part_id: Uuid) -> Result<Vec<WhereUsedEntry>> {
    let _ = get_part(tx, part_id).await?;
    let mut map = load_where_used_map(tx, &[part_id]).await?;
    Ok(map.remove(&part_id).unwrap_or_default())
}

pub async fn upsert_where_used(
    tx: &mut Tx,
    principal: &Principal,
    part_id: Uuid,
    req: &UpsertWhereUsedRequest,
) -> Result<Vec<WhereUsedEntry>> {
    let _ = get_part(tx, part_id).await?;
    let board_id = validate_nonempty_len("boardId", &req.board_id, 128)?;
    let board_name = validate_nonempty_len("boardName", &req.board_name, 200)?;
    let revision_tag = validate_nonempty_len("revisionTag", &req.revision_tag, 120)?;

    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO part_where_used (id, tenant_id, part_id, board_id, board_name, revision_tag, refdes_list, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, now())
         ON CONFLICT (tenant_id, part_id, board_id, revision_tag) DO UPDATE
           SET board_name = EXCLUDED.board_name,
               refdes_list = EXCLUDED.refdes_list,
               updated_at = now()",
    )
    .bind(id)
    .bind(principal.tenant_id.0)
    .bind(part_id)
    .bind(board_id)
    .bind(board_name)
    .bind(revision_tag)
    .bind(&req.refdes_list)
    .execute(&mut **tx)
    .await?;

    list_where_used(tx, part_id).await
}

pub async fn generate_and_store_cad(
    tx: &mut Tx,
    principal: &Principal,
    part_id: Uuid,
    spec: &Ipc7351Spec,
) -> Result<GateOutcome<GeneratedCadAssets>> {
    let existing = get_part(tx, part_id).await?;
    if existing.lifecycle == PartLifecycle::Obsolete {
        return Err(Error::conflict("cannot regenerate CAD for an Obsolete part"));
    }
    if let Some(request_id) = check_released_part_gate(
        tx,
        principal,
        &existing,
        "generate_cad",
        serde_json::to_value(spec).unwrap_or_default(),
    )
    .await?
    {
        return Ok(GateOutcome::PendingApproval(request_id));
    }

    let assets = generate_cad_assets(
        spec,
        &existing.mpn,
        &existing.value,
        &existing.footprint_ref,
        &existing.datasheet_url,
        &existing.description,
    )?;

    let spec_json = serde_json::to_value(spec)
        .map_err(|e| Error::invalid(format!("invalid ipcSpec: {e}")))?;

    let sym_ref = if existing.symbol_ref.is_empty() {
        format!("Backplane_Enterprise:{}", assets.symbol_name)
    } else {
        existing.symbol_ref.clone()
    };
    let fp_ref = if existing.footprint_ref.is_empty() {
        format!("Backplane_Enterprise:{}", assets.footprint_name)
    } else {
        existing.footprint_ref.clone()
    };

    sqlx::query(
        "UPDATE library_parts
         SET ipc_spec = $2,
             symbol_ref = $3,
             footprint_ref = $4,
             updated_by = $5,
             updated_at = now()
         WHERE id = $1",
    )
    .bind(part_id)
    .bind(spec_json)
    .bind(sym_ref)
    .bind(fp_ref)
    .bind(principal.user_id.0)
    .execute(&mut **tx)
    .await?;

    store_generated_cad_assets(tx, principal.tenant_id, part_id, &assets).await?;
    Ok(GateOutcome::Completed(assets))
}

/// Mints a scoped `parts:read`-only device token for KiCad `.kicad_httplib`.
/// Delegates to `bp_ent_core::auth::issue_token` so only the SHA-256 digest
/// is persisted; the raw token is returned once.
pub async fn mint_httplib_device_token(
    tx: &mut Tx,
    principal: &Principal,
    label: &str,
) -> Result<CreateTokenResponse> {
    let clean_label = label.trim();
    let label_final = if clean_label.is_empty() {
        "kicad-workstation"
    } else if clean_label.len() > 120 {
        return Err(Error::invalid("token label must be <= 120 characters"));
    } else {
        clean_label
    };

    const TTL_DAYS: i64 = 90;
    let ttl = std::time::Duration::from_secs((TTL_DAYS as u64) * 86_400);
    let (token_id, secret) = auth::issue_token(
        tx,
        principal.tenant_id,
        principal.user_id,
        AuthKind::DeviceToken,
        label_final,
        &Scopes::Only(vec![Permission::PartsRead]),
        ttl,
    )
    .await?;

    let tenant_hex = principal.tenant_id.0.simple().to_string();
    let token_prefix = format!("bpe_d_{}", &tenant_hex[..8]);
    let expires_at = OffsetDateTime::now_utc() + Duration::days(TTL_DAYS);

    Ok(CreateTokenResponse {
        token_id,
        token: secret.expose().clone(),
        token_prefix,
        expires_at: format_ts(expires_at),
    })
}

pub async fn list_httplib_device_tokens(
    tx: &mut Tx,
    principal: &Principal,
) -> Result<Vec<HttpLibTokenSummary>> {
    let is_admin = principal.can(Permission::AdminManage);
    let rows = sqlx::query(
        "SELECT id, user_id, name, scopes, created_at, expires_at, last_used_at, revoked_at
         FROM auth_tokens
         WHERE kind = 'd' AND ($1 OR user_id = $2)
         ORDER BY created_at DESC
         LIMIT 200",
    )
    .bind(is_admin)
    .bind(principal.user_id.0)
    .fetch_all(&mut **tx)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| HttpLibTokenSummary {
            id: r.get("id"),
            user_id: r.get("user_id"),
            name: r.get("name"),
            scopes: r.get("scopes"),
            created_at: format_ts(r.get("created_at")),
            expires_at: format_ts(r.get("expires_at")),
            last_used_at: r.get::<Option<OffsetDateTime>, _>("last_used_at").map(format_ts),
            revoked_at: r.get::<Option<OffsetDateTime>, _>("revoked_at").map(format_ts),
        })
        .collect())
}

pub async fn revoke_httplib_device_token(
    tx: &mut Tx,
    principal: &Principal,
    token_id: Uuid,
) -> Result<()> {
    let row = sqlx::query(
        "SELECT user_id FROM auth_tokens WHERE id = $1 AND kind = 'd'",
    )
    .bind(token_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(Error::NotFound)?;

    let owner_id: Uuid = row.get("user_id");
    if owner_id != principal.user_id.0 && !principal.can(Permission::AdminManage) {
        return Err(Error::NotFound);
    }

    if !auth::revoke_token(tx, principal.tenant_id, token_id).await? {
        return Err(Error::NotFound);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_like_pattern_escapes_wildcards_and_enforces_limit() {
        assert_eq!(
            escape_like_pattern("STM32_G4%\\A").unwrap(),
            "%stm32\\_g4\\%\\\\a%"
        );
        assert!(escape_like_pattern(&"a".repeat(100)).is_ok());
        assert!(escape_like_pattern(&"a".repeat(101)).is_err());
    }
}
