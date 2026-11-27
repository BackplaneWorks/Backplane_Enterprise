//! Board co-development (spec §3.3): what the web portal needs to review a
//! board without KiCad installed.
//!
//! - **Boards and revisions.** A revision is pushed by the desktop app, CI or
//!   a Boat VM with its BOM and component placement. Revisions are immutable;
//!   a released revision can only be altered through the
//!   `modify_released_board` approval gate.
//! - **Snapshots.** Layer/schematic SVGs, 3D models and fabrication outputs,
//!   envelope-encrypted with the tenant's key before they are stored.
//! - **Review.** Comments pinned to `(layer, x, y)` and/or a reference
//!   designator, BOM/placement diffs between revisions, ECOs with a
//!   four-eyes approval step.
//! - **External reviewers** (contract manufacturers) only see boards that
//!   were explicitly shared with them, and can only comment.

#![forbid(unsafe_code)]

pub mod diff;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use bp_ent_core::policy::{self, Approval, GateKind};
use bp_ent_core::{audit, AppCtx, Error, Permission, Principal, Result, Role, Tx};
use diff::{BomLine, Component, DiffEntry};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

/// Largest snapshot artifact accepted.
pub const MAX_ARTIFACT_BYTES: usize = 16 * 1024 * 1024;
const MAX_COMPONENTS: usize = 20_000;
const MAX_BOM_LINES: usize = 5_000;

/// This crate's migrations (0500-0599).
pub fn migrator() -> sqlx::migrate::Migrator {
    sqlx::migrate!("./migrations")
}

/// Routes under `/v1/boards`, authenticated.
pub fn router(ctx: AppCtx) -> Router {
    let r = Router::new()
        .route("/v1/boards", get(list_boards).post(create_board))
        .route("/v1/boards/where-used", get(where_used))
        .route("/v1/boards/{board}", get(get_board).patch(update_board))
        .route("/v1/boards/{board}/revisions", post(push_revision))
        .route("/v1/boards/{board}/revisions/{rev}/release", post(release_revision))
        .route("/v1/boards/{board}/revisions/{rev}/bom", get(get_bom))
        .route("/v1/boards/{board}/revisions/{rev}/artifacts", get(list_artifacts))
        .route(
            "/v1/boards/{board}/revisions/{rev}/artifacts/{kind}",
            put(put_artifact).get(get_artifact).layer(DefaultBodyLimit::max(MAX_ARTIFACT_BYTES)),
        )
        .route("/v1/boards/{board}/diff", get(get_diff))
        .route("/v1/boards/{board}/comments", get(list_comments).post(add_comment))
        .route("/v1/boards/{board}/comments/{comment}/resolve", post(resolve_comment))
        .route("/v1/boards/{board}/comments/{comment}/reopen", post(reopen_comment))
        .route("/v1/boards/{board}/ecos", get(list_ecos).post(create_eco))
        .route("/v1/boards/{board}/ecos/{eco}/transition", post(transition_eco))
        .with_state(ctx.clone());
    bp_ent_core::http::with_auth(r, &ctx)
}

fn rfc3339(t: time::OffsetDateTime) -> String {
    t.format(&time::format_description::well_known::Rfc3339).unwrap_or_default()
}

// ------------------------------------------------------------------ DTOs

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevisionOut {
    id: Uuid,
    tag: String,
    commit_sha: String,
    author: String,
    created_at: String,
    summary: String,
    status: String,
    seq: i32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommentOut {
    id: Uuid,
    board_id: Uuid,
    revision_id: Uuid,
    layer: String,
    x_mm: f64,
    y_mm: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    refdes: Option<String>,
    author_email: String,
    body: String,
    resolved: bool,
    created_at: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EcoOut {
    id: Uuid,
    code: String,
    title: String,
    rationale: String,
    status: String,
    created_by: String,
    created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    revision_id: Option<Uuid>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BoardOut {
    id: Uuid,
    name: String,
    slug: String,
    description: String,
    width_mm: f64,
    height_mm: f64,
    layer_count: i32,
    external_access: bool,
    /// Newest first.
    revisions: Vec<RevisionOut>,
    /// Placement of the newest revision.
    components: Vec<Component>,
    comments: Vec<CommentOut>,
    /// Newest revision against the one before it.
    diffs: Vec<DiffEntry>,
    ecos: Vec<EcoOut>,
}

// ---------------------------------------------------------------- access

struct BoardRow {
    id: Uuid,
    name: String,
    slug: String,
    description: String,
    width_mm: f64,
    height_mm: f64,
    layer_count: i32,
    external_access: bool,
}

fn board_row(r: &sqlx::postgres::PgRow) -> BoardRow {
    BoardRow {
        id: r.get("id"),
        name: r.get("name"),
        slug: r.get("slug"),
        description: r.get("description"),
        width_mm: r.get("width_mm"),
        height_mm: r.get("height_mm"),
        layer_count: r.get("layer_count"),
        external_access: r.get("external_access"),
    }
}

const BOARD_COLS: &str = "id, name, slug, description, width_mm, height_mm, layer_count, external_access";

/// External reviewers only ever see boards shared with them.
fn sees_all_boards(p: &Principal) -> bool {
    p.role != Role::ExternalReviewer
}

/// Load a board the caller may read. A board that exists but is not shared
/// with an external reviewer is "not found", like one in another tenant.
async fn load_board(tx: &mut Tx, p: &Principal, id: Uuid) -> Result<BoardRow> {
    p.require(Permission::BoardsRead)?;
    let r = sqlx::query(&format!("SELECT {BOARD_COLS} FROM boards WHERE tenant_id = $1 AND id = $2 AND ($3 OR external_access)"))
        .bind(p.tenant_id.0)
        .bind(id)
        .bind(sees_all_boards(p))
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(Error::NotFound)?;
    Ok(board_row(&r))
}

struct RevRow {
    status: String,
    tag: String,
}

async fn load_revision(tx: &mut Tx, p: &Principal, board: Uuid, rev: Uuid) -> Result<RevRow> {
    let r = sqlx::query("SELECT status, tag FROM board_revisions WHERE tenant_id = $1 AND board_id = $2 AND id = $3")
        .bind(p.tenant_id.0)
        .bind(board)
        .bind(rev)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(Error::NotFound)?;
    Ok(RevRow { status: r.get("status"), tag: r.get("tag") })
}

// ---------------------------------------------------------------- boards

async fn revisions_of(tx: &mut Tx, p: &Principal, board: Uuid) -> Result<Vec<RevisionOut>> {
    let rows = sqlx::query(
        "SELECT r.id, r.tag, r.commit_sha, r.summary, r.status, r.seq, r.created_at, COALESCE(NULLIF(u.name, ''), u.email) AS author \
         FROM board_revisions r JOIN users u ON u.tenant_id = r.tenant_id AND u.id = r.created_by \
         WHERE r.tenant_id = $1 AND r.board_id = $2 ORDER BY r.seq DESC",
    )
    .bind(p.tenant_id.0)
    .bind(board)
    .fetch_all(&mut **tx)
    .await?;
    Ok(rows
        .iter()
        .map(|r| RevisionOut { id: r.get("id"), tag: r.get("tag"), commit_sha: r.get("commit_sha"), author: r.get("author"), created_at: rfc3339(r.get("created_at")), summary: r.get("summary"), status: r.get("status"), seq: r.get("seq") })
        .collect())
}

async fn components_of(tx: &mut Tx, p: &Principal, rev: Uuid) -> Result<Vec<Component>> {
    let v: Option<serde_json::Value> = sqlx::query_scalar("SELECT components FROM board_revisions WHERE tenant_id = $1 AND id = $2").bind(p.tenant_id.0).bind(rev).fetch_optional(&mut **tx).await?;
    Ok(v.and_then(|v| serde_json::from_value(v).ok()).unwrap_or_default())
}

async fn bom_of(tx: &mut Tx, p: &Principal, rev: Uuid) -> Result<Vec<BomLine>> {
    let rows = sqlx::query("SELECT mpn, manufacturer, value, footprint, quantity, refdes FROM board_bom_lines WHERE tenant_id = $1 AND revision_id = $2 ORDER BY mpn")
        .bind(p.tenant_id.0)
        .bind(rev)
        .fetch_all(&mut **tx)
        .await?;
    Ok(rows
        .iter()
        .map(|r| BomLine { mpn: r.get("mpn"), manufacturer: r.get("manufacturer"), value: r.get("value"), footprint: r.get("footprint"), quantity: r.get("quantity"), refdes: r.get("refdes") })
        .collect())
}

async fn comments_of(tx: &mut Tx, p: &Principal, board: Uuid, revision: Option<Uuid>) -> Result<Vec<CommentOut>> {
    let rows = sqlx::query(
        "SELECT c.id, c.board_id, c.revision_id, c.layer, c.x_mm, c.y_mm, c.refdes, c.body, c.resolved, c.created_at, u.email \
         FROM board_comments c JOIN users u ON u.tenant_id = c.tenant_id AND u.id = c.author_id \
         WHERE c.tenant_id = $1 AND c.board_id = $2 AND ($3::uuid IS NULL OR c.revision_id = $3) ORDER BY c.created_at LIMIT 2000",
    )
    .bind(p.tenant_id.0)
    .bind(board)
    .bind(revision)
    .fetch_all(&mut **tx)
    .await?;
    Ok(rows.iter().map(comment_out).collect())
}

fn comment_out(r: &sqlx::postgres::PgRow) -> CommentOut {
    CommentOut {
        id: r.get("id"),
        board_id: r.get("board_id"),
        revision_id: r.get("revision_id"),
        layer: r.get("layer"),
        x_mm: r.get("x_mm"),
        y_mm: r.get("y_mm"),
        refdes: r.get("refdes"),
        author_email: r.get("email"),
        body: r.get("body"),
        resolved: r.get("resolved"),
        created_at: rfc3339(r.get("created_at")),
    }
}

async fn ecos_of(tx: &mut Tx, p: &Principal, board: Uuid) -> Result<Vec<EcoOut>> {
    let rows = sqlx::query(
        "SELECT e.id, e.number, e.title, e.rationale, e.status, e.revision_id, e.created_at, u.email \
         FROM board_ecos e JOIN users u ON u.tenant_id = e.tenant_id AND u.id = e.created_by \
         WHERE e.tenant_id = $1 AND e.board_id = $2 ORDER BY e.number DESC",
    )
    .bind(p.tenant_id.0)
    .bind(board)
    .fetch_all(&mut **tx)
    .await?;
    Ok(rows.iter().map(eco_out).collect())
}

fn eco_out(r: &sqlx::postgres::PgRow) -> EcoOut {
    EcoOut {
        id: r.get("id"),
        code: format!("ECO-{:04}", r.get::<i32, _>("number")),
        title: r.get("title"),
        rationale: r.get("rationale"),
        status: r.get("status"),
        created_by: r.get("email"),
        created_at: rfc3339(r.get("created_at")),
        revision_id: r.get("revision_id"),
    }
}

async fn board_out(tx: &mut Tx, p: &Principal, b: BoardRow) -> Result<BoardOut> {
    let revisions = revisions_of(tx, p, b.id).await?;
    let (components, diffs) = match revisions.as_slice() {
        [] => (vec![], vec![]),
        [only] => (components_of(tx, p, only.id).await?, vec![]),
        [new, old, ..] => {
            let (nc, oc) = (components_of(tx, p, new.id).await?, components_of(tx, p, old.id).await?);
            let d = diff::diff(&bom_of(tx, p, old.id).await?, &bom_of(tx, p, new.id).await?, &oc, &nc);
            (nc, d)
        }
    };
    Ok(BoardOut {
        comments: comments_of(tx, p, b.id, None).await?,
        ecos: ecos_of(tx, p, b.id).await?,
        id: b.id,
        name: b.name,
        slug: b.slug,
        description: b.description,
        width_mm: b.width_mm,
        height_mm: b.height_mm,
        layer_count: b.layer_count,
        external_access: b.external_access,
        revisions,
        components,
        diffs,
    })
}

async fn list_boards(State(ctx): State<AppCtx>, p: Principal) -> Result<Json<Vec<BoardOut>>> {
    p.require(Permission::BoardsRead)?;
    let mut tx = ctx.db.tenant_tx(p.tenant_id).await?;
    let rows = sqlx::query(&format!("SELECT {BOARD_COLS} FROM boards WHERE tenant_id = $1 AND ($2 OR external_access) ORDER BY name LIMIT 200"))
        .bind(p.tenant_id.0)
        .bind(sees_all_boards(&p))
        .fetch_all(&mut *tx)
        .await?;
    let mut out = Vec::with_capacity(rows.len());
    for r in &rows {
        out.push(board_out(&mut tx, &p, board_row(r)).await?);
    }
    Ok(Json(out))
}

async fn get_board(State(ctx): State<AppCtx>, p: Principal, Path(board): Path<Uuid>) -> Result<Json<BoardOut>> {
    let mut tx = ctx.db.tenant_tx(p.tenant_id).await?;
    let b = load_board(&mut tx, &p, board).await?;
    Ok(Json(board_out(&mut tx, &p, b).await?))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateBoard {
    name: String,
    slug: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    width_mm: f64,
    #[serde(default)]
    height_mm: f64,
    #[serde(default = "two")]
    layer_count: i32,
}

fn two() -> i32 {
    2
}

fn finite(v: f64) -> Result<f64> {
    if v.is_finite() {
        Ok(v)
    } else {
        Err(Error::invalid("numbers must be finite"))
    }
}

async fn create_board(State(ctx): State<AppCtx>, p: Principal, Json(req): Json<CreateBoard>) -> Result<(StatusCode, Json<BoardOut>)> {
    p.require(Permission::BoardsWrite)?;
    let id = Uuid::new_v4();
    let mut tx = ctx.db.tenant_tx(p.tenant_id).await?;
    let r = sqlx::query(&format!(
        "INSERT INTO boards (id, tenant_id, name, slug, description, width_mm, height_mm, layer_count, created_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING {BOARD_COLS}"
    ))
    .bind(id)
    .bind(p.tenant_id.0)
    .bind(req.name.trim())
    .bind(req.slug.trim().to_ascii_lowercase())
    .bind(&req.description)
    .bind(finite(req.width_mm)?)
    .bind(finite(req.height_mm)?)
    .bind(req.layer_count)
    .bind(p.user_id.0)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| match Error::from(e) {
        Error::Conflict(_) => Error::conflict("a board with this slug already exists"),
        other => other,
    })?;
    audit::append(&mut tx, &p, "board.created", &format!("board:{id}"), serde_json::json!({ "slug": req.slug })).await?;
    let out = board_out(&mut tx, &p, board_row(&r)).await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(out)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UpdateBoard {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    /// Share with (or hide from) external reviewers.
    #[serde(default)]
    external_access: Option<bool>,
}

async fn update_board(State(ctx): State<AppCtx>, p: Principal, Path(board): Path<Uuid>, Json(req): Json<UpdateBoard>) -> Result<Json<BoardOut>> {
    p.require(Permission::BoardsWrite)?;
    let mut tx = ctx.db.tenant_tx(p.tenant_id).await?;
    let before = load_board(&mut tx, &p, board).await?;
    let r = sqlx::query(&format!(
        "UPDATE boards SET name = COALESCE($3, name), description = COALESCE($4, description), external_access = COALESCE($5, external_access) WHERE tenant_id = $1 AND id = $2 RETURNING {BOARD_COLS}"
    ))
    .bind(p.tenant_id.0)
    .bind(board)
    .bind(req.name.as_deref().map(str::trim))
    .bind(&req.description)
    .bind(req.external_access)
    .fetch_one(&mut *tx)
    .await?;
    if let Some(share) = req.external_access {
        if share != before.external_access {
            // Opening a board to outsiders is the event an auditor looks for.
            audit::append(&mut tx, &p, if share { "board.shared_externally" } else { "board.unshared" }, &format!("board:{board}"), serde_json::json!({})).await?;
        }
    }
    let out = board_out(&mut tx, &p, board_row(&r)).await?;
    tx.commit().await?;
    Ok(Json(out))
}

// ------------------------------------------------------------- revisions

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PushRevision {
    tag: String,
    #[serde(default)]
    commit_sha: String,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    components: Vec<Component>,
    #[serde(default)]
    bom: Vec<BomLine>,
}

fn valid_refdes(s: &str) -> bool {
    !s.is_empty() && s.len() <= 32 && s.chars().all(|c| c.is_ascii_alphanumeric() || "_#.+-".contains(c))
}

fn validate_components(parts: &[Component]) -> Result<()> {
    if parts.len() > MAX_COMPONENTS {
        return Err(Error::invalid("too many components"));
    }
    let mut seen = std::collections::HashSet::new();
    for c in parts {
        let nums_ok = [c.x_mm, c.y_mm, c.width_mm, c.height_mm].iter().all(|v| v.is_finite() && v.abs() <= 10_000.0);
        if !valid_refdes(&c.refdes) || !nums_ok || !matches!(c.layer.as_str(), "F.Cu" | "B.Cu") || c.mpn.len() > 200 || c.package_name.len() > 200 {
            return Err(Error::invalid(format!("invalid component {}", c.refdes.chars().take(32).collect::<String>())));
        }
        if !seen.insert(c.refdes.as_str()) {
            return Err(Error::invalid(format!("duplicate reference designator {}", c.refdes)));
        }
    }
    Ok(())
}

/// Record a new revision of a board with its BOM and placement.
async fn push_revision(State(ctx): State<AppCtx>, p: Principal, Path(board): Path<Uuid>, Json(req): Json<PushRevision>) -> Result<(StatusCode, Json<RevisionOut>)> {
    p.require(Permission::BoardsWrite)?;
    validate_components(&req.components)?;
    if req.bom.len() > MAX_BOM_LINES || req.bom.iter().any(|l| l.refdes.len() > 2000 || !l.refdes.iter().all(|r| valid_refdes(r))) {
        return Err(Error::invalid("invalid BOM"));
    }
    let mut tx = ctx.db.tenant_tx(p.tenant_id).await?;
    load_board(&mut tx, &p, board).await?;
    // Lock the board row so two pushes get consecutive sequence numbers.
    sqlx::query("SELECT 1 FROM boards WHERE tenant_id = $1 AND id = $2 FOR UPDATE").bind(p.tenant_id.0).bind(board).execute(&mut *tx).await?;
    let seq: i32 = sqlx::query_scalar("SELECT COALESCE(max(seq), 0) + 1 FROM board_revisions WHERE tenant_id = $1 AND board_id = $2").bind(p.tenant_id.0).bind(board).fetch_one(&mut *tx).await?;
    let id = Uuid::new_v4();
    let created: time::OffsetDateTime = sqlx::query_scalar(
        "INSERT INTO board_revisions (id, tenant_id, board_id, seq, tag, commit_sha, summary, components, created_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING created_at",
    )
    .bind(id)
    .bind(p.tenant_id.0)
    .bind(board)
    .bind(seq)
    .bind(req.tag.trim())
    .bind(req.commit_sha.trim().to_ascii_lowercase())
    .bind(&req.summary)
    .bind(sqlx::types::Json(&req.components))
    .bind(p.user_id.0)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| match Error::from(e) {
        Error::Conflict(_) => Error::conflict("this board already has a revision with that tag"),
        other => other,
    })?;
    for l in &req.bom {
        sqlx::query("INSERT INTO board_bom_lines (id, tenant_id, revision_id, mpn, manufacturer, value, footprint, quantity, refdes) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)")
            .bind(Uuid::new_v4())
            .bind(p.tenant_id.0)
            .bind(id)
            .bind(l.mpn.trim())
            .bind(&l.manufacturer)
            .bind(&l.value)
            .bind(&l.footprint)
            .bind(l.quantity)
            .bind(&l.refdes)
            .execute(&mut *tx)
            .await?;
    }
    audit::append(&mut tx, &p, "board.revision_pushed", &format!("board:{board}"), serde_json::json!({ "revision": id, "tag": req.tag, "commit": req.commit_sha, "bomLines": req.bom.len(), "components": req.components.len() })).await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(RevisionOut { id, tag: req.tag.trim().to_string(), commit_sha: req.commit_sha, author: p.email.clone(), created_at: rfc3339(created), summary: req.summary, status: "draft".into(), seq }),
    ))
}

/// Mark a revision as released: from then on it is frozen.
async fn release_revision(State(ctx): State<AppCtx>, p: Principal, Path((board, rev)): Path<(Uuid, Uuid)>) -> Result<Json<serde_json::Value>> {
    p.require(Permission::BoardsWrite)?;
    let mut tx = ctx.db.tenant_tx(p.tenant_id).await?;
    load_board(&mut tx, &p, board).await?;
    let r = load_revision(&mut tx, &p, board, rev).await?;
    if r.status == "released" {
        return Err(Error::conflict("revision is already released"));
    }
    sqlx::query("UPDATE board_revisions SET status = 'released', released_by = $3, released_at = now() WHERE tenant_id = $1 AND id = $2")
        .bind(p.tenant_id.0)
        .bind(rev)
        .bind(p.user_id.0)
        .execute(&mut *tx)
        .await?;
    audit::append(&mut tx, &p, "board.revision_released", &format!("board:{board}"), serde_json::json!({ "revision": rev, "tag": r.tag })).await?;
    tx.commit().await?;
    Ok(Json(serde_json::json!({ "id": rev, "status": "released" })))
}

async fn get_bom(State(ctx): State<AppCtx>, p: Principal, Path((board, rev)): Path<(Uuid, Uuid)>) -> Result<Json<Vec<BomLine>>> {
    let mut tx = ctx.db.tenant_tx(p.tenant_id).await?;
    load_board(&mut tx, &p, board).await?;
    load_revision(&mut tx, &p, board, rev).await?;
    Ok(Json(bom_of(&mut tx, &p, rev).await?))
}

#[derive(Deserialize)]
struct DiffQuery {
    from: Uuid,
    to: Uuid,
}

async fn get_diff(State(ctx): State<AppCtx>, p: Principal, Path(board): Path<Uuid>, Query(q): Query<DiffQuery>) -> Result<Json<Vec<DiffEntry>>> {
    let mut tx = ctx.db.tenant_tx(p.tenant_id).await?;
    load_board(&mut tx, &p, board).await?;
    load_revision(&mut tx, &p, board, q.from).await?;
    load_revision(&mut tx, &p, board, q.to).await?;
    let d = diff::diff(&bom_of(&mut tx, &p, q.from).await?, &bom_of(&mut tx, &p, q.to).await?, &components_of(&mut tx, &p, q.from).await?, &components_of(&mut tx, &p, q.to).await?);
    Ok(Json(d))
}

#[derive(Deserialize)]
struct WhereUsedQuery {
    mpn: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WhereUsedOut {
    board_id: Uuid,
    board_name: String,
    revision_id: Uuid,
    revision_tag: String,
    revision_status: String,
    quantity: i32,
    refdes: Vec<String>,
}

/// Which boards (latest revision of each) use a manufacturer part number:
/// the impact list for an EOL notice or a part change.
async fn where_used(State(ctx): State<AppCtx>, p: Principal, Query(q): Query<WhereUsedQuery>) -> Result<Json<Vec<WhereUsedOut>>> {
    p.require(Permission::BoardsRead)?;
    if q.mpn.is_empty() || q.mpn.len() > 200 {
        return Err(Error::invalid("mpn is required"));
    }
    let mut tx = ctx.db.tenant_tx(p.tenant_id).await?;
    let rows = sqlx::query(
        "SELECT b.id AS board_id, b.name, r.id AS revision_id, r.tag, r.status, l.quantity, l.refdes \
         FROM boards b \
         JOIN board_revisions r ON r.tenant_id = b.tenant_id AND r.board_id = b.id \
              AND r.seq = (SELECT max(seq) FROM board_revisions x WHERE x.tenant_id = b.tenant_id AND x.board_id = b.id) \
         JOIN board_bom_lines l ON l.tenant_id = r.tenant_id AND l.revision_id = r.id \
         WHERE b.tenant_id = $1 AND l.mpn = $2 AND ($3 OR b.external_access) ORDER BY b.name LIMIT 500",
    )
    .bind(p.tenant_id.0)
    .bind(&q.mpn)
    .bind(sees_all_boards(&p))
    .fetch_all(&mut *tx)
    .await?;
    Ok(Json(
        rows.iter()
            .map(|r| WhereUsedOut { board_id: r.get("board_id"), board_name: r.get("name"), revision_id: r.get("revision_id"), revision_tag: r.get("tag"), revision_status: r.get("status"), quantity: r.get("quantity"), refdes: r.get("refdes") })
            .collect(),
    ))
}

// ------------------------------------------------------------- artifacts

fn content_type(kind: &str) -> Option<&'static str> {
    Some(match kind {
        "pcb_svg" | "schematic_svg" => "image/svg+xml",
        "model_glb" => "model/gltf-binary",
        "model_step" => "application/step",
        "solidcraft" => "application/zip",
        "model_stl" => "model/stl",
        "model_3mf" => "model/3mf",
        "model_iges" => "model/iges",
        "model_obj" => "model/obj",
        "gerbers_zip" => "application/zip",
        "bom_csv" => "text/csv; charset=utf-8",
        "kicad_pcb" | "kicad_sch" => "application/octet-stream",
        "pdf" => "application/pdf",
        _ => return None,
    })
}

fn artifact_aad(id: Uuid) -> Vec<u8> {
    format!("board_artifacts|{id}|data").into_bytes()
}

#[derive(Deserialize)]
struct ArtifactQuery {
    /// Distinguishes several artifacts of one kind, e.g. the layer: `F.Cu`.
    #[serde(default)]
    name: String,
}

fn valid_artifact_name(n: &str) -> bool {
    n.len() <= 80 && n.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ArtifactOut {
    id: Uuid,
    kind: String,
    name: String,
    size_bytes: i64,
    sha256: String,
    created_at: String,
}

async fn list_artifacts(State(ctx): State<AppCtx>, p: Principal, Path((board, rev)): Path<(Uuid, Uuid)>) -> Result<Json<Vec<ArtifactOut>>> {
    let mut tx = ctx.db.tenant_tx(p.tenant_id).await?;
    load_board(&mut tx, &p, board).await?;
    load_revision(&mut tx, &p, board, rev).await?;
    let rows = sqlx::query("SELECT id, kind, name, size_bytes, encode(sha256, 'hex') AS sha, created_at FROM board_artifacts WHERE tenant_id = $1 AND revision_id = $2 ORDER BY kind, name")
        .bind(p.tenant_id.0)
        .bind(rev)
        .fetch_all(&mut *tx)
        .await?;
    Ok(Json(
        rows.iter()
            .map(|r| ArtifactOut { id: r.get("id"), kind: r.get("kind"), name: r.get("name"), size_bytes: r.get("size_bytes"), sha256: r.get("sha"), created_at: rfc3339(r.get("created_at")) })
            .collect(),
    ))
}

/// Upload (or replace) a snapshot. The bytes are sealed with the tenant's
/// key before they reach the database. Changing a released revision goes
/// through the `modify_released_board` gate.
async fn put_artifact(State(ctx): State<AppCtx>, p: Principal, Path((board, rev, kind)): Path<(Uuid, Uuid, String)>, Query(q): Query<ArtifactQuery>, body: Bytes) -> Result<Response> {
    use sha2::Digest;
    p.require(Permission::BoardsWrite)?;
    if content_type(&kind).is_none() || !valid_artifact_name(&q.name) {
        return Err(Error::invalid("unknown artifact kind or invalid name"));
    }
    if body.is_empty() || body.len() > MAX_ARTIFACT_BYTES {
        return Err(Error::invalid("artifact must be between 1 byte and 16 MiB"));
    }
    let digest = sha2::Sha256::digest(&body);
    let mut tx = ctx.db.tenant_tx(p.tenant_id).await?;
    load_board(&mut tx, &p, board).await?;
    let r = load_revision(&mut tx, &p, board, rev).await?;
    if r.status == "released" {
        let summary = serde_json::json!({ "board": board, "revision": r.tag, "artifact": kind, "name": q.name, "sha256": hex(&digest) });
        match policy::require_approval(&mut tx, &p, GateKind::ModifyReleasedBoard, &format!("board-revision:{rev}"), summary).await? {
            a if a.may_proceed() => {}
            Approval::Pending { request_id } => {
                tx.commit().await?;
                return Ok((StatusCode::ACCEPTED, Json(serde_json::json!({ "status": "pending_approval", "requestId": request_id }))).into_response());
            }
            _ => return Err(Error::Forbidden),
        }
    }
    let existing: Option<Uuid> = sqlx::query_scalar("SELECT id FROM board_artifacts WHERE tenant_id = $1 AND revision_id = $2 AND kind = $3 AND name = $4 FOR UPDATE")
        .bind(p.tenant_id.0)
        .bind(rev)
        .bind(&kind)
        .bind(&q.name)
        .fetch_optional(&mut *tx)
        .await?;
    let id = existing.unwrap_or_else(Uuid::new_v4);
    let sealed = ctx.cipher.seal(p.tenant_id, &artifact_aad(id), &body).await?;
    sqlx::query(
        "INSERT INTO board_artifacts (id, tenant_id, revision_id, kind, name, size_bytes, sha256, data, uploaded_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
         ON CONFLICT (id) DO UPDATE SET size_bytes = EXCLUDED.size_bytes, sha256 = EXCLUDED.sha256, data = EXCLUDED.data, uploaded_by = EXCLUDED.uploaded_by, created_at = now()",
    )
    .bind(id)
    .bind(p.tenant_id.0)
    .bind(rev)
    .bind(&kind)
    .bind(&q.name)
    .bind(body.len() as i64)
    .bind(digest.as_slice())
    .bind(&sealed)
    .bind(p.user_id.0)
    .execute(&mut *tx)
    .await?;
    audit::append(&mut tx, &p, "board.artifact_uploaded", &format!("board:{board}"), serde_json::json!({ "revision": rev, "kind": kind, "name": q.name, "bytes": body.len(), "sha256": hex(&digest) })).await?;
    tx.commit().await?;
    Ok((StatusCode::OK, Json(serde_json::json!({ "id": id, "kind": kind, "name": q.name, "sizeBytes": body.len(), "sha256": hex(&digest) }))).into_response())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

async fn get_artifact(State(ctx): State<AppCtx>, p: Principal, Path((board, rev, kind)): Path<(Uuid, Uuid, String)>, Query(q): Query<ArtifactQuery>) -> Result<Response> {
    let ctype = content_type(&kind).ok_or(Error::NotFound)?;
    let mut tx = ctx.db.tenant_tx(p.tenant_id).await?;
    load_board(&mut tx, &p, board).await?;
    load_revision(&mut tx, &p, board, rev).await?;
    let row = sqlx::query("SELECT id, data FROM board_artifacts WHERE tenant_id = $1 AND revision_id = $2 AND kind = $3 AND name = $4")
        .bind(p.tenant_id.0)
        .bind(rev)
        .bind(&kind)
        .bind(&q.name)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(Error::NotFound)?;
    tx.commit().await?;
    let data = ctx.cipher.open(p.tenant_id, &artifact_aad(row.get("id")), &row.get::<Vec<u8>, _>("data")).await?;
    let mut resp = data.into_response();
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(ctype));
    // Uploaded files are untrusted content: an SVG may carry script. It is
    // shown through <img>, and if opened directly the sandbox stops it.
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("default-src 'none'; style-src 'unsafe-inline'; sandbox"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("private, no-store"));
    h.insert(header::VARY, HeaderValue::from_static("Authorization, Cookie"));
    if !ctype.starts_with("image/svg") {
        h.insert(header::CONTENT_DISPOSITION, HeaderValue::from_static("attachment"));
    }
    Ok(resp)
}

// -------------------------------------------------------------- comments

#[derive(Deserialize)]
struct CommentsQuery {
    #[serde(default)]
    revision: Option<Uuid>,
}

async fn list_comments(State(ctx): State<AppCtx>, p: Principal, Path(board): Path<Uuid>, Query(q): Query<CommentsQuery>) -> Result<Json<Vec<CommentOut>>> {
    let mut tx = ctx.db.tenant_tx(p.tenant_id).await?;
    load_board(&mut tx, &p, board).await?;
    Ok(Json(comments_of(&mut tx, &p, board, q.revision).await?))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AddComment {
    revision_id: Uuid,
    layer: String,
    x_mm: f64,
    y_mm: f64,
    #[serde(default)]
    refdes: Option<String>,
    body: String,
}

/// Pin a review comment to a point on a layer (and optionally a component).
async fn add_comment(State(ctx): State<AppCtx>, p: Principal, Path(board): Path<Uuid>, Json(req): Json<AddComment>) -> Result<(StatusCode, Json<CommentOut>)> {
    p.require(Permission::BoardsComment)?;
    let body = req.body.trim();
    if body.is_empty() || body.len() > 8000 {
        return Err(Error::invalid("comment must be 1-8000 characters"));
    }
    finite(req.x_mm)?;
    finite(req.y_mm)?;
    let refdes = req.refdes.as_deref().map(str::trim).filter(|s| !s.is_empty());
    if matches!(refdes, Some(r) if !valid_refdes(r)) {
        return Err(Error::invalid("invalid reference designator"));
    }
    let mut tx = ctx.db.tenant_tx(p.tenant_id).await?;
    load_board(&mut tx, &p, board).await?;
    load_revision(&mut tx, &p, board, req.revision_id).await?;
    let id = Uuid::new_v4();
    let created: time::OffsetDateTime = sqlx::query_scalar(
        "INSERT INTO board_comments (id, tenant_id, board_id, revision_id, layer, x_mm, y_mm, refdes, body, author_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING created_at",
    )
    .bind(id)
    .bind(p.tenant_id.0)
    .bind(board)
    .bind(req.revision_id)
    .bind(req.layer.trim())
    .bind(req.x_mm)
    .bind(req.y_mm)
    .bind(refdes)
    .bind(body)
    .bind(p.user_id.0)
    .fetch_one(&mut *tx)
    .await?;
    audit::append(&mut tx, &p, "board.comment_added", &format!("board:{board}"), serde_json::json!({ "comment": id, "revision": req.revision_id, "layer": req.layer, "refdes": refdes })).await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(CommentOut { id, board_id: board, revision_id: req.revision_id, layer: req.layer.trim().to_string(), x_mm: req.x_mm, y_mm: req.y_mm, refdes: refdes.map(String::from), author_email: p.email.clone(), body: body.to_string(), resolved: false, created_at: rfc3339(created) }),
    ))
}

async fn set_resolved(ctx: &AppCtx, p: &Principal, board: Uuid, comment: Uuid, resolved: bool) -> Result<Json<CommentOut>> {
    p.require(Permission::BoardsComment)?;
    let mut tx = ctx.db.tenant_tx(p.tenant_id).await?;
    load_board(&mut tx, p, board).await?;
    let author: Uuid = sqlx::query_scalar("SELECT author_id FROM board_comments WHERE tenant_id = $1 AND board_id = $2 AND id = $3 FOR UPDATE")
        .bind(p.tenant_id.0)
        .bind(board)
        .bind(comment)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(Error::NotFound)?;
    // Outside reviewers may close their own threads, not the team's.
    if p.role == Role::ExternalReviewer && author != p.user_id.0 {
        return Err(Error::Forbidden);
    }
    sqlx::query("UPDATE board_comments SET resolved = $4, resolved_by = CASE WHEN $4 THEN $5 END, resolved_at = CASE WHEN $4 THEN now() END WHERE tenant_id = $1 AND board_id = $2 AND id = $3")
        .bind(p.tenant_id.0)
        .bind(board)
        .bind(comment)
        .bind(resolved)
        .bind(p.user_id.0)
        .execute(&mut *tx)
        .await?;
    audit::append(&mut tx, p, if resolved { "board.comment_resolved" } else { "board.comment_reopened" }, &format!("board:{board}"), serde_json::json!({ "comment": comment })).await?;
    let r = sqlx::query(
        "SELECT c.id, c.board_id, c.revision_id, c.layer, c.x_mm, c.y_mm, c.refdes, c.body, c.resolved, c.created_at, u.email \
         FROM board_comments c JOIN users u ON u.tenant_id = c.tenant_id AND u.id = c.author_id WHERE c.tenant_id = $1 AND c.id = $2",
    )
    .bind(p.tenant_id.0)
    .bind(comment)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(comment_out(&r)))
}

async fn resolve_comment(State(ctx): State<AppCtx>, p: Principal, Path((board, comment)): Path<(Uuid, Uuid)>) -> Result<Json<CommentOut>> {
    set_resolved(&ctx, &p, board, comment, true).await
}

async fn reopen_comment(State(ctx): State<AppCtx>, p: Principal, Path((board, comment)): Path<(Uuid, Uuid)>) -> Result<Json<CommentOut>> {
    set_resolved(&ctx, &p, board, comment, false).await
}

// ------------------------------------------------------------------ ECOs

async fn list_ecos(State(ctx): State<AppCtx>, p: Principal, Path(board): Path<Uuid>) -> Result<Json<Vec<EcoOut>>> {
    let mut tx = ctx.db.tenant_tx(p.tenant_id).await?;
    load_board(&mut tx, &p, board).await?;
    Ok(Json(ecos_of(&mut tx, &p, board).await?))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateEco {
    title: String,
    #[serde(default)]
    rationale: String,
    #[serde(default)]
    revision_id: Option<Uuid>,
}

async fn create_eco(State(ctx): State<AppCtx>, p: Principal, Path(board): Path<Uuid>, Json(req): Json<CreateEco>) -> Result<(StatusCode, Json<EcoOut>)> {
    p.require(Permission::BoardsWrite)?;
    let mut tx = ctx.db.tenant_tx(p.tenant_id).await?;
    load_board(&mut tx, &p, board).await?;
    if let Some(rev) = req.revision_id {
        load_revision(&mut tx, &p, board, rev).await?;
    }
    // ECO numbers are per organisation and gap-free.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('bpe-eco:' || $1, 0))").bind(p.tenant_id.0.to_string()).execute(&mut *tx).await?;
    let number: i32 = sqlx::query_scalar("SELECT COALESCE(max(number), 0) + 1 FROM board_ecos WHERE tenant_id = $1").bind(p.tenant_id.0).fetch_one(&mut *tx).await?;
    let id = Uuid::new_v4();
    let created: time::OffsetDateTime = sqlx::query_scalar(
        "INSERT INTO board_ecos (id, tenant_id, board_id, number, title, rationale, revision_id, created_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING created_at",
    )
    .bind(id)
    .bind(p.tenant_id.0)
    .bind(board)
    .bind(number)
    .bind(req.title.trim())
    .bind(&req.rationale)
    .bind(req.revision_id)
    .bind(p.user_id.0)
    .fetch_one(&mut *tx)
    .await?;
    audit::append(&mut tx, &p, "eco.created", &format!("eco:{id}"), serde_json::json!({ "board": board, "number": number })).await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(EcoOut { id, code: format!("ECO-{number:04}"), title: req.title.trim().to_string(), rationale: req.rationale, status: "draft".into(), created_by: p.email.clone(), created_at: rfc3339(created), revision_id: req.revision_id }),
    ))
}

/// The ECO lifecycle. `draft -> in_review -> approved -> implemented`, with
/// `rejected` out of review and back to `draft` from there.
pub fn eco_transition_allowed(from: &str, to: &str) -> bool {
    matches!((from, to), ("draft", "in_review") | ("in_review", "approved") | ("in_review", "rejected") | ("in_review", "draft") | ("rejected", "draft") | ("approved", "implemented"))
}

#[derive(Deserialize)]
struct TransitionEco {
    status: String,
}

async fn transition_eco(State(ctx): State<AppCtx>, p: Principal, Path((board, eco)): Path<(Uuid, Uuid)>, Json(req): Json<TransitionEco>) -> Result<Json<EcoOut>> {
    p.require(Permission::BoardsWrite)?;
    let mut tx = ctx.db.tenant_tx(p.tenant_id).await?;
    load_board(&mut tx, &p, board).await?;
    let row = sqlx::query("SELECT status, created_by FROM board_ecos WHERE tenant_id = $1 AND board_id = $2 AND id = $3 FOR UPDATE")
        .bind(p.tenant_id.0)
        .bind(board)
        .bind(eco)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(Error::NotFound)?;
    let from: String = row.get("status");
    if !eco_transition_allowed(&from, &req.status) {
        return Err(Error::conflict(format!("an ECO cannot go from {from} to {}", req.status)));
    }
    let deciding = matches!(req.status.as_str(), "approved" | "rejected");
    if deciding {
        // Four eyes: a person other than the author, in the browser.
        p.require_interactive()?;
        if row.get::<Uuid, _>("created_by") == p.user_id.0 {
            return Err(Error::Forbidden);
        }
    }
    sqlx::query("UPDATE board_ecos SET status = $3, decided_by = CASE WHEN $4 THEN $5 ELSE decided_by END, updated_at = now() WHERE tenant_id = $1 AND id = $2")
        .bind(p.tenant_id.0)
        .bind(eco)
        .bind(&req.status)
        .bind(deciding)
        .bind(p.user_id.0)
        .execute(&mut *tx)
        .await?;
    audit::append(&mut tx, &p, "eco.status_changed", &format!("eco:{eco}"), serde_json::json!({ "from": from, "to": req.status })).await?;
    let r = sqlx::query(
        "SELECT e.id, e.number, e.title, e.rationale, e.status, e.revision_id, e.created_at, u.email \
         FROM board_ecos e JOIN users u ON u.tenant_id = e.tenant_id AND u.id = e.created_by WHERE e.tenant_id = $1 AND e.id = $2",
    )
    .bind(p.tenant_id.0)
    .bind(eco)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(eco_out(&r)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eco_lifecycle() {
        for (a, b) in [("draft", "in_review"), ("in_review", "approved"), ("in_review", "rejected"), ("rejected", "draft"), ("approved", "implemented")] {
            assert!(eco_transition_allowed(a, b), "{a} -> {b}");
        }
        for (a, b) in [("draft", "approved"), ("draft", "implemented"), ("in_review", "implemented"), ("implemented", "draft"), ("approved", "draft"), ("rejected", "approved"), ("draft", "nonsense")] {
            assert!(!eco_transition_allowed(a, b), "{a} -> {b}");
        }
    }

    #[test]
    fn component_validation() {
        let c = |r: &str, layer: &str, x: f64| Component { refdes: r.into(), mpn: "M".into(), x_mm: x, y_mm: 0.0, width_mm: 1.0, height_mm: 1.0, layer: layer.into(), package_name: String::new() };
        assert!(validate_components(&[c("R1", "F.Cu", 1.0), c("U2", "B.Cu", 2.0)]).is_ok());
        assert!(validate_components(&[c("R1", "F.Cu", 1.0), c("R1", "F.Cu", 2.0)]).is_err());
        assert!(validate_components(&[c("R1", "In1.Cu", 1.0)]).is_err());
        assert!(validate_components(&[c("R1", "F.Cu", f64::NAN)]).is_err());
        assert!(validate_components(&[c("<script>", "F.Cu", 1.0)]).is_err());
        assert!(valid_artifact_name("F.Cu") && valid_artifact_name("") && !valid_artifact_name("../x") && !valid_artifact_name("a b"));
        assert_eq!(content_type("solidcraft"), Some("application/zip"));
        assert_eq!(content_type("model_stl"), Some("model/stl"));
        assert_eq!(content_type("model_3mf"), Some("model/3mf"));
        assert_eq!(content_type("model_iges"), Some("model/iges"));
        assert_eq!(content_type("model_obj"), Some("model/obj"));
        assert_eq!(content_type("exe"), None);
    }
}
