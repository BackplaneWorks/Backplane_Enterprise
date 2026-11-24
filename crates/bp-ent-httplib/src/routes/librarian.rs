//! Web Librarian CRUD, lifecycle transitions, Where-Used impact, IPC-7351 CAD
//! synthesis, SVG/KiCad previews, and 1-click "Open in KiCad" routes (`/v1/librarian/*`).

use crate::model::{
    ArtifactKind, ClonePartRequest, CreateCategoryRequest, CreatePartRequest, GenerateCadRequest,
    GeneratedCadResponse, LibraryCategory, LibraryPart, LifecycleTransitionRequest, ListPartsQuery,
    OpenInKiCadQuery, OpenInKiCadResponse, UpdatePartRequest, UpsertWhereUsedRequest,
    WhereUsedEntry,
};
use crate::routes::HttpLibState;
use crate::store::{self, GateOutcome};
use crate::url_guard::build_kicad_deep_link;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use bp_ent_core::{audit, Permission, Principal, Result};
use uuid::Uuid;

pub fn router() -> Router<HttpLibState> {
    Router::new()
        .route("/categories", get(list_categories).post(create_category))
        .route("/parts", get(list_parts).post(create_part))
        .route(
            "/parts/{part_id}",
            get(get_part).put(update_part).delete(delete_part),
        )
        .route("/parts/{part_id}/clone", post(clone_part))
        .route("/parts/{part_id}/lifecycle", post(transition_lifecycle))
        .route(
            "/parts/{part_id}/where-used",
            get(get_where_used).put(upsert_where_used),
        )
        .route("/parts/{part_id}/generate-cad", post(generate_cad))
        .route(
            "/parts/{part_id}/preview/footprint.svg",
            get(preview_footprint_svg),
        )
        .route("/parts/{part_id}/preview/symbol.svg", get(preview_symbol_svg))
        .route("/parts/{part_id}/kicad-footprint", get(get_kicad_footprint))
        .route("/parts/{part_id}/kicad-symbol", get(get_kicad_symbol))
        .route("/parts/{part_id}/open-in-kicad", get(open_in_kicad))
}

async fn list_categories(
    State(state): State<HttpLibState>,
    principal: Principal,
) -> Result<Json<Vec<LibraryCategory>>> {
    principal.require(Permission::PartsRead)?;
    let mut tx = state.ctx.db.tenant_tx(principal.tenant_id).await?;
    let cats = store::list_categories(&mut tx).await?;
    tx.commit().await?;
    Ok(Json(cats))
}

async fn create_category(
    State(state): State<HttpLibState>,
    principal: Principal,
    Json(req): Json<CreateCategoryRequest>,
) -> Result<(StatusCode, Json<LibraryCategory>)> {
    principal.require(Permission::PartsWrite)?;
    let mut tx = state.ctx.db.tenant_tx(principal.tenant_id).await?;
    let cat = store::create_category(&mut tx, &principal, &req).await?;
    audit::append(
        &mut tx,
        &principal,
        "librarian.category.created",
        &format!("category:{}", cat.id),
        serde_json::json!({ "name": cat.name }),
    )
    .await?;
    tx.commit().await?;
    state.cache.invalidate_tenant(principal.tenant_id);
    Ok((StatusCode::CREATED, Json(cat)))
}

async fn list_parts(
    State(state): State<HttpLibState>,
    principal: Principal,
    Query(query): Query<ListPartsQuery>,
) -> Result<Json<Vec<LibraryPart>>> {
    principal.require(Permission::PartsRead)?;
    let mut tx = state.ctx.db.tenant_tx(principal.tenant_id).await?;
    let parts = store::list_parts(&mut tx, &query).await?;
    tx.commit().await?;
    Ok(Json(parts))
}

async fn create_part(
    State(state): State<HttpLibState>,
    principal: Principal,
    Json(req): Json<CreatePartRequest>,
) -> Result<(StatusCode, Json<LibraryPart>)> {
    principal.require(Permission::PartsWrite)?;
    let mut tx = state.ctx.db.tenant_tx(principal.tenant_id).await?;
    let part = store::create_part(&mut tx, &principal, &req).await?;
    audit::append(
        &mut tx,
        &principal,
        "librarian.part.created",
        &format!("part:{}", part.id),
        serde_json::json!({ "part_number": part.part_number, "mpn": part.mpn }),
    )
    .await?;
    tx.commit().await?;
    state.cache.invalidate_tenant(principal.tenant_id);
    Ok((StatusCode::CREATED, Json(part)))
}

async fn get_part(
    State(state): State<HttpLibState>,
    principal: Principal,
    Path(part_id): Path<Uuid>,
) -> Result<Json<LibraryPart>> {
    principal.require(Permission::PartsRead)?;
    let mut tx = state.ctx.db.tenant_tx(principal.tenant_id).await?;
    let part = store::get_part(&mut tx, part_id).await?;
    tx.commit().await?;
    Ok(Json(part))
}

async fn update_part(
    State(state): State<HttpLibState>,
    principal: Principal,
    Path(part_id): Path<Uuid>,
    Json(req): Json<UpdatePartRequest>,
) -> Result<Response> {
    principal.require(Permission::PartsWrite)?;
    let mut tx = state.ctx.db.tenant_tx(principal.tenant_id).await?;
    match store::update_part(&mut tx, &principal, part_id, &req).await? {
        GateOutcome::Completed(part) => {
            audit::append(
                &mut tx,
                &principal,
                "librarian.part.updated",
                &format!("part:{}", part.id),
                serde_json::json!({ "part_number": part.part_number, "mpn": part.mpn }),
            )
            .await?;
            tx.commit().await?;
            state.cache.invalidate_tenant(principal.tenant_id);
            Ok(Json(part).into_response())
        }
        GateOutcome::PendingApproval(request_id) => {
            tx.commit().await?;
            Ok((
                StatusCode::ACCEPTED,
                Json(serde_json::json!({
                    "status": "pending_approval",
                    "requestId": request_id,
                })),
            )
                .into_response())
        }
    }
}

async fn delete_part(
    State(state): State<HttpLibState>,
    principal: Principal,
    Path(part_id): Path<Uuid>,
) -> Result<Response> {
    principal.require(Permission::PartsWrite)?;
    let mut tx = state.ctx.db.tenant_tx(principal.tenant_id).await?;
    match store::delete_part(&mut tx, &principal, part_id).await? {
        GateOutcome::Completed(()) => {
            audit::append(
                &mut tx,
                &principal,
                "librarian.part.deleted",
                &format!("part:{part_id}"),
                serde_json::json!({}),
            )
            .await?;
            tx.commit().await?;
            state.cache.invalidate_tenant(principal.tenant_id);
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        GateOutcome::PendingApproval(request_id) => {
            tx.commit().await?;
            Ok((
                StatusCode::ACCEPTED,
                Json(serde_json::json!({
                    "status": "pending_approval",
                    "requestId": request_id,
                })),
            )
                .into_response())
        }
    }
}

async fn clone_part(
    State(state): State<HttpLibState>,
    principal: Principal,
    Path(part_id): Path<Uuid>,
    Json(req): Json<ClonePartRequest>,
) -> Result<(StatusCode, Json<LibraryPart>)> {
    principal.require(Permission::PartsWrite)?;
    let mut tx = state.ctx.db.tenant_tx(principal.tenant_id).await?;
    let cloned = store::clone_part(&mut tx, &principal, part_id, &req).await?;
    audit::append(
        &mut tx,
        &principal,
        "librarian.part.cloned",
        &format!("part:{}", cloned.id),
        serde_json::json!({ "source_part_id": part_id, "part_number": cloned.part_number }),
    )
    .await?;
    tx.commit().await?;
    state.cache.invalidate_tenant(principal.tenant_id);
    Ok((StatusCode::CREATED, Json(cloned)))
}

async fn transition_lifecycle(
    State(state): State<HttpLibState>,
    principal: Principal,
    Path(part_id): Path<Uuid>,
    Json(req): Json<LifecycleTransitionRequest>,
) -> Result<Json<LibraryPart>> {
    principal.require(Permission::PartsWrite)?;
    let mut tx = state.ctx.db.tenant_tx(principal.tenant_id).await?;
    let updated = store::transition_lifecycle(&mut tx, &principal, part_id, req.lifecycle).await?;
    audit::append(
        &mut tx,
        &principal,
        "librarian.part.lifecycle",
        &format!("part:{part_id}"),
        serde_json::json!({ "lifecycle": updated.lifecycle.as_str() }),
    )
    .await?;
    tx.commit().await?;
    state.cache.invalidate_tenant(principal.tenant_id);
    Ok(Json(updated))
}

async fn get_where_used(
    State(state): State<HttpLibState>,
    principal: Principal,
    Path(part_id): Path<Uuid>,
) -> Result<Json<Vec<WhereUsedEntry>>> {
    principal.require(Permission::PartsRead)?;
    let mut tx = state.ctx.db.tenant_tx(principal.tenant_id).await?;
    let entries = store::list_where_used(&mut tx, part_id).await?;
    tx.commit().await?;
    Ok(Json(entries))
}

async fn upsert_where_used(
    State(state): State<HttpLibState>,
    principal: Principal,
    Path(part_id): Path<Uuid>,
    Json(req): Json<UpsertWhereUsedRequest>,
) -> Result<Json<Vec<WhereUsedEntry>>> {
    principal.require(Permission::BoardsWrite)?;
    let mut tx = state.ctx.db.tenant_tx(principal.tenant_id).await?;
    let entries = store::upsert_where_used(&mut tx, &principal, part_id, &req).await?;
    audit::append(
        &mut tx,
        &principal,
        "librarian.part.where_used_updated",
        &format!("part:{part_id}"),
        serde_json::json!({ "board_id": req.board_id, "revision_tag": req.revision_tag }),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(entries))
}

async fn generate_cad(
    State(state): State<HttpLibState>,
    principal: Principal,
    Path(part_id): Path<Uuid>,
    Json(req): Json<GenerateCadRequest>,
) -> Result<Response> {
    principal.require(Permission::PartsWrite)?;
    let mut tx = state.ctx.db.tenant_tx(principal.tenant_id).await?;
    match store::generate_and_store_cad(&mut tx, &principal, part_id, &req.ipc_spec).await? {
        GateOutcome::Completed(assets) => {
            audit::append(
                &mut tx,
                &principal,
                "librarian.part.cad_generated",
                &format!("part:{part_id}"),
                serde_json::json!({ "footprint": assets.footprint_name, "symbol": assets.symbol_name }),
            )
            .await?;
            tx.commit().await?;
            state.cache.invalidate_tenant(principal.tenant_id);

            Ok(Json(GeneratedCadResponse {
                part_id,
                footprint_name: assets.footprint_name,
                symbol_name: assets.symbol_name,
                footprint_kicad_mod: assets.footprint_kicad_mod,
                symbol_kicad_sym: assets.symbol_kicad_sym,
                footprint_svg: assets.footprint_svg,
                symbol_svg: assets.symbol_svg,
            })
            .into_response())
        }
        GateOutcome::PendingApproval(request_id) => {
            tx.commit().await?;
            Ok((
                StatusCode::ACCEPTED,
                Json(serde_json::json!({
                    "status": "pending_approval",
                    "requestId": request_id,
                })),
            )
                .into_response())
        }
    }
}

async fn serve_artifact(
    state: &HttpLibState,
    principal: &Principal,
    part_id: Uuid,
    kind: ArtifactKind,
) -> Result<Response> {
    principal.require(Permission::PartsRead)?;
    let mut tx = state.ctx.db.tenant_tx(principal.tenant_id).await?;
    let artifact = store::get_artifact(&mut tx, part_id, kind).await?;
    tx.commit().await?;

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(kind.content_type()),
    );
    if matches!(kind, ArtifactKind::FootprintSvg | ArtifactKind::SymbolSvg) {
        headers.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("default-src 'none'; sandbox"),
        );
    }
    Ok((StatusCode::OK, headers, artifact.content).into_response())
}

async fn preview_footprint_svg(
    State(state): State<HttpLibState>,
    principal: Principal,
    Path(part_id): Path<Uuid>,
) -> Result<Response> {
    serve_artifact(&state, &principal, part_id, ArtifactKind::FootprintSvg).await
}

async fn preview_symbol_svg(
    State(state): State<HttpLibState>,
    principal: Principal,
    Path(part_id): Path<Uuid>,
) -> Result<Response> {
    serve_artifact(&state, &principal, part_id, ArtifactKind::SymbolSvg).await
}

async fn get_kicad_footprint(
    State(state): State<HttpLibState>,
    principal: Principal,
    Path(part_id): Path<Uuid>,
) -> Result<Response> {
    serve_artifact(&state, &principal, part_id, ArtifactKind::FootprintKicad).await
}

async fn get_kicad_symbol(
    State(state): State<HttpLibState>,
    principal: Principal,
    Path(part_id): Path<Uuid>,
) -> Result<Response> {
    serve_artifact(&state, &principal, part_id, ArtifactKind::SymbolKicad).await
}

async fn open_in_kicad(
    State(state): State<HttpLibState>,
    principal: Principal,
    Path(part_id): Path<Uuid>,
    Query(query): Query<OpenInKiCadQuery>,
) -> Result<Json<OpenInKiCadResponse>> {
    principal.require(Permission::PartsRead)?;
    let mut tx = state.ctx.db.tenant_tx(principal.tenant_id).await?;
    let _part = store::get_part(&mut tx, part_id).await?;
    let info = store::get_tenant_info(&mut tx, principal.tenant_id).await?;
    tx.commit().await?;

    let part_id_str = part_id.to_string();
    let deep_link = build_kicad_deep_link(
        &info.slug,
        &query.target,
        Some(&part_id_str),
        query.board_id.as_deref(),
        query.refdes.as_deref(),
        query.vm_id.as_deref(),
    )?;

    let kicad_http_lib_url = format!(
        "{}/v1/httplib/{}",
        state.ctx.config.api_base_url.trim_end_matches('/'),
        info.slug
    );

    Ok(Json(OpenInKiCadResponse {
        deep_link,
        target: query.target,
        tenant_slug: info.slug,
        kicad_http_lib_url,
    }))
}
