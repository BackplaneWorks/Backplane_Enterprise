//! KiCad `kicad_httplib` v1 JSON protocol routes (`/v1/httplib/{tenant}/*`).

use crate::kicad_protocol::{build_kicad_httplib_config, KiCadRootEndpoints};
use crate::model::{
    ArtifactKind, CreateTokenResponse, HttpLibQuery, HttpLibTokenSummary, MintTokenRequest,
};
use crate::routes::HttpLibState;
use crate::store;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get};
use axum::{Json, Router};
use bp_ent_core::{audit, AuthKind, Error, Permission, Principal, Result};
use uuid::Uuid;

pub fn router() -> Router<HttpLibState> {
    Router::new()
        .route("/{tenant}", get(root_endpoints))
        .route("/{tenant}/", get(root_endpoints))
        .route("/{tenant}/v1/", get(root_endpoints))
        .route("/{tenant}/categories.json", get(get_categories))
        .route("/{tenant}/v1/categories.json", get(get_categories))
        .route(
            "/{tenant}/parts/category/{category_id_json}",
            get(get_parts_by_category),
        )
        .route(
            "/{tenant}/v1/parts/category/{category_id_json}",
            get(get_parts_by_category),
        )
        .route("/{tenant}/parts/{part_id_json}", get(get_part_detail))
        .route("/{tenant}/v1/parts/{part_id_json}", get(get_part_detail))
        .route("/{tenant}/artifacts/{part_id}/{kind}", get(get_artifact))
        .route(
            "/{tenant}/tokens",
            get(list_device_tokens).post(mint_device_token),
        )
        .route("/{tenant}/tokens/{token_id}", delete(revoke_device_token))
        .route("/{tenant}/config.kicad_httplib", get(download_config))
}

fn resolve_include_draft(principal: &Principal, q: &HttpLibQuery) -> Result<bool> {
    match q.include.as_deref().map(str::trim) {
        None | Some("") => Ok(false),
        Some("draft") => {
            if principal.auth == AuthKind::DeviceToken || !principal.can(Permission::PartsWrite) {
                return Err(Error::Forbidden);
            }
            Ok(true)
        }
        Some(_) => Err(Error::invalid(
            "unsupported include parameter; expected 'draft'",
        )),
    }
}

fn parse_json_uuid(raw: &str) -> Result<Uuid> {
    let trimmed = raw.strip_suffix(".json").unwrap_or(raw);
    Uuid::parse_str(trimmed).map_err(|_| Error::NotFound)
}

fn json_string_response(body: String) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    (StatusCode::OK, headers, body).into_response()
}

async fn root_endpoints(
    State(state): State<HttpLibState>,
    principal: Principal,
    Path(tenant): Path<String>,
) -> Result<Json<KiCadRootEndpoints>> {
    principal.require(Permission::PartsRead)?;
    let mut tx = state.ctx.db.tenant_tx(principal.tenant_id).await?;
    let _info = store::resolve_and_verify_tenant_path(&mut tx, &principal, &tenant).await?;
    tx.commit().await?;

    Ok(Json(KiCadRootEndpoints {
        categories: "categories.json".to_string(),
        parts: "parts".to_string(),
    }))
}

async fn get_categories(
    State(state): State<HttpLibState>,
    principal: Principal,
    Path(tenant): Path<String>,
) -> Result<Response> {
    principal.require(Permission::PartsRead)?;
    let mut tx = state.ctx.db.tenant_tx(principal.tenant_id).await?;
    let _info = store::resolve_and_verify_tenant_path(&mut tx, &principal, &tenant).await?;

    if let Some(cached) = state.cache.get(principal.tenant_id, "httplib_categories", "all") {
        tx.commit().await?;
        return Ok(json_string_response(cached));
    }

    let cats = store::list_kicad_categories(&mut tx).await?;
    tx.commit().await?;

    let json = serde_json::to_string(&cats).map_err(Error::internal)?;
    state
        .cache
        .put(principal.tenant_id, "httplib_categories", "all", json.clone());
    Ok(json_string_response(json))
}

async fn get_parts_by_category(
    State(state): State<HttpLibState>,
    principal: Principal,
    Path((tenant, category_id_json)): Path<(String, String)>,
    Query(query): Query<HttpLibQuery>,
) -> Result<Response> {
    principal.require(Permission::PartsRead)?;
    let include_draft = resolve_include_draft(&principal, &query)?;
    let category_id = parse_json_uuid(&category_id_json)?;
    let mut tx = state.ctx.db.tenant_tx(principal.tenant_id).await?;
    let _info = store::resolve_and_verify_tenant_path(&mut tx, &principal, &tenant).await?;

    let tier = if include_draft { "draft" } else { "released" };
    let cache_item = format!("{category_id}:{tier}");
    if let Some(cached) = state
        .cache
        .get(principal.tenant_id, "httplib_category_parts", &cache_item)
    {
        tx.commit().await?;
        return Ok(json_string_response(cached));
    }

    let summaries =
        store::list_kicad_parts_in_category(&mut tx, category_id, include_draft).await?;
    tx.commit().await?;

    let json = serde_json::to_string(&summaries).map_err(Error::internal)?;
    state.cache.put(
        principal.tenant_id,
        "httplib_category_parts",
        &cache_item,
        json.clone(),
    );
    Ok(json_string_response(json))
}

async fn get_part_detail(
    State(state): State<HttpLibState>,
    principal: Principal,
    Path((tenant, part_id_json)): Path<(String, String)>,
    Query(query): Query<HttpLibQuery>,
) -> Result<Response> {
    principal.require(Permission::PartsRead)?;
    let include_draft = resolve_include_draft(&principal, &query)?;
    let part_id = parse_json_uuid(&part_id_json)?;
    let mut tx = state.ctx.db.tenant_tx(principal.tenant_id).await?;
    let _info = store::resolve_and_verify_tenant_path(&mut tx, &principal, &tenant).await?;

    let tier = if include_draft { "draft" } else { "released" };
    let cache_item = format!("{part_id}:{tier}");
    if let Some(cached) = state
        .cache
        .get(principal.tenant_id, "httplib_part", &cache_item)
    {
        tx.commit().await?;
        return Ok(json_string_response(cached));
    }

    let detail = store::get_kicad_part_detail(&mut tx, part_id, include_draft).await?;
    tx.commit().await?;

    let json = serde_json::to_string(&detail).map_err(Error::internal)?;
    state
        .cache
        .put(principal.tenant_id, "httplib_part", &cache_item, json.clone());
    Ok(json_string_response(json))
}

async fn get_artifact(
    State(state): State<HttpLibState>,
    principal: Principal,
    Path((tenant, part_id, kind_raw)): Path<(String, Uuid, String)>,
    Query(query): Query<HttpLibQuery>,
) -> Result<Response> {
    principal.require(Permission::PartsRead)?;
    let include_draft = resolve_include_draft(&principal, &query)?;
    let kind = ArtifactKind::parse(&kind_raw)?;
    let mut tx = state.ctx.db.tenant_tx(principal.tenant_id).await?;
    let _info = store::resolve_and_verify_tenant_path(&mut tx, &principal, &tenant).await?;
    let artifact = store::get_kicad_artifact(&mut tx, part_id, kind, include_draft).await?;
    tx.commit().await?;

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(kind.content_type()),
    );
    if matches!(kind, ArtifactKind::SymbolSvg | ArtifactKind::FootprintSvg) {
        headers.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("default-src 'none'; sandbox"),
        );
    }
    Ok((StatusCode::OK, headers, artifact.content).into_response())
}

async fn list_device_tokens(
    State(state): State<HttpLibState>,
    principal: Principal,
    Path(tenant): Path<String>,
) -> Result<Json<Vec<HttpLibTokenSummary>>> {
    if principal.auth == AuthKind::DeviceToken {
        return Err(Error::Forbidden);
    }
    principal.require(Permission::PartsRead)?;

    let mut tx = state.ctx.db.tenant_tx(principal.tenant_id).await?;
    let _info = store::resolve_and_verify_tenant_path(&mut tx, &principal, &tenant).await?;
    let tokens = store::list_httplib_device_tokens(&mut tx, &principal).await?;
    tx.commit().await?;
    Ok(Json(tokens))
}

async fn mint_device_token(
    State(state): State<HttpLibState>,
    principal: Principal,
    Path(tenant): Path<String>,
    Json(req): Json<MintTokenRequest>,
) -> Result<(StatusCode, Json<CreateTokenResponse>)> {
    // Device tokens cannot mint new tokens.
    if principal.auth == AuthKind::DeviceToken {
        return Err(Error::Forbidden);
    }
    principal.require(Permission::PartsRead)?;

    let mut tx = state.ctx.db.tenant_tx(principal.tenant_id).await?;
    let _info = store::resolve_and_verify_tenant_path(&mut tx, &principal, &tenant).await?;
    let resp = store::mint_httplib_device_token(&mut tx, &principal, &req.label).await?;
    audit::append(
        &mut tx,
        &principal,
        "httplib.token.minted",
        &format!("token:{}", resp.token_id),
        serde_json::json!({ "scope": Permission::PartsRead.scope(), "prefix": resp.token_prefix }),
    )
    .await?;
    tx.commit().await?;

    Ok((StatusCode::CREATED, Json(resp)))
}

async fn revoke_device_token(
    State(state): State<HttpLibState>,
    principal: Principal,
    Path((tenant, token_id)): Path<(String, Uuid)>,
) -> Result<StatusCode> {
    if principal.auth == AuthKind::DeviceToken {
        return Err(Error::Forbidden);
    }
    principal.require(Permission::PartsRead)?;

    let mut tx = state.ctx.db.tenant_tx(principal.tenant_id).await?;
    let _info = store::resolve_and_verify_tenant_path(&mut tx, &principal, &tenant).await?;
    store::revoke_httplib_device_token(&mut tx, &principal, token_id).await?;
    audit::append(
        &mut tx,
        &principal,
        "httplib.token.revoked",
        &format!("token:{token_id}"),
        serde_json::json!({}),
    )
    .await?;
    tx.commit().await?;

    Ok(StatusCode::NO_CONTENT)
}

async fn download_config(
    State(state): State<HttpLibState>,
    principal: Principal,
    Path(tenant): Path<String>,
) -> Result<Response> {
    principal.require(Permission::PartsRead)?;
    let mut tx = state.ctx.db.tenant_tx(principal.tenant_id).await?;
    let info = store::resolve_and_verify_tenant_path(&mut tx, &principal, &tenant).await?;
    tx.commit().await?;

    let cfg = build_kicad_httplib_config(
        &info.name,
        &info.slug,
        &state.ctx.config.api_base_url,
        "<PASTE_OR_MINT_SCOPED_TOKEN>",
    );
    let body = serde_json::to_string_pretty(&cfg).map_err(Error::internal)?;

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    let disp = format!("attachment; filename=\"{}.kicad_httplib\"", info.slug);
    if let Ok(v) = HeaderValue::from_str(&disp) {
        headers.insert(header::CONTENT_DISPOSITION, v);
    }
    Ok((StatusCode::OK, headers, body).into_response())
}
