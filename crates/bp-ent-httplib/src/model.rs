//! Domain models, lifecycle state machine, and API DTOs for the Private
//! KiCad HTTP Library and Web Librarian.

use bp_ent_core::{Error, Permission, Principal, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

/// Part approval lifecycle (`Draft -> In Review -> Released -> Obsolete`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PartLifecycle {
    Draft,
    #[serde(rename = "In Review")]
    InReview,
    Released,
    Obsolete,
}

impl PartLifecycle {
    pub fn as_str(&self) -> &'static str {
        match self {
            PartLifecycle::Draft => "Draft",
            PartLifecycle::InReview => "In Review",
            PartLifecycle::Released => "Released",
            PartLifecycle::Obsolete => "Obsolete",
        }
    }

    pub fn parse(raw: &str) -> Result<Self> {
        match raw {
            "Draft" => Ok(PartLifecycle::Draft),
            "In Review" => Ok(PartLifecycle::InReview),
            "Released" => Ok(PartLifecycle::Released),
            "Obsolete" => Ok(PartLifecycle::Obsolete),
            _ => Err(Error::invalid("unknown part lifecycle state")),
        }
    }

    /// Enforce valid lifecycle state transitions and RBAC permissions.
    pub fn validate_transition(from: Self, to: Self, principal: &Principal) -> Result<()> {
        if from == to {
            return Err(Error::conflict("part is already in that lifecycle state"));
        }
        if from == PartLifecycle::Obsolete {
            return Err(Error::conflict(
                "obsolete parts cannot be reactivated; clone into a new Draft part",
            ));
        }

        match (from, to) {
            (PartLifecycle::Draft, PartLifecycle::InReview)
            | (PartLifecycle::InReview, PartLifecycle::Draft) => {
                principal.require(Permission::PartsWrite)
            }
            (PartLifecycle::Draft, PartLifecycle::Released)
            | (PartLifecycle::InReview, PartLifecycle::Released)
            | (PartLifecycle::Draft, PartLifecycle::Obsolete)
            | (PartLifecycle::InReview, PartLifecycle::Obsolete)
            | (PartLifecycle::Released, PartLifecycle::Obsolete) => {
                principal.require(Permission::PartsRelease)
            }
            (PartLifecycle::Released, PartLifecycle::Draft)
            | (PartLifecycle::Released, PartLifecycle::InReview) => Err(Error::conflict(
                "released parts cannot revert to Draft/In Review; clone or mark Obsolete",
            )),
            _ => Err(Error::invalid("invalid lifecycle transition")),
        }
    }
}

/// Supported parametric IPC-7351 package families (aligned with `web/src/types/domain.ts`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum IpcPackageFamily {
    SOIC,
    QFN,
    LQFP,
    CHIP,
    BGA,
}

/// Parametric dimensions used to synthesize IPC-7351 footprints, KiCad symbols, and SVGs.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ipc7351Spec {
    pub family: IpcPackageFamily,
    pub pin_count: u32,
    pub pitch_mm: f64,
    pub body_width_mm: f64,
    pub body_length_mm: f64,
    pub pad_width_mm: f64,
    pub pad_length_mm: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thermal_pad_mm: Option<f64>,
}

impl Ipc7351Spec {
    pub fn validate(&self) -> Result<()> {
        if self.pin_count < 2 || self.pin_count > 1024 {
            return Err(Error::invalid("pinCount must be between 2 and 1024"));
        }
        for (name, val, min, max) in [
            ("pitchMm", self.pitch_mm, 0.2, 10.0),
            ("bodyWidthMm", self.body_width_mm, 0.4, 200.0),
            ("bodyLengthMm", self.body_length_mm, 0.4, 200.0),
            ("padWidthMm", self.pad_width_mm, 0.1, 20.0),
            ("padLengthMm", self.pad_length_mm, 0.1, 20.0),
        ] {
            if !val.is_finite() || val < min || val > max {
                return Err(Error::invalid(format!(
                    "{name} must be finite and between {min} and {max} mm"
                )));
            }
        }
        if let Some(ep) = self.thermal_pad_mm {
            if !ep.is_finite() || ep <= 0.0 || ep >= self.body_width_mm.min(self.body_length_mm) {
                return Err(Error::invalid(
                    "thermalPadMm must be positive and smaller than body dimensions",
                ));
            }
        }
        Ok(())
    }
}

/// Where-Used board reference for impact analysis before part changes/obsolescence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WhereUsedEntry {
    pub board_id: String,
    pub board_name: String,
    pub revision_tag: String,
    pub refdes_list: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LibraryCategory {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub created_at: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LibraryPart {
    pub id: Uuid,
    pub part_number: String,
    pub mpn: String,
    pub manufacturer: String,
    pub category: String,
    pub category_id: Uuid,
    pub value: String,
    pub package_name: String,
    pub lifecycle: PartLifecycle,
    pub preferred_by_fab: bool,
    pub fab_stock_qty: i32,
    pub unit_price_usd: f64,
    pub datasheet_url: String,
    pub description: String,
    pub symbol_ref: String,
    pub footprint_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_3d_key: Option<String>,
    pub exclude_from_bom: bool,
    pub exclude_from_board: bool,
    pub attributes: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipc_spec: Option<Ipc7351Spec>,
    pub where_used: Vec<WhereUsedEntry>,
    pub updated_at: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    SymbolKicad,
    FootprintKicad,
    SymbolSvg,
    FootprintSvg,
    Model3dRef,
}

impl ArtifactKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ArtifactKind::SymbolKicad => "symbol_kicad",
            ArtifactKind::FootprintKicad => "footprint_kicad",
            ArtifactKind::SymbolSvg => "symbol_svg",
            ArtifactKind::FootprintSvg => "footprint_svg",
            ArtifactKind::Model3dRef => "model_3d_ref",
        }
    }

    pub fn parse(raw: &str) -> Result<Self> {
        match raw {
            "symbol_kicad" => Ok(ArtifactKind::SymbolKicad),
            "footprint_kicad" => Ok(ArtifactKind::FootprintKicad),
            "symbol_svg" => Ok(ArtifactKind::SymbolSvg),
            "footprint_svg" => Ok(ArtifactKind::FootprintSvg),
            "model_3d_ref" => Ok(ArtifactKind::Model3dRef),
            _ => Err(Error::NotFound),
        }
    }

    pub fn content_type(&self) -> &'static str {
        match self {
            ArtifactKind::SymbolKicad | ArtifactKind::FootprintKicad => "text/plain; charset=utf-8",
            ArtifactKind::SymbolSvg | ArtifactKind::FootprintSvg => "image/svg+xml; charset=utf-8",
            ArtifactKind::Model3dRef => "application/json",
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateCategoryRequest {
    pub name: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatePartRequest {
    pub part_number: String,
    pub mpn: String,
    pub manufacturer: String,
    pub category: String,
    #[serde(default)]
    pub value: String,
    #[serde(default)]
    pub package_name: String,
    #[serde(default)]
    pub preferred_by_fab: bool,
    #[serde(default)]
    pub fab_stock_qty: i32,
    #[serde(default)]
    pub unit_price_usd: f64,
    #[serde(default)]
    pub datasheet_url: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub symbol_ref: String,
    #[serde(default)]
    pub footprint_ref: String,
    #[serde(default)]
    pub model_3d_key: Option<String>,
    #[serde(default)]
    pub exclude_from_bom: bool,
    #[serde(default)]
    pub exclude_from_board: bool,
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
    #[serde(default)]
    pub ipc_spec: Option<Ipc7351Spec>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdatePartRequest {
    pub mpn: Option<String>,
    pub manufacturer: Option<String>,
    pub category: Option<String>,
    pub value: Option<String>,
    pub package_name: Option<String>,
    pub preferred_by_fab: Option<bool>,
    pub fab_stock_qty: Option<i32>,
    pub unit_price_usd: Option<f64>,
    pub datasheet_url: Option<String>,
    pub description: Option<String>,
    pub symbol_ref: Option<String>,
    pub footprint_ref: Option<String>,
    pub model_3d_key: Option<Option<String>>,
    pub exclude_from_bom: Option<bool>,
    pub exclude_from_board: Option<bool>,
    pub attributes: Option<BTreeMap<String, String>>,
    pub ipc_spec: Option<Option<Ipc7351Spec>>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClonePartRequest {
    pub part_number: String,
    #[serde(default)]
    pub mpn: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleTransitionRequest {
    pub lifecycle: PartLifecycle,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpsertWhereUsedRequest {
    pub board_id: String,
    pub board_name: String,
    pub revision_tag: String,
    pub refdes_list: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateCadRequest {
    pub ipc_spec: Ipc7351Spec,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GeneratedCadResponse {
    pub part_id: Uuid,
    pub footprint_name: String,
    pub symbol_name: String,
    pub footprint_kicad_mod: String,
    pub symbol_kicad_sym: String,
    pub footprint_svg: String,
    pub symbol_svg: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MintTokenRequest {
    #[serde(default = "default_token_label")]
    pub label: String,
}

fn default_token_label() -> String {
    "kicad-workstation".to_string()
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateTokenResponse {
    pub token_id: Uuid,
    /// Shown once at creation time; stored only as SHA-256 on the server.
    pub token: String,
    pub token_prefix: String,
    pub expires_at: String,
}

impl std::fmt::Debug for CreateTokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateTokenResponse")
            .field("token_id", &self.token_id)
            .field("token", &"[redacted]")
            .field("token_prefix", &self.token_prefix)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpLibTokenSummary {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub scopes: Vec<String>,
    pub created_at: String,
    pub expires_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpLibQuery {
    pub include: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenInKiCadResponse {
    pub deep_link: String,
    pub target: String,
    pub tenant_slug: String,
    pub kicad_http_lib_url: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListPartsQuery {
    pub q: Option<String>,
    pub lifecycle: Option<String>,
    pub category: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenInKiCadQuery {
    #[serde(default = "default_open_target")]
    pub target: String,
    pub board_id: Option<String>,
    pub refdes: Option<String>,
    pub vm_id: Option<String>,
}

fn default_open_target() -> String {
    "local".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bp_ent_core::{rbac::Scopes, AuthKind, Role, TenantId, UserId};

    fn make_principal(role: Role) -> Principal {
        Principal {
            tenant_id: TenantId::new(),
            user_id: UserId::new(),
            role,
            email: "test@example.com".into(),
            auth: AuthKind::Session,
            scopes: Scopes::All,
            token_id: Uuid::new_v4(),
        }
    }

    #[test]
    fn lifecycle_transitions_enforce_state_machine_and_rbac() {
        let engineer = make_principal(Role::Engineer);
        let librarian = make_principal(Role::Librarian);
        let purchasing = make_principal(Role::Purchasing);

        // Engineer can submit Draft -> In Review, but cannot Release or Obsolete.
        assert!(PartLifecycle::validate_transition(
            PartLifecycle::Draft,
            PartLifecycle::InReview,
            &engineer
        )
        .is_ok());
        assert!(PartLifecycle::validate_transition(
            PartLifecycle::InReview,
            PartLifecycle::Released,
            &engineer
        )
        .is_err());

        // Purchasing cannot mutate parts at all.
        assert!(PartLifecycle::validate_transition(
            PartLifecycle::Draft,
            PartLifecycle::InReview,
            &purchasing
        )
        .is_err());

        // Librarian can Release and Obsolete, but cannot resurrect Obsolete or revert Released.
        assert!(PartLifecycle::validate_transition(
            PartLifecycle::InReview,
            PartLifecycle::Released,
            &librarian
        )
        .is_ok());
        assert!(PartLifecycle::validate_transition(
            PartLifecycle::Released,
            PartLifecycle::Obsolete,
            &librarian
        )
        .is_ok());
        assert!(PartLifecycle::validate_transition(
            PartLifecycle::Obsolete,
            PartLifecycle::Draft,
            &librarian
        )
        .is_err());
        assert!(PartLifecycle::validate_transition(
            PartLifecycle::Released,
            PartLifecycle::Draft,
            &librarian
        )
        .is_err());
    }

    #[test]
    fn token_response_debug_redacts_secret() {
        let resp = CreateTokenResponse {
            token_id: Uuid::new_v4(),
            token: "bpe_d_0000_supersecretvalue".into(),
            token_prefix: "bpe_d_0000".into(),
            expires_at: "2027-01-01T00:00:00Z".into(),
        };
        let dbg = format!("{resp:?}");
        assert!(!dbg.contains("supersecretvalue"));
        assert!(dbg.contains("[redacted]"));
    }
}
