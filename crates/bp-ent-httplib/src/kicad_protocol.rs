//! KiCad `kicad_httplib` v1 JSON protocol types and `.kicad_httplib` config generator.

use crate::model::LibraryPart;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;

/// Returned by `GET /v1/httplib/{tenant}/` (or `/v1/`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KiCadRootEndpoints {
    pub categories: String,
    pub parts: String,
}

/// Returned in array by `GET /v1/httplib/{tenant}/categories.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KiCadCategory {
    pub id: String,
    pub name: String,
    pub description: String,
}

/// Returned in array by `GET /v1/httplib/{tenant}/parts/category/{id}.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KiCadPartSummary {
    pub id: String,
    pub name: String,
    pub description: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KiCadField {
    pub value: String,
    pub visible: String,
}

/// Returned by `GET /v1/httplib/{tenant}/parts/{id}.json` per KiCad HTTP Library v1 spec.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KiCadPartDetail {
    pub id: String,
    pub name: String,
    pub symbol_id_str: String,
    #[serde(rename = "exclude_from_bom")]
    pub exclude_from_bom: String,
    #[serde(rename = "exclude_from_board")]
    pub exclude_from_board: String,
    #[serde(rename = "exclude_from_sim")]
    pub exclude_from_sim: String,
    pub fields: BTreeMap<String, KiCadField>,
}

fn kicad_bool(b: bool) -> String {
    if b {
        "True".to_string()
    } else {
        "False".to_string()
    }
}

pub fn part_to_kicad_detail(part: &LibraryPart) -> KiCadPartDetail {
    let mut fields = BTreeMap::new();
    let footprint = if part.footprint_ref.is_empty() {
        format!("Backplane_Enterprise:{}", part.package_name)
    } else {
        part.footprint_ref.clone()
    };
    let symbol = if part.symbol_ref.is_empty() {
        format!("Backplane_Enterprise:{}", part.mpn)
    } else {
        part.symbol_ref.clone()
    };

    fields.insert(
        "Value".to_string(),
        KiCadField {
            value: if part.value.is_empty() {
                part.mpn.clone()
            } else {
                part.value.clone()
            },
            visible: "True".to_string(),
        },
    );
    fields.insert(
        "Footprint".to_string(),
        KiCadField {
            value: footprint,
            visible: "False".to_string(),
        },
    );
    fields.insert(
        "Datasheet".to_string(),
        KiCadField {
            value: part.datasheet_url.clone(),
            visible: "False".to_string(),
        },
    );
    fields.insert(
        "MPN".to_string(),
        KiCadField {
            value: part.mpn.clone(),
            visible: "False".to_string(),
        },
    );
    fields.insert(
        "Manufacturer".to_string(),
        KiCadField {
            value: part.manufacturer.clone(),
            visible: "False".to_string(),
        },
    );
    fields.insert(
        "Internal_PN".to_string(),
        KiCadField {
            value: part.part_number.clone(),
            visible: "False".to_string(),
        },
    );
    fields.insert(
        "Lifecycle".to_string(),
        KiCadField {
            value: part.lifecycle.as_str().to_string(),
            visible: "False".to_string(),
        },
    );
    fields.insert(
        "Preferred_By_Fab".to_string(),
        KiCadField {
            value: kicad_bool(part.preferred_by_fab),
            visible: "False".to_string(),
        },
    );
    fields.insert(
        "Fab_Stock".to_string(),
        KiCadField {
            value: part.fab_stock_qty.to_string(),
            visible: "False".to_string(),
        },
    );

    for (k, v) in &part.attributes {
        fields.entry(k.clone()).or_insert_with(|| KiCadField {
            value: v.clone(),
            visible: "False".to_string(),
        });
    }

    KiCadPartDetail {
        id: part.id.to_string(),
        name: part.part_number.clone(),
        symbol_id_str: symbol,
        exclude_from_bom: kicad_bool(part.exclude_from_bom),
        exclude_from_board: kicad_bool(part.exclude_from_board),
        exclude_from_sim: "False".to_string(),
        fields,
    }
}

/// Generates a ready-to-import `<org>.kicad_httplib` JSON document.
pub fn build_kicad_httplib_config(
    org_name: &str,
    tenant_slug: &str,
    api_base_url: &str,
    token: &str,
) -> serde_json::Value {
    let clean_base = api_base_url.trim_end_matches('/');
    json!({
        "meta": {
            "version": 1.0
        },
        "name": format!("{org_name} Private Library"),
        "description": format!("Backplane Enterprise tenant-isolated KiCad HTTP Library ({tenant_slug})"),
        "source": {
            "type": "REST_API",
            "api_version": "v1",
            "root_url": format!("{clean_base}/v1/httplib/{tenant_slug}"),
            "token": token,
            "timeout_ms": 8000
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::PartLifecycle;
    use uuid::Uuid;

    #[test]
    fn part_maps_to_kicad_httplib_v1_detail() {
        let mut attrs = BTreeMap::new();
        attrs.insert("Core".into(), "Cortex-M33".into());
        let part = LibraryPart {
            id: Uuid::new_v4(),
            part_number: "BP-MCU-0001".into(),
            mpn: "RP2350A".into(),
            manufacturer: "Raspberry Pi".into(),
            category: "Microcontrollers".into(),
            category_id: Uuid::new_v4(),
            value: "Dual M33".into(),
            package_name: "QFN-60".into(),
            lifecycle: PartLifecycle::Released,
            preferred_by_fab: true,
            fab_stock_qty: 4200,
            unit_price_usd: 0.85,
            datasheet_url: "https://datasheets.raspberrypi.com/rp2350/rp2350-datasheet.pdf".into(),
            description: "Dual-core MCU".into(),
            symbol_ref: "Backplane_Enterprise:RP2350A".into(),
            footprint_ref: "Backplane_Enterprise:QFN-60".into(),
            model_3d_key: None,
            exclude_from_bom: false,
            exclude_from_board: false,
            attributes: attrs,
            ipc_spec: None,
            where_used: vec![],
            updated_at: "2026-11-23T00:00:00Z".into(),
        };

        let detail = part_to_kicad_detail(&part);
        assert_eq!(detail.name, "BP-MCU-0001");
        assert_eq!(detail.symbol_id_str, "Backplane_Enterprise:RP2350A");
        assert_eq!(detail.exclude_from_bom, "False");
        assert_eq!(detail.fields["MPN"].value, "RP2350A");
        assert_eq!(detail.fields["Value"].visible, "True");
        assert_eq!(detail.fields["Core"].value, "Cortex-M33");
    }

    #[test]
    fn builds_kicad_httplib_config_matching_spec() {
        let cfg = build_kicad_httplib_config(
            "Acme Robotics",
            "acme-robotics",
            "https://enterprise.backplane.dev/",
            "bpe_d_1234_secret",
        );
        assert_eq!(cfg["source"]["type"], "REST_API");
        assert_eq!(cfg["source"]["api_version"], "v1");
        assert_eq!(
            cfg["source"]["root_url"],
            "https://enterprise.backplane.dev/v1/httplib/acme-robotics"
        );
        assert_eq!(cfg["source"]["token"], "bpe_d_1234_secret");
    }
}
