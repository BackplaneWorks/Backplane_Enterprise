//! Differences between two board revisions: BOM lines and component placement.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BomLine {
    pub mpn: String,
    #[serde(default)]
    pub manufacturer: String,
    #[serde(default)]
    pub value: String,
    #[serde(default)]
    pub footprint: String,
    pub quantity: i32,
    #[serde(default)]
    pub refdes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Component {
    pub refdes: String,
    #[serde(default)]
    pub mpn: String,
    pub x_mm: f64,
    pub y_mm: f64,
    #[serde(default)]
    pub width_mm: f64,
    #[serde(default)]
    pub height_mm: f64,
    /// `F.Cu` or `B.Cu`
    pub layer: String,
    #[serde(default)]
    pub package_name: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiffEntry {
    /// `added` | `removed` | `changed`
    pub kind: &'static str,
    /// `BOM` | `PCB`
    pub scope: &'static str,
    pub target: String,
    pub detail: String,
}

fn entry(kind: &'static str, scope: &'static str, target: &str, detail: String) -> DiffEntry {
    DiffEntry { kind, scope, target: target.to_string(), detail }
}

/// BOM changes by manufacturer part number, then placement changes by
/// reference designator. Deterministic order (sorted by target).
pub fn diff(old_bom: &[BomLine], new_bom: &[BomLine], old_parts: &[Component], new_parts: &[Component]) -> Vec<DiffEntry> {
    let mut out = Vec::new();

    let by_mpn = |lines: &[BomLine]| {
        let mut m: BTreeMap<String, i64> = BTreeMap::new();
        for l in lines {
            *m.entry(l.mpn.clone()).or_default() += l.quantity as i64;
        }
        m
    };
    let (old, new) = (by_mpn(old_bom), by_mpn(new_bom));
    for (mpn, qty) in &new {
        match old.get(mpn) {
            None => out.push(entry("added", "BOM", mpn, format!("new part, quantity {qty}"))),
            Some(before) if before != qty => out.push(entry("changed", "BOM", mpn, format!("quantity {before} -> {qty}"))),
            _ => {}
        }
    }
    for (mpn, qty) in &old {
        if !new.contains_key(mpn) {
            out.push(entry("removed", "BOM", mpn, format!("no longer used (was {qty})")));
        }
    }

    let by_ref = |parts: &[Component]| parts.iter().map(|c| (c.refdes.clone(), c.clone())).collect::<BTreeMap<_, _>>();
    let (old, new) = (by_ref(old_parts), by_ref(new_parts));
    for (refdes, c) in &new {
        match old.get(refdes) {
            None => out.push(entry("added", "PCB", refdes, format!("{} placed at ({:.2}, {:.2}) mm on {}", c.mpn, c.x_mm, c.y_mm, c.layer))),
            Some(b) => {
                let mut changes = Vec::new();
                if b.mpn != c.mpn {
                    changes.push(format!("part {} -> {}", b.mpn, c.mpn));
                }
                if b.layer != c.layer {
                    changes.push(format!("side {} -> {}", b.layer, c.layer));
                }
                if (b.x_mm - c.x_mm).abs() > 0.005 || (b.y_mm - c.y_mm).abs() > 0.005 {
                    changes.push(format!("moved ({:.2}, {:.2}) -> ({:.2}, {:.2}) mm", b.x_mm, b.y_mm, c.x_mm, c.y_mm));
                }
                if b.package_name != c.package_name {
                    changes.push(format!("package {} -> {}", b.package_name, c.package_name));
                }
                if !changes.is_empty() {
                    out.push(entry("changed", "PCB", refdes, changes.join("; ")));
                }
            }
        }
    }
    for refdes in old.keys() {
        if !new.contains_key(refdes) {
            out.push(entry("removed", "PCB", refdes, "component removed".into()));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(mpn: &str, q: i32) -> BomLine {
        BomLine { mpn: mpn.into(), manufacturer: String::new(), value: String::new(), footprint: String::new(), quantity: q, refdes: vec![] }
    }

    fn part(r: &str, mpn: &str, x: f64, layer: &str) -> Component {
        Component { refdes: r.into(), mpn: mpn.into(), x_mm: x, y_mm: 1.0, width_mm: 1.0, height_mm: 1.0, layer: layer.into(), package_name: "0402".into() }
    }

    #[test]
    fn bom_and_placement_changes() {
        let d = diff(
            &[line("RC0402-10K", 4), line("STM32F103", 1), line("OLD-LDO", 1)],
            &[line("RC0402-10K", 6), line("STM32F103", 1), line("NEW-LDO", 1)],
            &[part("R1", "RC0402-10K", 1.0, "F.Cu"), part("U1", "STM32F103", 5.0, "F.Cu"), part("U2", "OLD-LDO", 9.0, "F.Cu")],
            &[part("R1", "RC0402-10K", 2.5, "B.Cu"), part("U1", "STM32F103", 5.0, "F.Cu"), part("U3", "NEW-LDO", 9.0, "F.Cu")],
        );
        let find = |scope: &str, target: &str| d.iter().find(|e| e.scope == scope && e.target == target).unwrap_or_else(|| panic!("{scope} {target}"));
        assert_eq!((find("BOM", "RC0402-10K").kind, find("BOM", "RC0402-10K").detail.as_str()), ("changed", "quantity 4 -> 6"));
        assert_eq!(find("BOM", "NEW-LDO").kind, "added");
        assert_eq!(find("BOM", "OLD-LDO").kind, "removed");
        assert!(find("PCB", "R1").detail.contains("side F.Cu -> B.Cu") && find("PCB", "R1").detail.contains("moved"));
        assert_eq!(find("PCB", "U3").kind, "added");
        assert_eq!(find("PCB", "U2").kind, "removed");
        assert!(!d.iter().any(|e| e.target == "U1" || e.target == "STM32F103"), "unchanged items are not listed");
    }

    #[test]
    fn identical_revisions_have_no_diff_and_split_lines_are_summed() {
        let bom = [line("A", 2), line("A", 3)];
        assert!(diff(&bom, &[line("A", 5)], &[], &[]).is_empty());
        assert!(diff(&[], &[], &[part("R1", "A", 1.0, "F.Cu")], &[part("R1", "A", 1.004, "F.Cu")]).is_empty(), "sub-0.005 mm jitter is not a move");
    }
}
