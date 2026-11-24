//! Parametric IPC-7351 footprint, KiCad `.kicad_mod` / `.kicad_sym`, and safe SVG generator.

use crate::model::{Ipc7351Spec, IpcPackageFamily};
use bp_ent_core::Result;
use serde::Serialize;
use std::fmt::Write as _;

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PadGeometry {
    pub pin: String,
    pub x_mm: f64,
    pub y_mm: f64,
    pub width_mm: f64,
    pub height_mm: f64,
    pub shape: &'static str,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FootprintGeometry {
    pub name: String,
    pub pads: Vec<PadGeometry>,
    pub body_width_mm: f64,
    pub body_length_mm: f64,
    pub courtyard_width_mm: f64,
    pub courtyard_length_mm: f64,
    pub pin1_marker_x_mm: f64,
    pub pin1_marker_y_mm: f64,
    pub view_box_width_mm: f64,
    pub view_box_height_mm: f64,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SymbolPin {
    pub number: u32,
    pub name: String,
    pub side: &'static str,
    pub x: f64,
    pub y: f64,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SymbolGeometry {
    pub width: f64,
    pub height: f64,
    pub pins: Vec<SymbolPin>,
}

#[derive(Clone, Debug)]
pub struct GeneratedCadAssets {
    pub footprint_name: String,
    pub symbol_name: String,
    pub footprint_kicad_mod: String,
    pub symbol_kicad_sym: String,
    pub footprint_svg: String,
    pub symbol_svg: String,
}

fn round3(v: f64) -> f64 {
    (v * 1000.0).round() / 1000.0
}

fn escape_xml(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

fn escape_sexpr(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' | '\r' => out.push(' '),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

fn sanitize_identifier(input: &str, fallback: &str) -> String {
    let cleaned: String = input
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() {
        fallback.to_string()
    } else {
        cleaned
    }
}

pub fn generate_footprint_geometry(spec: &Ipc7351Spec) -> Result<FootprintGeometry> {
    spec.validate()?;

    let mut pads = Vec::new();
    let pin_count = spec.pin_count.max(2);
    let pitch = spec.pitch_mm.max(0.25);
    let body_w = spec.body_width_mm.max(0.6);
    let body_l = spec.body_length_mm.max(0.6);
    let pad_w = spec.pad_width_mm.max(0.15);
    let pad_l = spec.pad_length_mm.max(0.15);

    match spec.family {
        IpcPackageFamily::CHIP => {
            let span = body_l * 0.45;
            pads.push(PadGeometry {
                pin: "1".into(),
                x_mm: round3(-span),
                y_mm: 0.0,
                width_mm: round3(pad_w),
                height_mm: round3(pad_l),
                shape: "roundrect",
            });
            pads.push(PadGeometry {
                pin: "2".into(),
                x_mm: round3(span),
                y_mm: 0.0,
                width_mm: round3(pad_w),
                height_mm: round3(pad_l),
                shape: "roundrect",
            });
        }
        IpcPackageFamily::SOIC => {
            let per_side = (pin_count / 2).max(1);
            let span_y = ((per_side - 1) as f64 * pitch) / 2.0;
            let x_offset = body_w / 2.0 + pad_l * 0.45;
            for i in 0..per_side {
                pads.push(PadGeometry {
                    pin: (i + 1).to_string(),
                    x_mm: round3(-x_offset),
                    y_mm: round3(-span_y + i as f64 * pitch),
                    width_mm: round3(pad_l),
                    height_mm: round3(pad_w),
                    shape: "roundrect",
                });
            }
            for i in 0..per_side {
                pads.push(PadGeometry {
                    pin: (per_side + i + 1).to_string(),
                    x_mm: round3(x_offset),
                    y_mm: round3(span_y - i as f64 * pitch),
                    width_mm: round3(pad_l),
                    height_mm: round3(pad_w),
                    shape: "roundrect",
                });
            }
        }
        IpcPackageFamily::QFN | IpcPackageFamily::LQFP => {
            let per_side = (pin_count / 4).max(1);
            let span = ((per_side - 1) as f64 * pitch) / 2.0;
            let overhang = if spec.family == IpcPackageFamily::LQFP {
                pad_l * 0.45
            } else {
                0.05
            };
            let x_lead = body_w / 2.0 + overhang;
            let y_lead = body_l / 2.0 + overhang;
            let mut pin = 1u32;

            for i in 0..per_side {
                pads.push(PadGeometry {
                    pin: pin.to_string(),
                    x_mm: round3(-x_lead),
                    y_mm: round3(-span + i as f64 * pitch),
                    width_mm: round3(pad_l),
                    height_mm: round3(pad_w),
                    shape: "roundrect",
                });
                pin += 1;
            }
            for i in 0..per_side {
                pads.push(PadGeometry {
                    pin: pin.to_string(),
                    x_mm: round3(-span + i as f64 * pitch),
                    y_mm: round3(y_lead),
                    width_mm: round3(pad_w),
                    height_mm: round3(pad_l),
                    shape: "roundrect",
                });
                pin += 1;
            }
            for i in 0..per_side {
                pads.push(PadGeometry {
                    pin: pin.to_string(),
                    x_mm: round3(x_lead),
                    y_mm: round3(span - i as f64 * pitch),
                    width_mm: round3(pad_l),
                    height_mm: round3(pad_w),
                    shape: "roundrect",
                });
                pin += 1;
            }
            for i in 0..per_side {
                pads.push(PadGeometry {
                    pin: pin.to_string(),
                    x_mm: round3(span - i as f64 * pitch),
                    y_mm: round3(-y_lead),
                    width_mm: round3(pad_w),
                    height_mm: round3(pad_l),
                    shape: "roundrect",
                });
                pin += 1;
            }

            if let Some(ep) = spec.thermal_pad_mm {
                if ep > 0.0 {
                    pads.push(PadGeometry {
                        pin: "EP".into(),
                        x_mm: 0.0,
                        y_mm: 0.0,
                        width_mm: round3(ep),
                        height_mm: round3(ep),
                        shape: "rect",
                    });
                }
            }
        }
        IpcPackageFamily::BGA => {
            let cols = (pin_count as f64).sqrt().round().max(2.0) as u32;
            let rows = ((pin_count as f64) / (cols as f64)).ceil().max(2.0) as u32;
            let span_x = ((cols - 1) as f64 * pitch) / 2.0;
            let span_y = ((rows - 1) as f64 * pitch) / 2.0;
            let mut count = 0u32;
            for r in 0..rows {
                for c in 0..cols {
                    if count >= pin_count {
                        break;
                    }
                    count += 1;
                    let row_letter = char::from(b'A' + (r % 26) as u8);
                    pads.push(PadGeometry {
                        pin: format!("{row_letter}{}", c + 1),
                        x_mm: round3(-span_x + c as f64 * pitch),
                        y_mm: round3(-span_y + r as f64 * pitch),
                        width_mm: round3(pad_w),
                        height_mm: round3(pad_w),
                        shape: "circle",
                    });
                }
            }
        }
    }

    let max_x = pads
        .iter()
        .map(|p| p.x_mm.abs() + p.width_mm / 2.0)
        .fold(body_w / 2.0, f64::max);
    let max_y = pads
        .iter()
        .map(|p| p.y_mm.abs() + p.height_mm / 2.0)
        .fold(body_l / 2.0, f64::max);
    let courtyard_width_mm = round3(max_x * 2.0 + 0.5);
    let courtyard_length_mm = round3(max_y * 2.0 + 0.5);

    let (pin1_marker_x_mm, pin1_marker_y_mm) = pads
        .first()
        .map(|p| (round3(p.x_mm - p.width_mm / 2.0 - 0.35), round3(p.y_mm)))
        .unwrap_or((round3(-body_w / 2.0 - 0.35), round3(-body_l / 2.0)));

    let family_name = match spec.family {
        IpcPackageFamily::SOIC => "SOIC",
        IpcPackageFamily::QFN => "QFN",
        IpcPackageFamily::LQFP => "LQFP",
        IpcPackageFamily::CHIP => "CHIP",
        IpcPackageFamily::BGA => "BGA",
    };

    Ok(FootprintGeometry {
        name: format!(
            "{family_name}-{pin_count}_P{pitch}mm_{body_w}x{body_l}mm"
        ),
        pads,
        body_width_mm: body_w,
        body_length_mm: body_l,
        courtyard_width_mm,
        courtyard_length_mm,
        pin1_marker_x_mm,
        pin1_marker_y_mm,
        view_box_width_mm: round3((courtyard_width_mm + 2.4).max(6.0)),
        view_box_height_mm: round3((courtyard_length_mm + 2.4).max(6.0)),
    })
}

pub fn generate_symbol_geometry(pin_count: u32, family: IpcPackageFamily) -> SymbolGeometry {
    let clamped = pin_count.clamp(2, 32);
    let left_count = clamped.div_ceil(2);
    let right_count = clamped - left_count;
    let max_side = left_count.max(right_count);
    let spacing = 18.0;
    let height = (max_side as f64 * spacing + 28.0).max(70.0);
    let width = 120.0;
    let mut pins = Vec::with_capacity(clamped as usize);

    for i in 0..left_count {
        let num = i + 1;
        let name = if family == IpcPackageFamily::CHIP {
            num.to_string()
        } else if num == 1 {
            "VIN/P1".to_string()
        } else {
            format!("IO_{num}")
        };
        pins.push(SymbolPin {
            number: num,
            name,
            side: "left",
            x: 0.0,
            y: 22.0 + i as f64 * spacing,
        });
    }
    for i in 0..right_count {
        let num = left_count + i + 1;
        let name = if num == clamped {
            "GND".to_string()
        } else {
            format!("OUT_{num}")
        };
        pins.push(SymbolPin {
            number: num,
            name,
            side: "right",
            x: width,
            y: 22.0 + i as f64 * spacing,
        });
    }

    SymbolGeometry {
        width,
        height,
        pins,
    }
}

pub fn generate_kicad_mod(
    geom: &FootprintGeometry,
    mpn: &str,
    description: &str,
) -> String {
    let fp_name = sanitize_identifier(&geom.name, "BP_Footprint");
    let mut s = String::new();
    let _ = writeln!(
        s,
        "(footprint \"{}\" (version 20240108) (generator \"backplane_librarian\")",
        escape_sexpr(&fp_name)
    );
    let _ = writeln!(s, "  (layer \"F.Cu\")");
    let _ = writeln!(
        s,
        "  (descr \"{}\")",
        escape_sexpr(if description.is_empty() { mpn } else { description })
    );
    let _ = writeln!(s, "  (attr smd)");

    let bw = round3(geom.body_width_mm / 2.0);
    let bl = round3(geom.body_length_mm / 2.0);
    let cw = round3(geom.courtyard_width_mm / 2.0);
    let cl = round3(geom.courtyard_length_mm / 2.0);

    let _ = writeln!(
        s,
        "  (fp_rect (start -{bw} -{bl}) (end {bw} {bl}) (stroke (width 0.12) (type solid)) (fill none) (layer \"F.Fab\"))"
    );
    let _ = writeln!(
        s,
        "  (fp_rect (start -{cw} -{cl}) (end {cw} {cl}) (stroke (width 0.05) (type solid)) (fill none) (layer \"F.CrtYd\"))"
    );
    let _ = writeln!(
        s,
        "  (fp_circle (center {} {}) (end {} {}) (stroke (width 0.15) (type solid)) (fill solid) (layer \"F.SilkS\"))",
        geom.pin1_marker_x_mm,
        geom.pin1_marker_y_mm,
        round3(geom.pin1_marker_x_mm + 0.15),
        geom.pin1_marker_y_mm
    );

    for pad in &geom.pads {
        let _ = writeln!(
            s,
            "  (pad \"{}\" smd {} (at {} {}) (size {} {}) (layers \"F.Cu\" \"F.Paste\" \"F.Mask\"))",
            escape_sexpr(&pad.pin),
            pad.shape,
            pad.x_mm,
            pad.y_mm,
            pad.width_mm,
            pad.height_mm
        );
    }

    s.push_str(")\n");
    s
}

pub fn generate_kicad_sym(
    geom: &SymbolGeometry,
    mpn: &str,
    value: &str,
    footprint_ref: &str,
    datasheet_url: &str,
    description: &str,
) -> String {
    let sym_name = sanitize_identifier(mpn, "BP_Symbol");
    let mut s = String::new();
    s.push_str("(kicad_symbol_lib (version 20231120) (generator \"backplane_librarian\")\n");
    let _ = writeln!(s, "  (symbol \"{}\" (in_bom yes) (on_board yes)", escape_sexpr(&sym_name));
    let _ = writeln!(
        s,
        "    (property \"Reference\" \"U\" (at 0 2.54 0) (effects (font (size 1.27 1.27))))"
    );
    let _ = writeln!(
        s,
        "    (property \"Value\" \"{}\" (at 0 -2.54 0) (effects (font (size 1.27 1.27))))",
        escape_sexpr(if value.is_empty() { mpn } else { value })
    );
    let _ = writeln!(
        s,
        "    (property \"Footprint\" \"{}\" (at 0 -5.08 0) (effects (font (size 1.27 1.27)) hide))",
        escape_sexpr(footprint_ref)
    );
    let _ = writeln!(
        s,
        "    (property \"Datasheet\" \"{}\" (at 0 -7.62 0) (effects (font (size 1.27 1.27)) hide))",
        escape_sexpr(datasheet_url)
    );
    let _ = writeln!(
        s,
        "    (property \"Description\" \"{}\" (at 0 -10.16 0) (effects (font (size 1.27 1.27)) hide))",
        escape_sexpr(description)
    );

    let half_h = round3((geom.pins.len().max(2) as f64 * 2.54) / 2.0);
    let _ = writeln!(s, "    (symbol \"{}_0_1\"", escape_sexpr(&sym_name));
    let _ = writeln!(
        s,
        "      (rectangle (start -7.62 {half_h}) (end 7.62 -{half_h}) (stroke (width 0.254) (type default)) (fill (type background)))"
    );
    s.push_str("    )\n");
    let _ = writeln!(s, "    (symbol \"{}_1_1\"", escape_sexpr(&sym_name));
    for (idx, pin) in geom.pins.iter().enumerate() {
        let (x, angle) = if pin.side == "left" {
            (-10.16, 0)
        } else {
            (10.16, 180)
        };
        let y = round3(half_h - 2.54 - (idx / 2) as f64 * 2.54);
        let _ = writeln!(
            s,
            "      (pin passive line (at {x} {y} {angle}) (length 2.54) (name \"{}\" (effects (font (size 1.27 1.27)))) (number \"{}\" (effects (font (size 1.27 1.27)))))",
            escape_sexpr(&pin.name),
            pin.number
        );
    }
    s.push_str("    )\n");
    s.push_str("  )\n)\n");
    s
}

pub fn render_footprint_svg(geom: &FootprintGeometry, mpn: &str) -> String {
    let half_vw = round3(geom.view_box_width_mm / 2.0);
    let half_vh = round3(geom.view_box_height_mm / 2.0);
    let mut svg = String::new();
    let _ = writeln!(
        svg,
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"{} {} {} {}\" width=\"480\" height=\"360\" role=\"img\" aria-label=\"IPC-7351 footprint for {}\">",
        -half_vw,
        -half_vh,
        geom.view_box_width_mm,
        geom.view_box_height_mm,
        escape_xml(mpn)
    );
    svg.push_str("  <rect x=\"-1000\" y=\"-1000\" width=\"2000\" height=\"2000\" fill=\"#0b1220\"/>\n");
    // Courtyard
    let _ = writeln!(
        svg,
        "  <rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" fill=\"none\" stroke=\"#64748b\" stroke-width=\"0.06\" stroke-dasharray=\"0.2 0.15\"/>",
        round3(-geom.courtyard_width_mm / 2.0),
        round3(-geom.courtyard_length_mm / 2.0),
        geom.courtyard_width_mm,
        geom.courtyard_length_mm
    );
    // Body
    let _ = writeln!(
        svg,
        "  <rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" fill=\"#1e293b\" stroke=\"#94a3b8\" stroke-width=\"0.08\"/>",
        round3(-geom.body_width_mm / 2.0),
        round3(-geom.body_length_mm / 2.0),
        geom.body_width_mm,
        geom.body_length_mm
    );
    // Pin 1 marker
    let _ = writeln!(
        svg,
        "  <circle cx=\"{}\" cy=\"{}\" r=\"0.16\" fill=\"#38bdf8\"/>",
        geom.pin1_marker_x_mm, geom.pin1_marker_y_mm
    );
    // Pads
    for pad in &geom.pads {
        if pad.shape == "circle" {
            let _ = writeln!(
                svg,
                "  <circle cx=\"{}\" cy=\"{}\" r=\"{}\" fill=\"#d97706\" stroke=\"#fbbf24\" stroke-width=\"0.03\"/>",
                pad.x_mm,
                pad.y_mm,
                round3(pad.width_mm / 2.0)
            );
        } else {
            let rx = if pad.shape == "roundrect" {
                round3((pad.width_mm.min(pad.height_mm) * 0.18).min(0.12))
            } else {
                0.0
            };
            let _ = writeln!(
                svg,
                "  <rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" rx=\"{rx}\" fill=\"#d97706\" stroke=\"#fbbf24\" stroke-width=\"0.03\"/>",
                round3(pad.x_mm - pad.width_mm / 2.0),
                round3(pad.y_mm - pad.height_mm / 2.0),
                pad.width_mm,
                pad.height_mm
            );
        }
    }
    svg.push_str("</svg>\n");
    svg
}

pub fn render_symbol_svg(geom: &SymbolGeometry, mpn: &str, value: &str) -> String {
    let vb_w = geom.width + 120.0;
    let vb_h = geom.height + 40.0;
    let mut svg = String::new();
    let _ = writeln!(
        svg,
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"-60 -20 {vb_w} {vb_h}\" width=\"420\" height=\"320\" role=\"img\" aria-label=\"KiCad symbol for {}\">",
        escape_xml(mpn)
    );
    svg.push_str("  <rect x=\"-60\" y=\"-20\" width=\"100%\" height=\"100%\" fill=\"#0b1220\"/>\n");
    let _ = writeln!(
        svg,
        "  <rect x=\"0\" y=\"0\" width=\"{}\" height=\"{}\" fill=\"#1e293b\" stroke=\"#facc15\" stroke-width=\"2\"/>",
        geom.width, geom.height
    );
    let _ = writeln!(
        svg,
        "  <text x=\"{}\" y=\"-6\" fill=\"#e2e8f0\" font-family=\"monospace\" font-size=\"11\" text-anchor=\"middle\">{}</text>",
        geom.width / 2.0,
        escape_xml(if value.is_empty() { mpn } else { value })
    );
    for pin in &geom.pins {
        let (x2, text_x, anchor) = if pin.side == "left" {
            (-22.0, 6.0, "start")
        } else {
            (geom.width + 22.0, geom.width - 6.0, "end")
        };
        let _ = writeln!(
            svg,
            "  <line x1=\"{}\" y1=\"{}\" x2=\"{x2}\" y2=\"{}\" stroke=\"#38bdf8\" stroke-width=\"1.6\"/>",
            pin.x, pin.y, pin.y
        );
        let _ = writeln!(
            svg,
            "  <text x=\"{text_x}\" y=\"{}\" fill=\"#cbd5e1\" font-family=\"monospace\" font-size=\"9\" text-anchor=\"{anchor}\">{}</text>",
            pin.y + 3.0,
            escape_xml(&pin.name)
        );
    }
    svg.push_str("</svg>\n");
    svg
}

pub fn generate_cad_assets(
    spec: &Ipc7351Spec,
    mpn: &str,
    value: &str,
    footprint_ref: &str,
    datasheet_url: &str,
    description: &str,
) -> Result<GeneratedCadAssets> {
    let fp_geom = generate_footprint_geometry(spec)?;
    let sym_geom = generate_symbol_geometry(spec.pin_count, spec.family);
    let footprint_kicad_mod = generate_kicad_mod(&fp_geom, mpn, description);
    let symbol_kicad_sym = generate_kicad_sym(
        &sym_geom,
        mpn,
        value,
        if footprint_ref.is_empty() {
            &fp_geom.name
        } else {
            footprint_ref
        },
        datasheet_url,
        description,
    );
    let footprint_svg = render_footprint_svg(&fp_geom, mpn);
    let symbol_svg = render_symbol_svg(&sym_geom, mpn, value);

    Ok(GeneratedCadAssets {
        footprint_name: fp_geom.name,
        symbol_name: sanitize_identifier(mpn, "BP_Symbol"),
        footprint_kicad_mod,
        symbol_kicad_sym,
        footprint_svg,
        symbol_svg,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_spec(family: IpcPackageFamily, pins: u32, thermal: Option<f64>) -> Ipc7351Spec {
        Ipc7351Spec {
            family,
            pin_count: pins,
            pitch_mm: 0.5,
            body_width_mm: 4.0,
            body_length_mm: 4.0,
            pad_width_mm: 0.28,
            pad_length_mm: 0.75,
            thermal_pad_mm: thermal,
        }
    }

    #[test]
    fn generates_all_five_ipc7351_families() {
        for (family, pins, thermal, expected_pads) in [
            (IpcPackageFamily::CHIP, 2, None, 2),
            (IpcPackageFamily::SOIC, 8, None, 8),
            (IpcPackageFamily::QFN, 16, Some(2.1), 17),
            (IpcPackageFamily::LQFP, 32, None, 32),
            (IpcPackageFamily::BGA, 16, None, 16),
        ] {
            let spec = sample_spec(family, pins, thermal);
            let geom = generate_footprint_geometry(&spec).unwrap();
            assert_eq!(geom.pads.len(), expected_pads);
            let kmod = generate_kicad_mod(&geom, "TEST-MPN", "desc");
            assert!(kmod.starts_with("(footprint "));
            assert!(kmod.contains("(pad \""));
        }
    }

    #[test]
    fn escapes_xml_and_sexpr_injection_attempts() {
        let spec = sample_spec(IpcPackageFamily::QFN, 16, Some(2.1));
        let assets = generate_cad_assets(
            &spec,
            "BAD\"<script>alert(1)</script>",
            "<img onerror=alert(1)>",
            "Lib:FP\"hack",
            "https://example.com/ds.pdf",
            "desc\"\n(evil)",
        )
        .unwrap();

        assert!(!assets.footprint_svg.contains("<script>"));
        assert!(!assets.symbol_svg.contains("<script>"));
        assert!(!assets.symbol_svg.contains("<img"));
        assert!(assets.symbol_svg.contains("&lt;img"));
        assert!(assets
            .footprint_kicad_mod
            .contains(r#"(descr "desc\" (evil)")"#));
        assert!(!assets.symbol_kicad_sym.contains("FP\"hack"));
        assert!(assets.symbol_kicad_sym.contains(r#"FP\"hack"#));
    }
}
