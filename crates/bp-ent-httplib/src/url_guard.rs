//! SSRF-safe external URL validation for datasheet links and `backplane://open-kicad` deep links.

use bp_ent_core::{Error, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use url::Url;

fn is_blocked_ipv4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        // CGNAT 100.64.0.0/10
        || (o[0] == 100 && (o[1] & 0b1100_0000) == 64)
        // Benchmarking 198.18.0.0/15
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
}

fn is_blocked_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_blocked_ipv4(v4);
    }
    let segs = ip.segments();
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        // Unique Local Addresses fc00::/7
        || (segs[0] & 0xfe00) == 0xfc00
        // Link-local fe80::/10
        || (segs[0] & 0xffc0) == 0xfe80
}

fn is_blocked_host(host: &str) -> bool {
    let lower = host.trim_matches(['[', ']']).to_ascii_lowercase();
    if lower.is_empty()
        || lower == "localhost"
        || lower.ends_with(".localhost")
        || lower.ends_with(".local")
        || lower.ends_with(".internal")
        || lower == "metadata.google.internal"
    {
        return true;
    }

    if let Ok(ip) = lower.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(v4) => is_blocked_ipv4(v4),
            IpAddr::V6(v6) => is_blocked_ipv6(v6),
        };
    }

    false
}

/// Validates user-supplied datasheet links: must be empty or a public `https://`
/// URL with no embedded credentials and no private/link-local/metadata host.
pub fn validate_public_https_url(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    let parsed = Url::parse(trimmed).map_err(|_| Error::invalid("invalid datasheet URL"))?;
    if parsed.scheme() != "https" {
        return Err(Error::invalid("datasheet URL must use https://"));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(Error::invalid("datasheet URL must not embed credentials"));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| Error::invalid("datasheet URL must include a host"))?;
    if is_blocked_host(host) {
        return Err(Error::invalid(
            "datasheet URL must target a public host (private/local/metadata addresses are blocked)",
        ));
    }
    Ok(parsed.to_string())
}

/// Builds a `backplane://open-kicad?...` deep link for either local KiCad or a managed Boat VM.
pub fn build_kicad_deep_link(
    tenant_slug: &str,
    target: &str,
    part_id: Option<&str>,
    board_id: Option<&str>,
    refdes: Option<&str>,
    vm_id: Option<&str>,
) -> Result<String> {
    if target != "local" && target != "boat_vm" {
        return Err(Error::invalid("target must be 'local' or 'boat_vm'"));
    }
    let mut url = Url::parse("backplane://open-kicad")
        .map_err(|e| Error::internal(anyhow::anyhow!("deep-link base error: {e}")))?;
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("tenant", tenant_slug);
        q.append_pair("target", target);
        if let Some(p) = part_id {
            if !p.is_empty() {
                q.append_pair("part_id", p);
            }
        }
        if let Some(b) = board_id {
            if !b.is_empty() {
                q.append_pair("board_id", b);
            }
        }
        if let Some(r) = refdes {
            if !r.is_empty() {
                q.append_pair("refdes", r);
            }
        }
        if let Some(v) = vm_id {
            if !v.is_empty() {
                q.append_pair("vm_id", v);
            }
        }
    }
    Ok(url.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_empty_and_public_https_urls() {
        assert_eq!(validate_public_https_url("   ").unwrap(), "");
        let ok = validate_public_https_url("https://www.ti.com/lit/ds/symlink/tps54302.pdf").unwrap();
        assert_eq!(ok, "https://www.ti.com/lit/ds/symlink/tps54302.pdf");
    }

    #[test]
    fn rejects_non_https_credentials_and_ssrf_targets() {
        for bad in [
            "http://www.ti.com/ds.pdf",
            "javascript:alert(1)",
            "file:///etc/passwd",
            "https://user:pass@example.com/ds.pdf",
            "https://localhost/ds.pdf",
            "https://internal.corp.local/ds.pdf",
            "https://metadata.google.internal/computeMetadata/v1/",
            "https://169.254.169.254/latest/meta-data/",
            "https://127.0.0.1/ds.pdf",
            "https://10.0.0.1/ds.pdf",
            "https://172.16.5.4/ds.pdf",
            "https://192.168.1.1/ds.pdf",
            "https://[::1]/ds.pdf",
            "https://[fe80::1]/ds.pdf",
            "https://[::ffff:169.254.169.254]/latest/meta-data/",
        ] {
            assert!(validate_public_https_url(bad).is_err(), "expected rejection for {bad}");
        }
    }

    #[test]
    fn builds_valid_deep_link() {
        let link = build_kicad_deep_link(
            "acme-robotics",
            "boat_vm",
            Some("part-123"),
            None,
            Some("U1"),
            Some("vm-99"),
        )
        .unwrap();
        assert!(link.starts_with("backplane://open-kicad?"));
        assert!(link.contains("tenant=acme-robotics"));
        assert!(link.contains("target=boat_vm"));
        assert!(link.contains("part_id=part-123"));
        assert!(link.contains("vm_id=vm-99"));
        assert!(build_kicad_deep_link("acme", "ssh", None, None, None, None).is_err());
    }
}
