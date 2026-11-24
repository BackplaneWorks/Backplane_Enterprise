//! Outbound HTTP for URLs that a user, a tenant admin or a remote document
//! can influence (OIDC discovery, JWKS, datasheet links, webhooks).
//!
//! Guards against server-side request forgery:
//! - `https` only;
//! - the address actually connected to is checked *after* DNS resolution
//!   (inside the resolver the client uses, so there is no check/use gap for
//!   DNS rebinding), and private, loopback, link-local and cloud-metadata
//!   addresses are refused;
//! - redirects are not followed;
//! - responses are size-capped and requests time out.

use crate::{Error, Result};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

/// Default cap on a response body.
pub const DEFAULT_MAX_BODY: usize = 2 * 1024 * 1024;

#[derive(Clone)]
pub struct SafeHttp {
    client: reqwest::Client,
    allow_private: bool,
}

struct GuardedResolver {
    allow_private: bool,
}

impl Resolve for GuardedResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let allow_private = self.allow_private;
        Box::pin(async move {
            let host = name.as_str().to_string();
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                .await?
                .filter(|a| !is_blocked(a.ip(), allow_private))
                .collect();
            if addrs.is_empty() {
                return Err("destination address is not allowed".into());
            }
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

/// Addresses that are never a legitimate destination, and (unless
/// `allow_private`) every non-public range.
pub fn is_blocked(ip: IpAddr, allow_private: bool) -> bool {
    match ip {
        IpAddr::V4(v4) => blocked_v4(v4, allow_private),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return blocked_v4(v4, allow_private);
            }
            let seg = v6.segments();
            // NAT64 (64:ff9b::/96) and 6to4 (2002::/16) embed an IPv4 address.
            if seg[0] == 0x64 && seg[1] == 0xff9b && seg[2..6] == [0, 0, 0, 0] {
                let v4 = Ipv4Addr::new((seg[6] >> 8) as u8, seg[6] as u8, (seg[7] >> 8) as u8, seg[7] as u8);
                return blocked_v4(v4, allow_private);
            }
            if seg[0] == 0x2002 {
                let v4 = Ipv4Addr::new((seg[1] >> 8) as u8, seg[1] as u8, (seg[2] >> 8) as u8, seg[2] as u8);
                return blocked_v4(v4, allow_private);
            }
            let always = v6.is_unspecified()
                || v6.is_multicast()
                || (seg[0] & 0xffc0) == 0xfe80 // link-local
                || v6 == Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254); // AWS IMDS
            let private = v6.is_loopback()
                || (seg[0] & 0xfe00) == 0xfc00 // unique local
                || (seg[0] == 0x2001 && seg[1] == 0xdb8) // documentation
                || (seg[0] == 0 && seg[1] == 0 && seg[2] == 0 && seg[3] == 0 && seg[4] == 0 && seg[5] == 0); // v4-compatible
            always || (!allow_private && private)
        }
    }
}

fn blocked_v4(ip: Ipv4Addr, allow_private: bool) -> bool {
    let o = ip.octets();
    // Link-local covers every cloud metadata service (169.254.169.254,
    // 169.254.170.2, ...): blocked even on self-host.
    let always = ip.is_unspecified() || ip.is_link_local() || ip.is_multicast() || ip.is_broadcast() || o[0] == 0;
    let private = ip.is_loopback()
        || ip.is_private()
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // CGNAT 100.64/10
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // IETF protocol assignments
        || (o[0] == 198 && (o[1] & 0xfe) == 18) // benchmarking
        || ip.is_documentation()
        || o[0] >= 240; // reserved
    always || (!allow_private && private)
}

impl SafeHttp {
    pub fn new(allow_private: bool) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .dns_resolver(Arc::new(GuardedResolver { allow_private }))
            .no_proxy()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(20))
            .user_agent("backplane-enterprise")
            .build()?;
        Ok(Self { client, allow_private })
    }

    /// Check a URL before any request is made: https, has a host, no
    /// credentials, and if the host is an IP literal, an allowed one.
    /// (Host names are checked when they resolve.)
    pub fn check_url(&self, raw: &str) -> Result<url::Url> {
        check_url(raw, self.allow_private)
    }

    /// Start a request to a checked URL.
    pub fn request(&self, method: reqwest::Method, url: &str) -> Result<reqwest::RequestBuilder> {
        Ok(self.client.request(method, self.check_url(url)?))
    }

    pub fn get(&self, url: &str) -> Result<reqwest::RequestBuilder> {
        self.request(reqwest::Method::GET, url)
    }

    pub fn post(&self, url: &str) -> Result<reqwest::RequestBuilder> {
        self.request(reqwest::Method::POST, url)
    }

    /// Send and read the body, refusing more than `max` bytes.
    pub async fn fetch(&self, req: reqwest::RequestBuilder, max: usize) -> Result<(reqwest::StatusCode, Vec<u8>)> {
        let mut resp = req.send().await.map_err(|e| Error::upstream(anyhow::anyhow!("request failed: {}", e.without_url())))?;
        let status = resp.status();
        if matches!(resp.content_length(), Some(n) if n > max as u64) {
            return Err(Error::upstream(anyhow::anyhow!("response too large")));
        }
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(|e| Error::upstream(anyhow::anyhow!("read failed: {}", e.without_url())))? {
            if body.len() + chunk.len() > max {
                return Err(Error::upstream(anyhow::anyhow!("response too large")));
            }
            body.extend_from_slice(&chunk);
        }
        Ok((status, body))
    }

    /// GET a JSON document (2xx only, size-capped).
    pub async fn get_json<T: serde::de::DeserializeOwned>(&self, url: &str) -> Result<T> {
        let (status, body) = self.fetch(self.get(url)?.header("accept", "application/json"), DEFAULT_MAX_BODY).await?;
        if !status.is_success() {
            return Err(Error::upstream(anyhow::anyhow!("unexpected status {status}")));
        }
        serde_json::from_slice(&body).map_err(|e| Error::upstream(anyhow::anyhow!("invalid JSON: {e}")))
    }
}

pub fn check_url(raw: &str, allow_private: bool) -> Result<url::Url> {
    let bad = |m: &str| Error::invalid(m.to_string());
    let u = url::Url::parse(raw).map_err(|_| bad("not a valid URL"))?;
    if u.scheme() != "https" {
        return Err(bad("URL must be https"));
    }
    if !u.username().is_empty() || u.password().is_some() {
        return Err(bad("URL must not contain credentials"));
    }
    match u.host() {
        None => return Err(bad("URL has no host")),
        Some(url::Host::Ipv4(ip)) if is_blocked(IpAddr::V4(ip), allow_private) => return Err(bad("destination is not allowed")),
        Some(url::Host::Ipv6(ip)) if is_blocked(IpAddr::V6(ip), allow_private) => return Err(bad("destination is not allowed")),
        Some(url::Host::Domain(d)) => {
            let d = d.trim_end_matches('.').to_ascii_lowercase();
            if !allow_private && (d == "localhost" || d.ends_with(".localhost") || d.ends_with(".internal") || d.ends_with(".local")) {
                return Err(bad("destination is not allowed"));
            }
        }
        _ => {}
    }
    Ok(u)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blocked(s: &str) -> bool {
        is_blocked(s.parse().unwrap(), false)
    }

    #[test]
    fn blocks_internal_ranges() {
        for ip in [
            "127.0.0.1", "10.0.0.5", "172.16.0.1", "172.31.255.255", "192.168.1.1", "169.254.169.254",
            "169.254.170.2", "100.64.0.1", "0.0.0.0", "0.1.2.3", "224.0.0.1", "255.255.255.255", "240.0.0.1",
            "198.18.0.1", "192.0.0.1", "::1", "::", "fe80::1", "fc00::1", "fd00:ec2::254", "ff02::1",
            "::ffff:127.0.0.1", "::ffff:169.254.169.254", "::ffff:10.0.0.1", "64:ff9b::a9fe:a9fe",
            "2002:7f00:1::1", "::7f00:1",
        ] {
            assert!(blocked(ip), "{ip} should be blocked");
        }
    }

    #[test]
    fn allows_public_addresses() {
        for ip in ["1.1.1.1", "8.8.8.8", "93.184.216.34", "172.32.0.1", "100.128.0.1", "2606:4700:4700::1111", "64:ff9b::808:808"] {
            assert!(!blocked(ip), "{ip} should be allowed");
        }
    }

    #[test]
    fn self_host_mode_allows_private_but_never_metadata() {
        let p = |s: &str| is_blocked(s.parse().unwrap(), true);
        assert!(!p("10.0.0.5"));
        assert!(!p("127.0.0.1"));
        assert!(!p("fd12::1"));
        assert!(p("169.254.169.254"));
        assert!(p("::ffff:169.254.169.254"));
        assert!(p("fd00:ec2::254"));
        assert!(p("fe80::1"));
        assert!(p("0.0.0.0"));
    }

    #[test]
    fn url_checks() {
        assert!(check_url("https://accounts.google.com/.well-known/openid-configuration", false).is_ok());
        for bad in [
            "http://example.com/",
            "ftp://example.com/",
            "file:///etc/passwd",
            "https://user:pw@example.com/",
            "https://127.0.0.1/",
            "https://[::1]/",
            "https://169.254.169.254/latest/meta-data/",
            "https://2130706433/",     // decimal 127.0.0.1
            "https://0x7f.0.0.1/",     // hex octet
            "https://localhost/",
            "https://db.internal/",
            "https://foo.localhost./",
            "not a url",
        ] {
            assert!(check_url(bad, false).is_err(), "{bad}");
        }
        assert!(check_url("https://idp.corp.internal/", true).is_ok());
        assert!(check_url("https://169.254.169.254/", true).is_err());
    }

    #[tokio::test]
    async fn resolver_refuses_names_that_resolve_to_loopback() {
        let http = SafeHttp::new(false).unwrap();
        // Passes the URL check (a plain host name), must die at resolution.
        let res = http.fetch(http.client.get("https://localhost.localdomain.invalid./"), 1024).await;
        assert!(res.is_err());
        let r = GuardedResolver { allow_private: false };
        let out = r.resolve("localhost".parse().unwrap()).await;
        assert!(out.is_err());
    }
}
