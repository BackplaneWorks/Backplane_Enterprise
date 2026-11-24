//! Outbound HTTP to fixed vendor APIs (Google, Microsoft, AWS).
//!
//! These hosts come from configuration, never from request or e-mail data, so
//! this is not the place for `bp_ent_core::SafeHttp` (which exists for
//! user-influenced URLs). The rules here: https only, enforced by the client
//! itself (plain http is accepted solely for a loopback base, used by
//! tests), no redirects, short timeouts,
//! response bodies read under a hard cap, and errors that carry no URL,
//! header or body text.

use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NetError {
    #[error("endpoint is not https")]
    InsecureBase,
    #[error("request failed")]
    Transport,
    /// The access token was refused: the connection needs to be re-authorised.
    #[error("provider refused the credentials")]
    Unauthorized,
    #[error("provider returned status {0}")]
    Status(u16),
    #[error("response too large")]
    TooLarge,
    #[error("unexpected response")]
    Decode,
}

/// A validated API base URL (no trailing slash).
#[derive(Clone, Debug)]
pub struct Base(String);

impl Base {
    pub fn new(base: &str) -> Result<Self, NetError> {
        let url = url::Url::parse(base).map_err(|_| NetError::InsecureBase)?;
        let loopback = matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"));
        let ok = url.scheme() == "https" || (url.scheme() == "http" && loopback);
        if !ok || !url.username().is_empty() || url.password().is_some() {
            return Err(NetError::InsecureBase);
        }
        Ok(Self(base.trim_end_matches('/').to_string()))
    }
    pub fn join(&self, path: &str) -> String {
        format!("{}{}", self.0, path)
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The client for vendor APIs. `https_only` is on in production; it is off
/// only when a loopback base has been configured (tests).
pub fn client(https_only: bool) -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(5))
        .https_only(https_only)
        .user_agent("backplane-enterprise")
        .build()
        .expect("reqwest client")
}

/// Read a response body, refusing anything over `max` bytes.
pub async fn read_capped(mut resp: reqwest::Response, max: usize) -> Result<Vec<u8>, NetError> {
    if resp.content_length().is_some_and(|l| l > max as u64) {
        return Err(NetError::TooLarge);
    }
    let mut out = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|_| NetError::Transport)? {
        if out.len() + chunk.len() > max {
            return Err(NetError::TooLarge);
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

/// Send a prepared request and decode a JSON body under `max` bytes.
pub async fn send_json<T: serde::de::DeserializeOwned>(
    req: reqwest::RequestBuilder,
    max: usize,
) -> Result<T, NetError> {
    let bytes = send_bytes(req, max).await?;
    serde_json::from_slice(&bytes).map_err(|_| NetError::Decode)
}

pub async fn send_bytes(req: reqwest::RequestBuilder, max: usize) -> Result<Vec<u8>, NetError> {
    let resp = req.send().await.map_err(|_| NetError::Transport)?;
    let status = resp.status();
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(NetError::Unauthorized);
    }
    if !status.is_success() {
        return Err(NetError::Status(status.as_u16()));
    }
    read_capped(resp, max).await
}

/// Percent-encode one path segment (ids handed back by a provider).
pub fn seg(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>().replace('+', "%20")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_must_be_https_or_loopback() {
        assert!(Base::new("https://gmail.googleapis.com").is_ok());
        assert!(Base::new("http://127.0.0.1:9000").is_ok());
        for bad in ["http://gmail.googleapis.com", "http://169.254.169.254", "file:///etc/passwd", "https://user:pw@host", "nonsense"] {
            assert_eq!(Base::new(bad).unwrap_err(), NetError::InsecureBase, "{bad}");
        }
    }

    #[tokio::test]
    async fn production_client_refuses_plain_http() {
        // Nothing listens here; the request must fail before any connection.
        let err = client(true).get("http://127.0.0.1:9/x").send().await.unwrap_err();
        assert!(err.is_builder() || err.is_request(), "{err:?}");
        assert!(!err.is_connect());
    }

    #[test]
    fn path_segments_cannot_escape() {
        assert_eq!(seg("../../x?y=1#z"), "..%2F..%2Fx%3Fy%3D1%23z");
        assert_eq!(seg("a b"), "a%20b");
    }
}
