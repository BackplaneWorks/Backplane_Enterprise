//! APNs HTTP/2 client & ES256 provider JWT signer, with mock URL support.

use async_trait::async_trait;
use bp_ent_core::Secret;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::Serialize;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const TOKEN_REFRESH_SECS: u64 = 40 * 60;

#[derive(Clone, Debug)]
pub struct ApnsRequest {
    pub token: Secret<String>,
    pub env: String,
    pub topic: String,
    pub push_type: String,
    pub priority: u8,
    pub collapse_id: Option<String>,
    pub payload: serde_json::Value,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApnsDelivery {
    pub status: u16,
    pub apns_id: Option<String>,
    pub reason: Option<String>,
    pub dead: bool,
}

#[async_trait]
pub trait ApnsSender: Send + Sync {
    fn mode(&self) -> &'static str;
    async fn send(&self, req: ApnsRequest) -> ApnsDelivery;
}

#[derive(Clone)]
pub struct ApnsConfig {
    pub key_pem: Option<Secret<String>>,
    pub key_id: String,
    pub team_id: String,
    pub mock_url: Option<String>,
}

impl ApnsConfig {
    pub fn from_env() -> Self {
        let mock_url = std::env::var("BP_APNS_MOCK_URL")
            .ok()
            .map(|s| s.trim().trim_end_matches('/').to_string())
            .filter(|s| !s.is_empty());

        let key_pem = std::env::var("BP_APNS_KEY_PEM")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| {
                std::env::var("BP_APNS_KEY_FILE")
                    .ok()
                    .filter(|p| !p.trim().is_empty())
                    .and_then(|p| match std::fs::read_to_string(&p) {
                        Ok(s) if !s.trim().is_empty() => Some(s),
                        Ok(_) => {
                            tracing::warn!(path = %p, "BP_APNS_KEY_FILE is empty");
                            None
                        }
                        Err(e) => {
                            tracing::warn!(path = %p, error = %e, "could not read BP_APNS_KEY_FILE");
                            None
                        }
                    })
            })
            .map(Secret::new);

        let key_id = std::env::var("BP_APNS_KEY_ID")
            .unwrap_or_default()
            .trim()
            .to_string();
        let team_id = std::env::var("BP_APNS_TEAM_ID")
            .unwrap_or_default()
            .trim()
            .to_string();

        Self {
            key_pem,
            key_id,
            team_id,
            mock_url,
        }
    }

    pub fn has_real_credentials(&self) -> bool {
        self.key_pem.is_some() && !self.key_id.is_empty() && !self.team_id.is_empty()
    }
}

#[derive(Serialize)]
struct ProviderClaims<'a> {
    iss: &'a str,
    iat: u64,
}

pub fn sign_provider_jwt(
    key_pem: &str,
    key_id: &str,
    team_id: &str,
    now_secs: u64,
) -> Result<String, String> {
    let key = EncodingKey::from_ec_pem(key_pem.as_bytes())
        .map_err(|e| format!("invalid APNs EC private key: {e}"))?;
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(key_id.to_string());
    let claims = ProviderClaims {
        iss: team_id,
        iat: now_secs,
    };
    encode(&header, &claims, &key).map_err(|e| format!("failed signing APNs JWT: {e}"))
}

pub fn classify_apns_response(
    status: u16,
    apns_id: Option<String>,
    body: &str,
) -> ApnsDelivery {
    let reason = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("reason").and_then(|r| r.as_str()).map(str::to_string))
        .filter(|s| !s.is_empty());

    let dead = status == 410
        || (matches!(status, 400 | 403)
            && matches!(
                reason.as_deref(),
                Some("BadDeviceToken" | "DeviceTokenNotForTopic" | "Unregistered")
            ));

    ApnsDelivery {
        status,
        apns_id,
        reason,
        dead,
    }
}

pub struct HttpApnsSender {
    cfg: ApnsConfig,
    apns_http: reqwest::Client,
    mock_http: reqwest::Client,
    jwt_cache: Mutex<(String, u64)>,
}

impl HttpApnsSender {
    pub fn from_env() -> Self {
        Self::new(ApnsConfig::from_env())
    }

    pub fn new(cfg: ApnsConfig) -> Self {
        let apns_http = reqwest::Client::builder()
            .use_rustls_tls()
            .https_only(true)
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("reqwest apns client");
        let mock_http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("reqwest mock client");
        Self {
            cfg,
            apns_http,
            mock_http,
            jwt_cache: Mutex::new((String::new(), 0)),
        }
    }

    fn provider_jwt(&self, now_secs: u64) -> Result<String, String> {
        let Some(pem) = &self.cfg.key_pem else {
            return Err("APNs key is not configured".into());
        };
        if self.cfg.key_id.is_empty() || self.cfg.team_id.is_empty() {
            return Err("APNs key_id or team_id is not configured".into());
        }
        let mut guard = self.jwt_cache.lock().unwrap();
        if guard.0.is_empty() || now_secs >= guard.1.saturating_add(TOKEN_REFRESH_SECS) {
            let tok = sign_provider_jwt(
                pem.expose(),
                &self.cfg.key_id,
                &self.cfg.team_id,
                now_secs,
            )?;
            *guard = (tok, now_secs);
        }
        Ok(guard.0.clone())
    }
}

#[async_trait]
impl ApnsSender for HttpApnsSender {
    fn mode(&self) -> &'static str {
        if self.cfg.mock_url.is_some() {
            "mock"
        } else if self.cfg.has_real_credentials() {
            "apns"
        } else {
            "unconfigured"
        }
    }

    async fn send(&self, req: ApnsRequest) -> ApnsDelivery {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());

        let (client, base_url, jwt) = if let Some(mock) = &self.cfg.mock_url {
            (&self.mock_http, mock.as_str(), "mock-jwt".to_string())
        } else {
            let jwt = match self.provider_jwt(now_secs) {
                Ok(j) => j,
                Err(why) => {
                    return ApnsDelivery {
                        status: 503,
                        apns_id: None,
                        reason: Some(why),
                        dead: false,
                    };
                }
            };
            let host = if req.env == "sandbox" {
                "https://api.sandbox.push.apple.com"
            } else {
                "https://api.push.apple.com"
            };
            (&self.apns_http, host, jwt)
        };

        let url = format!("{base_url}/3/device/{}", req.token.expose());
        let mut builder = client
            .post(url)
            .header("authorization", format!("bearer {jwt}"))
            .header("apns-topic", &req.topic)
            .header("apns-push-type", &req.push_type)
            .header("apns-priority", req.priority.to_string());
        if let Some(cid) = req.collapse_id.as_deref().filter(|s| !s.is_empty()) {
            builder = builder.header("apns-collapse-id", cid);
        }

        match builder.json(&req.payload).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let apns_id = resp
                    .headers()
                    .get("apns-id")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string);
                let body = resp.text().await.unwrap_or_default();
                classify_apns_response(status, apns_id, &body)
            }
            Err(e) => {
                tracing::warn!(error = %e.without_url(), "APNs transport request failed");
                ApnsDelivery {
                    status: 502,
                    apns_id: None,
                    reason: Some("APNs transport error".into()),
                    dead: false,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signs_es256_jwt_and_classifies_dead_tokens() {
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let pem = kp.serialize_pem();
        let jwt = sign_provider_jwt(&pem, "KEY1234567", "TEAMID1234", 1_700_000_000).unwrap();
        let header = jsonwebtoken::decode_header(&jwt).unwrap();
        assert_eq!(header.alg, Algorithm::ES256);
        assert_eq!(header.kid.as_deref(), Some("KEY1234567"));

        assert!(classify_apns_response(410, None, r#"{"reason":"Unregistered"}"#).dead);
        assert!(classify_apns_response(400, None, r#"{"reason":"BadDeviceToken"}"#).dead);
        assert!(classify_apns_response(400, None, r#"{"reason":"DeviceTokenNotForTopic"}"#).dead);
        assert!(!classify_apns_response(403, None, r#"{"reason":"TopicDisallowed"}"#).dead);
        assert!(classify_apns_response(200, Some("id-1".into()), "").apns_id == Some("id-1".into()));
    }
}
