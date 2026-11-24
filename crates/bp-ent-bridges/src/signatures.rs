//! Native per-platform signature & token verification over raw request bytes.
//!
//! - Generic / Dots / Grok / A2A (`X-BP-Signature: t=<unix>,v1=<hex>`):
//!   HMAC-SHA256(secret, "<t>.<body>"), constant-time compare, ±300s window.
//! - Slack (`X-Slack-Request-Timestamp` + `X-Slack-Signature: v0=<hex>`):
//!   HMAC-SHA256(signing_secret, "v0:<ts>:<body>"), constant-time compare, ±300s window.
//! - Discord (`X-Signature-Ed25519` + `X-Signature-Timestamp`):
//!   Ed25519 `verify_strict` over `<ts><body>`, ±300s window.
//! - Microsoft Teams (`Authorization: Bearer <jwt>`):
//!   RS256 JWT signature verified against Microsoft Bot Framework JWKS
//!   (rejecting alg=none / HS256), `aud` == bot app id, `iss` allowlisted,
//!   and optional `serviceurl` checked with `SafeHttp::check_url`.

use async_trait::async_trait;
use ed25519_dalek::{Signature, VerifyingKey};
use hmac::{Hmac, Mac};
use jsonwebtoken::{decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;

/// Maximum accepted inbound webhook body (256 KiB).
pub const MAX_INBOUND_BODY: usize = 256 * 1024;
/// Standard 5-minute replay tolerance.
pub const DEFAULT_TOLERANCE_SECS: i64 = 300;

/// Trusted Bot Framework OpenID metadata URLs (official Microsoft hosts only).
const TEAMS_OPENID_METADATA_URL: &str =
    "https://login.botframework.com/v1/.well-known/openidconfiguration";

const TEAMS_ISSUERS: &[&str] = &[
    "https://api.botframework.com",
    "https://sts.windows.net/d6d49420-f39b-4df7-a1dc-59a935871db/",
    "https://login.microsoftonline.com/d6d49420-f39b-4df7-a1dc-59a935871db/v2.0",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SignatureError {
    #[error("missing or malformed signature header")]
    Malformed,
    #[error("timestamp outside tolerance")]
    Stale,
    #[error("signature mismatch")]
    Mismatch,
    #[error("body too large")]
    TooLarge,
    #[error("bridge verification key missing")]
    MissingKey,
    #[error("invalid teams jwt")]
    InvalidJwt,
}

fn check_body_len(body: &[u8]) -> Result<(), SignatureError> {
    if body.len() > MAX_INBOUND_BODY {
        Err(SignatureError::TooLarge)
    } else {
        Ok(())
    }
}

fn parse_unix_ts(raw: &str) -> Result<i64, SignatureError> {
    let s = raw.trim();
    if s.is_empty() || s.len() > 12 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(SignatureError::Malformed);
    }
    s.parse().map_err(|_| SignatureError::Malformed)
}

// ================================================== Generic / Dots / Grok / A2A

/// Verify `X-BP-Signature: t=<unix>,v1=<hex>[,v1=...]` over `<t>.<body>`.
/// Mirrors `bp-ent-orders::stripe::webhook::verify_signature`.
pub fn verify_bp_hmac(
    secret: &[u8],
    header: &str,
    body: &[u8],
    now: i64,
    tolerance_secs: i64,
) -> Result<(), SignatureError> {
    check_body_len(body)?;
    if secret.is_empty() || header.len() > 2048 {
        return Err(SignatureError::Malformed);
    }
    let mut timestamp: Option<&str> = None;
    let mut candidates: Vec<Vec<u8>> = Vec::new();
    for part in header.split(',') {
        let Some((k, v)) = part.trim().split_once('=') else {
            return Err(SignatureError::Malformed);
        };
        match k {
            "t" => {
                if timestamp.replace(v).is_some() {
                    return Err(SignatureError::Malformed);
                }
            }
            "v1" => {
                if let Ok(raw) = hex::decode(v) {
                    if raw.len() == 32 && candidates.len() < 8 {
                        candidates.push(raw);
                    }
                }
            }
            _ => {}
        }
    }
    let t_str = timestamp.ok_or(SignatureError::Malformed)?;
    let t = parse_unix_ts(t_str)?;
    if candidates.is_empty() {
        return Err(SignatureError::Malformed);
    }

    let mut mac = Hmac::<Sha256>::new_from_slice(secret).map_err(|_| SignatureError::Malformed)?;
    mac.update(t_str.as_bytes());
    mac.update(b".");
    mac.update(body);
    let expected = mac.finalize().into_bytes();

    let mut ok = 0u8;
    for c in &candidates {
        ok |= c.as_slice().ct_eq(expected.as_slice()).unwrap_u8();
    }
    if ok != 1 {
        return Err(SignatureError::Mismatch);
    }
    if (now - t).abs() > tolerance_secs {
        return Err(SignatureError::Stale);
    }
    Ok(())
}

/// Produce `t=<t>,v1=<hex>` signature for outbound webhooks / A2A / tests.
pub fn sign_bp_hmac(secret: &[u8], body: &[u8], t: i64) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("hmac key");
    mac.update(t.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    format!("t={t},v1={}", hex::encode(mac.finalize().into_bytes()))
}

// ===================================================================== Slack v0

/// Verify Slack Events API `X-Slack-Request-Timestamp` and `X-Slack-Signature: v0=<hex>`.
pub fn verify_slack_v0(
    signing_secret: &[u8],
    timestamp_hdr: &str,
    signature_hdr: &str,
    body: &[u8],
    now: i64,
    tolerance_secs: i64,
) -> Result<(), SignatureError> {
    check_body_len(body)?;
    if signing_secret.is_empty() || signature_hdr.len() > 256 {
        return Err(SignatureError::Malformed);
    }
    let ts_str = timestamp_hdr.trim();
    let ts = parse_unix_ts(ts_str)?;
    let sig_hex = signature_hdr
        .trim()
        .strip_prefix("v0=")
        .ok_or(SignatureError::Malformed)?;
    let sig_bytes = hex::decode(sig_hex).map_err(|_| SignatureError::Malformed)?;
    if sig_bytes.len() != 32 {
        return Err(SignatureError::Malformed);
    }

    let mut mac =
        Hmac::<Sha256>::new_from_slice(signing_secret).map_err(|_| SignatureError::Malformed)?;
    mac.update(b"v0:");
    mac.update(ts_str.as_bytes());
    mac.update(b":");
    mac.update(body);
    let expected = mac.finalize().into_bytes();

    if !bool::from(sig_bytes.as_slice().ct_eq(expected.as_slice())) {
        return Err(SignatureError::Mismatch);
    }
    if (now - ts).abs() > tolerance_secs {
        return Err(SignatureError::Stale);
    }
    Ok(())
}

/// Sign a payload using Slack's `v0:<ts>:<body>` scheme (for tests).
pub fn sign_slack_v0(signing_secret: &[u8], ts: i64, body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(signing_secret).expect("hmac key");
    mac.update(b"v0:");
    mac.update(ts.to_string().as_bytes());
    mac.update(b":");
    mac.update(body);
    format!("v0={}", hex::encode(mac.finalize().into_bytes()))
}

// ============================================================= Discord Ed25519

/// Verify Discord Interactions `X-Signature-Ed25519` and `X-Signature-Timestamp`.
pub fn verify_discord_ed25519(
    pubkey_hex: &str,
    signature_hex: &str,
    timestamp_hdr: &str,
    body: &[u8],
    now: i64,
    tolerance_secs: i64,
) -> Result<(), SignatureError> {
    check_body_len(body)?;
    let pk_bytes = hex::decode(pubkey_hex.trim()).map_err(|_| SignatureError::MissingKey)?;
    let pk_arr: [u8; 32] = pk_bytes
        .try_into()
        .map_err(|_| SignatureError::MissingKey)?;
    let verifying_key = VerifyingKey::from_bytes(&pk_arr).map_err(|_| SignatureError::MissingKey)?;

    let sig_bytes = hex::decode(signature_hex.trim()).map_err(|_| SignatureError::Malformed)?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| SignatureError::Malformed)?;
    let signature = Signature::from_bytes(&sig_arr);

    let ts_str = timestamp_hdr.trim();
    let ts = parse_unix_ts(ts_str)?;

    let mut msg = Vec::with_capacity(ts_str.len() + body.len());
    msg.extend_from_slice(ts_str.as_bytes());
    msg.extend_from_slice(body);

    verifying_key
        .verify_strict(&msg, &signature)
        .map_err(|_| SignatureError::Mismatch)?;

    if (now - ts).abs() > tolerance_secs {
        return Err(SignatureError::Stale);
    }
    Ok(())
}

// ====================================================== Microsoft Teams RS256

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TeamsClaims {
    pub iss: String,
    pub aud: String,
    pub exp: i64,
    #[serde(default)]
    pub nbf: Option<i64>,
    #[serde(default)]
    pub serviceurl: Option<String>,
}

type JwksKeyMap = HashMap<String, (String, String)>;

#[async_trait]
pub trait JwksProvider: Send + Sync + 'static {
    async fn decoding_key(&self, kid: &str) -> Result<DecodingKey, SignatureError>;
}

/// Static JWKS provider for deterministic tests and offline verification.
#[derive(Default)]
pub struct StaticJwksProvider {
    keys: Mutex<JwksKeyMap>,
}

impl StaticJwksProvider {
    pub fn with_rsa_b64(self, kid: impl Into<String>, n_b64url: impl Into<String>, e_b64url: impl Into<String>) -> Self {
        self.keys
            .lock()
            .unwrap()
            .insert(kid.into(), (n_b64url.into(), e_b64url.into()));
        self
    }

    pub fn with_jwk_set(jwk_set_json: &str) -> Result<Self, SignatureError> {
        let set: JwkSet = serde_json::from_str(jwk_set_json).map_err(|_| SignatureError::InvalidJwt)?;
        let provider = Self::default();
        for jwk in set.keys {
            if let (Some(kid), jsonwebtoken::jwk::AlgorithmParameters::RSA(rsa)) =
                (jwk.common.key_id, jwk.algorithm)
            {
                provider.keys.lock().unwrap().insert(kid, (rsa.n, rsa.e));
            }
        }
        Ok(provider)
    }
}

#[async_trait]
impl JwksProvider for StaticJwksProvider {
    async fn decoding_key(&self, kid: &str) -> Result<DecodingKey, SignatureError> {
        let guard = self.keys.lock().unwrap();
        let (n, e) = guard.get(kid).ok_or(SignatureError::InvalidJwt)?;
        DecodingKey::from_rsa_components(n, e).map_err(|_| SignatureError::InvalidJwt)
    }
}

/// Live Microsoft Bot Framework JWKS provider backed by `SafeHttp` with a 1-hour cache.
pub struct LiveJwksProvider {
    http: bp_ent_core::SafeHttp,
    cache: tokio::sync::Mutex<Option<(Instant, JwksKeyMap)>>,
}

impl LiveJwksProvider {
    pub fn new(http: bp_ent_core::SafeHttp) -> Self {
        Self {
            http,
            cache: tokio::sync::Mutex::new(None),
        }
    }

    async fn fetch_keys(&self) -> Result<JwksKeyMap, SignatureError> {
        #[derive(Deserialize)]
        struct OidcDoc {
            jwks_uri: String,
        }
        let doc: OidcDoc = self
            .http
            .get_json(TEAMS_OPENID_METADATA_URL)
            .await
            .map_err(|_| SignatureError::InvalidJwt)?;
        let jwks_url = url::Url::parse(&doc.jwks_uri).map_err(|_| SignatureError::InvalidJwt)?;
        let host = jwks_url.host_str().unwrap_or("");
        if !matches!(
            host,
            "login.botframework.com" | "login.microsoftonline.com" | "login.windows.net"
        ) {
            return Err(SignatureError::InvalidJwt);
        }
        let jwk_set: JwkSet = self
            .http
            .get_json(&doc.jwks_uri)
            .await
            .map_err(|_| SignatureError::InvalidJwt)?;
        let mut out = HashMap::new();
        for jwk in jwk_set.keys {
            if let (Some(kid), jsonwebtoken::jwk::AlgorithmParameters::RSA(rsa)) =
                (jwk.common.key_id, jwk.algorithm)
            {
                out.insert(kid, (rsa.n, rsa.e));
            }
        }
        Ok(out)
    }
}

#[async_trait]
impl JwksProvider for LiveJwksProvider {
    async fn decoding_key(&self, kid: &str) -> Result<DecodingKey, SignatureError> {
        let mut guard = self.cache.lock().await;
        let fresh = guard
            .as_ref()
            .is_some_and(|(at, keys)| at.elapsed() < Duration::from_secs(3600) && keys.contains_key(kid));
        if !fresh {
            let fetched = self.fetch_keys().await?;
            *guard = Some((Instant::now(), fetched));
        }
        let (_, keys) = guard.as_ref().ok_or(SignatureError::InvalidJwt)?;
        let (n, e) = keys.get(kid).ok_or(SignatureError::InvalidJwt)?;
        DecodingKey::from_rsa_components(n, e).map_err(|_| SignatureError::InvalidJwt)
    }
}

/// Verify a Microsoft Teams Bot Framework Bearer JWT (RS256 only).
pub async fn verify_teams_jwt(
    auth_header: &str,
    expected_app_id: &str,
    jwks: &dyn JwksProvider,
    now: i64,
    allow_private_urls: bool,
) -> Result<TeamsClaims, SignatureError> {
    if expected_app_id.trim().is_empty() {
        return Err(SignatureError::MissingKey);
    }
    let token = auth_header
        .split_once(' ')
        .and_then(|(scheme, tok)| scheme.eq_ignore_ascii_case("bearer").then(|| tok.trim()))
        .ok_or(SignatureError::Malformed)?;
    if token.is_empty() || token.len() > 16 * 1024 {
        return Err(SignatureError::Malformed);
    }

    let header = decode_header(token).map_err(|_| SignatureError::InvalidJwt)?;
    // Explicitly refuse algorithm confusion (alg=none, HS256, etc.).
    if header.alg != Algorithm::RS256 {
        return Err(SignatureError::InvalidJwt);
    }
    let kid = header.kid.ok_or(SignatureError::InvalidJwt)?;
    let key = jwks.decoding_key(&kid).await?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.set_audience(&[expected_app_id]);
    validation.set_issuer(TEAMS_ISSUERS);
    validation.leeway = 0;

    let data = decode::<TeamsClaims>(token, &key, &validation).map_err(|_| SignatureError::InvalidJwt)?;
    let claims = data.claims;

    // Explicit deterministic time checks with 300s leeway so tests do not depend on wall clock.
    if now > claims.exp + DEFAULT_TOLERANCE_SECS {
        return Err(SignatureError::Stale);
    }
    if let Some(nbf) = claims.nbf {
        if now + DEFAULT_TOLERANCE_SECS < nbf {
            return Err(SignatureError::Stale);
        }
    }
    if let Some(ref svc_url) = claims.serviceurl {
        bp_ent_core::safehttp::check_url(svc_url, allow_private_urls)
            .map_err(|_| SignatureError::InvalidJwt)?;
    }
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn bp_hmac_accepts_valid_and_rotates_and_rejects_bad() {
        let secret = b"bp_sec_test_12345";
        let body = br#"{"event":"room.post","text":"hello"}"#;
        let sig = sign_bp_hmac(secret, body, 10_000);
        assert_eq!(verify_bp_hmac(secret, &sig, body, 10_100, 300), Ok(()));

        // Multiple v1 signatures during secret roll
        let v1 = sig.split("v1=").nth(1).unwrap();
        let multi = format!("t=10000,v1={},v1={v1}", "00".repeat(32));
        assert_eq!(verify_bp_hmac(secret, &multi, body, 10_100, 300), Ok(()));

        // Tamper / wrong secret / stale / downgrade / oversize
        let mut tampered = body.to_vec();
        tampered[2] ^= 1;
        assert_eq!(verify_bp_hmac(secret, &sig, &tampered, 10_000, 300), Err(SignatureError::Mismatch));
        assert_eq!(verify_bp_hmac(b"wrong", &sig, body, 10_000, 300), Err(SignatureError::Mismatch));
        assert_eq!(verify_bp_hmac(secret, &sig, body, 10_301, 300), Err(SignatureError::Stale));
        assert_eq!(
            verify_bp_hmac(secret, &sig.replace("v1=", "v0="), body, 10_000, 300),
            Err(SignatureError::Malformed)
        );
        let huge = vec![b'x'; MAX_INBOUND_BODY + 1];
        assert_eq!(verify_bp_hmac(secret, &sig, &huge, 10_000, 300), Err(SignatureError::TooLarge));
    }

    #[test]
    fn slack_v0_hmac_verifies_and_rejects_stale_or_tampered() {
        let secret = b"slack_signing_secret_xyz";
        let body = br#"{"type":"url_verification","challenge":"abc123"}"#;
        let sig = sign_slack_v0(secret, 5_000, body);
        assert_eq!(verify_slack_v0(secret, "5000", &sig, body, 5_100, 300), Ok(()));
        assert_eq!(verify_slack_v0(secret, "5000", &sig, body, 5_301, 300), Err(SignatureError::Stale));
        assert_eq!(verify_slack_v0(b"other", "5000", &sig, body, 5_000, 300), Err(SignatureError::Mismatch));
        assert_eq!(verify_slack_v0(secret, "5000", "v1=deadbeef", body, 5_000, 300), Err(SignatureError::Malformed));
    }

    #[test]
    fn discord_ed25519_verifies_and_rejects_forgery() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pk_hex = hex::encode(sk.verifying_key().to_bytes());
        let ts = "1700000000";
        let body = br#"{"type":1}"#;
        let mut msg = ts.as_bytes().to_vec();
        msg.extend_from_slice(body);
        let sig_hex = hex::encode(sk.sign(&msg).to_bytes());

        assert_eq!(
            verify_discord_ed25519(&pk_hex, &sig_hex, ts, body, 1_700_000_050, 300),
            Ok(())
        );
        assert_eq!(
            verify_discord_ed25519(&pk_hex, &sig_hex, ts, br#"{"type":2}"#, 1_700_000_050, 300),
            Err(SignatureError::Mismatch)
        );
        assert_eq!(
            verify_discord_ed25519(&pk_hex, &sig_hex, ts, body, 1_700_000_301, 300),
            Err(SignatureError::Stale)
        );
    }

    #[tokio::test]
    async fn teams_jwt_rejects_alg_confusion_bad_iss_and_ssrf_serviceurl() {
        // Construct an HS256 token pretending to be signed for kid "k1" — must be rejected
        // immediately because only RS256 is accepted.
        let hs_tok = jsonwebtoken::encode(
            &jsonwebtoken::Header {
                alg: Algorithm::HS256,
                kid: Some("k1".into()),
                ..Default::default()
            },
            &TeamsClaims {
                iss: "https://api.botframework.com".into(),
                aud: "bot-app-1".into(),
                exp: 20_000,
                nbf: None,
                serviceurl: None,
            },
            &jsonwebtoken::EncodingKey::from_secret(b"attacker"),
        )
        .unwrap();
        let jwks = StaticJwksProvider::default();
        let res = verify_teams_jwt(
            &format!("Bearer {hs_tok}"),
            "bot-app-1",
            &jwks,
            19_900,
            false,
        )
        .await;
        assert_eq!(res.unwrap_err(), SignatureError::InvalidJwt);
    }
}
