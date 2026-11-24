//! OpenID Connect relying party (authorization code flow + PKCE), used for
//! Google Workspace, Microsoft Entra ID and any standards-compliant IdP.
//!
//! Every network fetch goes through `SafeHttp`. ID tokens are verified
//! against the issuer's published keys: signature, `iss`, `aud`, `exp`,
//! `nonce`, with an explicit allowlist of asymmetric algorithms.

use base64::Engine;
use bp_ent_core::{Error, Result, SafeHttp};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const CACHE_TTL: Duration = Duration::from_secs(3600);
/// Asymmetric only: `none` and the HMAC family (where the "public" key would
/// double as the secret) are never accepted.
const ALGS: [Algorithm; 7] = [
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::ES256,
    Algorithm::ES384,
];

#[derive(Clone, Debug, Deserialize)]
pub struct Discovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
}

/// The claims we use. Everything else in the token is ignored.
#[derive(Clone, Debug, Deserialize)]
pub struct IdClaims {
    pub sub: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: Option<serde_json::Value>,
    #[serde(default)]
    pub preferred_username: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub nonce: Option<String>,
    /// Google Workspace hosted domain.
    #[serde(default)]
    pub hd: Option<String>,
    /// Microsoft Entra tenant id.
    #[serde(default)]
    pub tid: Option<String>,
}

impl IdClaims {
    /// Some IdPs send `"true"` as a string.
    pub fn email_verified(&self) -> Option<bool> {
        match &self.email_verified {
            Some(serde_json::Value::Bool(b)) => Some(*b),
            Some(serde_json::Value::String(s)) => Some(s == "true"),
            _ => None,
        }
    }
}

type ProviderCache = HashMap<String, (Instant, Discovery, Arc<JwkSet>)>;

#[derive(Clone, Default)]
pub struct OidcClient {
    cache: Arc<Mutex<ProviderCache>>,
}

pub fn pkce_challenge(verifier: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

impl OidcClient {
    /// Discovery document + signing keys for an issuer (cached for an hour).
    pub async fn provider(&self, http: &SafeHttp, issuer: &str) -> Result<(Discovery, Arc<JwkSet>)> {
        self.provider_inner(http, issuer, false).await
    }

    async fn provider_inner(&self, http: &SafeHttp, issuer: &str, force: bool) -> Result<(Discovery, Arc<JwkSet>)> {
        let issuer = issuer.trim_end_matches('/');
        if !force {
            if let Some((at, d, k)) = self.cache.lock().unwrap().get(issuer) {
                if at.elapsed() < CACHE_TTL {
                    return Ok((d.clone(), k.clone()));
                }
            }
        }
        let disco: Discovery = http.get_json(&format!("{issuer}/.well-known/openid-configuration")).await?;
        // The document must speak for the issuer we asked for (mix-up defence).
        if disco.issuer.trim_end_matches('/') != issuer {
            return Err(Error::upstream(anyhow::anyhow!("discovery document names a different issuer")));
        }
        for u in [&disco.authorization_endpoint, &disco.token_endpoint, &disco.jwks_uri] {
            http.check_url(u).map_err(|_| Error::upstream(anyhow::anyhow!("issuer publishes an endpoint that is not allowed")))?;
        }
        let jwks: JwkSet = http.get_json(&disco.jwks_uri).await?;
        let jwks = Arc::new(jwks);
        self.cache.lock().unwrap().insert(issuer.to_string(), (Instant::now(), disco.clone(), jwks.clone()));
        Ok((disco, jwks))
    }

    /// The URL to send the browser to.
    #[allow(clippy::too_many_arguments)]
    pub fn authorize_url(
        disco: &Discovery,
        client_id: &str,
        redirect_uri: &str,
        state: &str,
        nonce: &str,
        pkce_verifier: &str,
        hosted_domain: Option<&str>,
    ) -> Result<String> {
        let mut u = url::Url::parse(&disco.authorization_endpoint).map_err(Error::upstream)?;
        {
            let mut q = u.query_pairs_mut();
            q.append_pair("response_type", "code")
                .append_pair("client_id", client_id)
                .append_pair("redirect_uri", redirect_uri)
                .append_pair("scope", "openid email profile")
                .append_pair("state", state)
                .append_pair("nonce", nonce)
                .append_pair("code_challenge", &pkce_challenge(pkce_verifier))
                .append_pair("code_challenge_method", "S256")
                .append_pair("prompt", "select_account");
            if let Some(hd) = hosted_domain {
                q.append_pair("hd", hd);
            }
        }
        Ok(u.into())
    }

    /// Exchange the authorization code and return the verified ID token claims.
    #[allow(clippy::too_many_arguments)]
    pub async fn exchange(
        &self,
        http: &SafeHttp,
        issuer: &str,
        client_id: &str,
        client_secret: &str,
        redirect_uri: &str,
        code: &str,
        pkce_verifier: &str,
        nonce: &str,
    ) -> Result<IdClaims> {
        #[derive(Deserialize)]
        struct TokenResponse {
            id_token: Option<String>,
        }
        let (disco, jwks) = self.provider(http, issuer).await?;
        let form = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("code_verifier", pkce_verifier),
        ];
        let body = url::form_urlencoded::Serializer::new(String::new()).extend_pairs(form).finish();
        let req = http
            .post(&disco.token_endpoint)?
            .header("content-type", "application/x-www-form-urlencoded")
            .header("accept", "application/json")
            .body(body);
        let (status, bytes) = http.fetch(req, 256 * 1024).await?;
        if !status.is_success() {
            // The body may echo the code or secret back: log the status only.
            return Err(Error::upstream(anyhow::anyhow!("token endpoint answered {status}")));
        }
        let tr: TokenResponse = serde_json::from_slice(&bytes).map_err(|_| Error::upstream(anyhow::anyhow!("token endpoint sent invalid JSON")))?;
        let id_token = tr.id_token.ok_or_else(|| Error::upstream(anyhow::anyhow!("token endpoint sent no id_token")))?;

        let claims = match verify_id_token(&id_token, &jwks, &disco.issuer, client_id, nonce) {
            Ok(c) => c,
            Err(VerifyError::UnknownKey) => {
                // The IdP may have rotated its keys since we cached them.
                let (disco, jwks) = self.provider_inner(http, issuer, true).await?;
                verify_id_token(&id_token, &jwks, &disco.issuer, client_id, nonce).map_err(|_| Error::Unauthorized)?
            }
            Err(VerifyError::Invalid) => return Err(Error::Unauthorized),
        };
        Ok(claims)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
    UnknownKey,
    Invalid,
}

/// Verify an ID token: allowed algorithm, signature by one of the issuer's
/// keys, issuer, audience, expiry and nonce.
pub fn verify_id_token(token: &str, jwks: &JwkSet, issuer: &str, client_id: &str, nonce: &str) -> std::result::Result<IdClaims, VerifyError> {
    let header = jsonwebtoken::decode_header(token).map_err(|_| VerifyError::Invalid)?;
    if !ALGS.contains(&header.alg) {
        return Err(VerifyError::Invalid);
    }
    let jwk = match &header.kid {
        Some(kid) => jwks.find(kid).ok_or(VerifyError::UnknownKey)?,
        // No kid: only unambiguous if the issuer publishes a single key.
        None if jwks.keys.len() == 1 => &jwks.keys[0],
        None => return Err(VerifyError::Invalid),
    };
    let key = DecodingKey::from_jwk(jwk).map_err(|_| VerifyError::Invalid)?;
    let mut v = Validation::new(header.alg);
    v.set_audience(&[client_id]);
    v.set_issuer(&[issuer, issuer.trim_end_matches('/')]);
    v.set_required_spec_claims(&["exp", "aud", "iss", "sub"]);
    v.leeway = 60;
    let data = jsonwebtoken::decode::<IdClaims>(token, &key, &v).map_err(|_| VerifyError::Invalid)?;
    let claims = data.claims;
    let nonce_ok = claims.nonce.as_deref().map(|n| bp_ent_core::crypto::ct_eq(n.as_bytes(), nonce.as_bytes())).unwrap_or(false);
    if !nonce_ok || claims.sub.is_empty() || claims.sub.len() > 255 {
        return Err(VerifyError::Invalid);
    }
    Ok(claims)
}
