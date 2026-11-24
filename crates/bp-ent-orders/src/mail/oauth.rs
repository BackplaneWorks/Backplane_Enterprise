//! OAuth 2.0 for mailbox connections: authorisation code + PKCE (S256), and
//! refresh-token exchange. Tokens are held in [`Secret`] and never logged.

use super::Provider;
use crate::net::{self, Base, NetError};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use bp_ent_core::Secret;
use rand::RngCore;
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// Least privilege: read mail, send mail, and learn the mailbox address.
pub const GOOGLE_SCOPES: &str =
    "https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/gmail.send";
pub const MICROSOFT_SCOPES: &str = "offline_access User.Read Mail.Read Mail.Send";

/// OAuth client registration for one provider.
#[derive(Clone)]
pub struct OAuthClient {
    pub provider: Provider,
    pub client_id: String,
    pub client_secret: Secret<String>,
    pub authorize_url: String,
    pub token_base: Base,
    pub token_path: String,
    pub scopes: &'static str,
}

impl OAuthClient {
    pub fn google(client_id: String, client_secret: Secret<String>) -> Self {
        Self {
            provider: Provider::Google,
            client_id,
            client_secret,
            authorize_url: "https://accounts.google.com/o/oauth2/v2/auth".into(),
            token_base: Base::new("https://oauth2.googleapis.com").expect("static url"),
            token_path: "/token".into(),
            scopes: GOOGLE_SCOPES,
        }
    }

    /// `tenant` is the Entra tenant segment: `common`, `organizations` or a
    /// directory id (letters, digits, `-`, `.` only).
    pub fn microsoft(client_id: String, client_secret: Secret<String>, tenant: &str) -> Self {
        let tenant: String = tenant
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '.')
            .collect();
        let tenant = if tenant.is_empty() { "common".to_string() } else { tenant };
        Self {
            provider: Provider::Microsoft,
            client_id,
            client_secret,
            authorize_url: format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize"),
            token_base: Base::new("https://login.microsoftonline.com").expect("static url"),
            token_path: format!("/{tenant}/oauth2/v2.0/token"),
            scopes: MICROSOFT_SCOPES,
        }
    }

    /// The URL to send the user's browser to.
    pub fn authorize_url(&self, redirect_uri: &str, state: &str, pkce_challenge: &str) -> String {
        let mut q = url::form_urlencoded::Serializer::new(String::new());
        q.append_pair("response_type", "code")
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("scope", self.scopes)
            .append_pair("state", state)
            .append_pair("code_challenge", pkce_challenge)
            .append_pair("code_challenge_method", "S256");
        match self.provider {
            // Needed to get a refresh token from Google every time.
            Provider::Google => {
                q.append_pair("access_type", "offline").append_pair("prompt", "consent");
            }
            Provider::Microsoft => {
                q.append_pair("prompt", "select_account");
            }
        }
        format!("{}?{}", self.authorize_url, q.finish())
    }

    async fn token_request(&self, http: &reqwest::Client, extra: &[(&str, &str)]) -> Result<TokenSet, NetError> {
        let mut form: Vec<(&str, &str)> = vec![
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.expose().as_str()),
        ];
        form.extend_from_slice(extra);
        let body = url::form_urlencoded::Serializer::new(String::new()).extend_pairs(&form).finish();
        let req = http
            .post(self.token_base.join(&self.token_path))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Accept", "application/json")
            .body(body);
        let resp = req.send().await.map_err(|_| NetError::Transport)?;
        let status = resp.status();
        let bytes = net::read_capped(resp, 64 * 1024).await?;
        if !status.is_success() {
            // `invalid_grant` means the refresh token was revoked or expired.
            #[derive(Deserialize)]
            struct E {
                error: Option<String>,
            }
            let revoked = serde_json::from_slice::<E>(&bytes)
                .ok()
                .and_then(|e| e.error)
                .is_some_and(|e| e == "invalid_grant");
            return Err(if revoked || status.as_u16() == 401 {
                NetError::Unauthorized
            } else {
                NetError::Status(status.as_u16())
            });
        }
        let raw: RawTokens = serde_json::from_slice(&bytes).map_err(|_| NetError::Decode)?;
        if raw.access_token.is_empty() {
            return Err(NetError::Decode);
        }
        Ok(TokenSet {
            access_token: Secret::new(raw.access_token),
            refresh_token: raw.refresh_token.filter(|t| !t.is_empty()).map(Secret::new),
            scope: raw.scope.unwrap_or_default(),
        })
    }

    /// Exchange the authorisation code (with the PKCE verifier) for tokens.
    pub async fn exchange_code(
        &self,
        http: &reqwest::Client,
        code: &str,
        redirect_uri: &str,
        pkce_verifier: &str,
    ) -> Result<TokenSet, NetError> {
        self.token_request(
            http,
            &[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", redirect_uri),
                ("code_verifier", pkce_verifier),
            ],
        )
        .await
    }

    /// Get a fresh access token. Microsoft may rotate the refresh token; the
    /// caller must store `refresh_token` when it is `Some`.
    pub async fn refresh(&self, http: &reqwest::Client, refresh_token: &str) -> Result<TokenSet, NetError> {
        self.token_request(http, &[("grant_type", "refresh_token"), ("refresh_token", refresh_token)])
            .await
    }
}

#[derive(Deserialize)]
struct RawTokens {
    access_token: String,
    refresh_token: Option<String>,
    scope: Option<String>,
}

pub struct TokenSet {
    pub access_token: Secret<String>,
    pub refresh_token: Option<Secret<String>>,
    pub scope: String,
}

/// 32 random bytes, base64url: used for both `state` and the PKCE verifier.
pub fn random_token() -> String {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    URL_SAFE_NO_PAD.encode(b)
}

pub fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

pub fn state_hash(state: &str) -> Vec<u8> {
    Sha256::digest(state.as_bytes()).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_matches_rfc7636_vector() {
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn random_tokens_are_long_and_distinct() {
        let (a, b) = (random_token(), random_token());
        assert_eq!(a.len(), 43);
        assert_ne!(a, b);
    }

    #[test]
    fn authorize_url_has_pkce_state_and_least_scopes() {
        let c = OAuthClient::google("cid".into(), Secret::new("sec".to_string()));
        let u = url::Url::parse(&c.authorize_url("https://api.example.com/v1/mail/callback/google", "st&ate", "chal")).unwrap();
        let q: std::collections::HashMap<_, _> = u.query_pairs().into_owned().collect();
        assert_eq!(u.host_str(), Some("accounts.google.com"));
        assert_eq!(q["state"], "st&ate");
        assert_eq!(q["code_challenge_method"], "S256");
        assert_eq!(q["access_type"], "offline");
        assert!(!q["scope"].contains("mail.google.com/"), "full-mailbox scope must not be requested");
        assert!(!u.as_str().contains("sec"));
    }

    #[test]
    fn microsoft_tenant_segment_is_sanitised() {
        let c = OAuthClient::microsoft("cid".into(), Secret::new("s".to_string()), "../evil/?x=");
        assert_eq!(c.token_path, "/..evilx/oauth2/v2.0/token");
        let c = OAuthClient::microsoft("cid".into(), Secret::new("s".to_string()), "");
        assert!(c.authorize_url.contains("/common/"));
    }
}
