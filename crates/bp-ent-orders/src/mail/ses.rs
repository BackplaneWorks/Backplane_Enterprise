//! AWS SES (v2 API) sender, for organisations without a connected mailbox.
//!
//! A small SigV4 signer over `hmac`/`sha2` instead of the AWS SDK: one call,
//! no extra dependency tree. Credentials come from the standard environment
//! variables or, on ECS/Fargate, from the task-role credentials endpoint.

use super::{validate_address, OutboundMessage};
use crate::net::{self, NetError};
use bp_ent_core::Secret;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

pub struct AwsCredentials {
    pub access_key_id: String,
    pub secret_access_key: Secret<String>,
    pub session_token: Option<Secret<String>>,
}

#[derive(Clone)]
pub struct Ses {
    http: reqwest::Client,
    region: String,
    from: String,
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("hmac key");
    m.update(data);
    m.finalize().into_bytes().to_vec()
}

/// One request to sign. `headers` must be lower-case names, sorted, and
/// include `host` and `x-amz-date`.
pub struct SignInput<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub query: &'a str,
    pub headers: &'a [(&'a str, &'a str)],
    pub payload: &'a [u8],
    pub region: &'a str,
    pub service: &'a str,
    /// `YYYYMMDDTHHMMSSZ`
    pub amz_date: &'a str,
}

/// AWS Signature Version 4: returns the `Authorization` header value.
pub fn sigv4_authorization(access_key_id: &str, secret_access_key: &str, i: &SignInput<'_>) -> String {
    let date = &i.amz_date[..8];
    let canonical_headers: String = i.headers.iter().map(|(k, v)| format!("{k}:{}\n", v.trim())).collect();
    let signed_headers = i.headers.iter().map(|(k, _)| *k).collect::<Vec<_>>().join(";");
    let canonical = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        i.method,
        i.path,
        i.query,
        canonical_headers,
        signed_headers,
        hex::encode(Sha256::digest(i.payload))
    );
    let scope = format!("{date}/{}/{}/aws4_request", i.region, i.service);
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{scope}\n{}",
        i.amz_date,
        hex::encode(Sha256::digest(canonical.as_bytes()))
    );
    let k_date = hmac(format!("AWS4{secret_access_key}").as_bytes(), date.as_bytes());
    let k_region = hmac(&k_date, i.region.as_bytes());
    let k_service = hmac(&k_region, i.service.as_bytes());
    let k_signing = hmac(&k_service, b"aws4_request");
    let signature = hex::encode(hmac(&k_signing, to_sign.as_bytes()));
    format!("AWS4-HMAC-SHA256 Credential={access_key_id}/{scope}, SignedHeaders={signed_headers}, Signature={signature}")
}

fn amz_date(now: OffsetDateTime) -> String {
    let n = now.to_offset(time::UtcOffset::UTC);
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        n.year(),
        u8::from(n.month()),
        n.day(),
        n.hour(),
        n.minute(),
        n.second()
    )
}

impl Ses {
    /// `region` like `us-east-1`; `from` must be an identity verified in SES.
    pub fn new(http: reqwest::Client, region: &str, from: &str) -> Option<Self> {
        let region_ok = !region.is_empty()
            && region.len() <= 32
            && region.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        let from = validate_address(from)?;
        region_ok.then(|| Self { http, region: region.to_string(), from })
    }

    /// Environment credentials, else the ECS task-role endpoint.
    async fn credentials(&self) -> Result<AwsCredentials, NetError> {
        if let (Ok(id), Ok(secret)) = (std::env::var("AWS_ACCESS_KEY_ID"), std::env::var("AWS_SECRET_ACCESS_KEY")) {
            if !id.is_empty() && !secret.is_empty() {
                return Ok(AwsCredentials {
                    access_key_id: id,
                    secret_access_key: Secret::new(secret),
                    session_token: std::env::var("AWS_SESSION_TOKEN").ok().filter(|t| !t.is_empty()).map(Secret::new),
                });
            }
        }
        // Fixed link-local address defined by ECS; the path comes from the
        // task environment, not from any request.
        let rel = std::env::var("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI").map_err(|_| NetError::Unauthorized)?;
        if !rel.starts_with('/') || rel.contains("..") || rel.contains('@') {
            return Err(NetError::Unauthorized);
        }
        #[derive(Deserialize)]
        struct C {
            #[serde(rename = "AccessKeyId")]
            id: String,
            #[serde(rename = "SecretAccessKey")]
            secret: String,
            #[serde(rename = "Token")]
            token: Option<String>,
        }
        // The one plain-http call in the crate: its own client, so the main
        // one can stay https-only.
        let c: C = net::send_json(net::client(false).get(format!("http://169.254.170.2{rel}")), 16 * 1024).await?;
        Ok(AwsCredentials {
            access_key_id: c.id,
            secret_access_key: Secret::new(c.secret),
            session_token: c.token.map(Secret::new),
        })
    }

    pub async fn send(&self, msg: &OutboundMessage) -> Result<(), NetError> {
        let to = validate_address(&msg.to).ok_or(NetError::Decode)?;
        let creds = self.credentials().await?;
        let body = serde_json::to_vec(&serde_json::json!({
            "FromEmailAddress": self.from,
            "Destination": { "ToAddresses": [to] },
            "Content": { "Simple": {
                "Subject": { "Data": super::sanitize::clean_header(&msg.subject), "Charset": "UTF-8" },
                "Body": { "Text": { "Data": msg.text, "Charset": "UTF-8" } }
            } }
        }))
        .map_err(|_| NetError::Decode)?;
        let host = format!("email.{}.amazonaws.com", self.region);
        let path = "/v2/email/outbound-emails";
        let date = amz_date(OffsetDateTime::now_utc());
        let token = creds.session_token.as_ref().map(|t| t.expose().clone());
        let mut headers: Vec<(&str, &str)> =
            vec![("content-type", "application/json"), ("host", host.as_str()), ("x-amz-date", date.as_str())];
        if let Some(t) = token.as_deref() {
            headers.push(("x-amz-security-token", t));
        }
        let auth = sigv4_authorization(
            &creds.access_key_id,
            creds.secret_access_key.expose(),
            &SignInput {
                method: "POST",
                path,
                query: "",
                headers: &headers,
                payload: &body,
                region: &self.region,
                service: "ses",
                amz_date: &date,
            },
        );
        let mut req = self
            .http
            .post(format!("https://{host}{path}"))
            .header("content-type", "application/json")
            .header("x-amz-date", &date)
            .header("authorization", auth)
            .body(body);
        if let Some(t) = token.as_deref() {
            req = req.header("x-amz-security-token", t);
        }
        net::send_bytes(req, 64 * 1024).await.map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The worked example from the AWS SigV4 documentation.
    #[test]
    fn sigv4_matches_aws_documented_example() {
        let auth = sigv4_authorization(
            "AKIDEXAMPLE",
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            &SignInput {
                method: "GET",
                path: "/",
                query: "Action=ListUsers&Version=2010-05-08",
                headers: &[
                    ("content-type", "application/x-www-form-urlencoded; charset=utf-8"),
                    ("host", "iam.amazonaws.com"),
                    ("x-amz-date", "20150830T123600Z"),
                ],
                payload: b"",
                region: "us-east-1",
                service: "iam",
                amz_date: "20150830T123600Z",
            },
        );
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, \
             SignedHeaders=content-type;host;x-amz-date, \
             Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
        );
    }

    #[test]
    fn rejects_bad_region_and_sender() {
        let http = crate::net::client(true);
        assert!(Ses::new(http.clone(), "us-east-1", "orders@example.com").is_some());
        assert!(Ses::new(http.clone(), "us-east-1.evil.com/", "orders@example.com").is_none());
        assert!(Ses::new(http.clone(), "", "orders@example.com").is_none());
        assert!(Ses::new(http, "us-east-1", "Orders <o@example.com>").is_none());
    }

    #[test]
    fn amz_date_format() {
        let t = OffsetDateTime::from_unix_timestamp(1_440_938_160).unwrap();
        assert_eq!(amz_date(t), "20150830T123600Z");
    }
}
