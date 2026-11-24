//! Gmail API connector (`gmail.readonly` + `gmail.send`).

use super::sanitize::{clean_header, clean_text, html_to_text, MAX_TEXT_OUTPUT};
use super::{AttachmentMeta, InboundMessage, Mailbox, OutboundMessage, MAX_ATTACHMENTS_LISTED, MAX_MESSAGE_RESPONSE};
use crate::net::{self, Base, NetError};
use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use serde::Deserialize;
use time::OffsetDateTime;

pub const GMAIL_API_BASE: &str = "https://gmail.googleapis.com";

pub struct Gmail {
    http: reqwest::Client,
    base: Base,
}

impl Gmail {
    pub fn new(http: reqwest::Client) -> Self {
        Self { http, base: Base::new(GMAIL_API_BASE).expect("static url") }
    }
    pub fn with_base(http: reqwest::Client, base: Base) -> Self {
        Self { http, base }
    }
}

#[derive(Deserialize)]
struct Profile {
    #[serde(rename = "emailAddress")]
    email_address: String,
}

#[derive(Deserialize)]
struct List {
    #[serde(default)]
    messages: Vec<ListItem>,
}
#[derive(Deserialize)]
struct ListItem {
    id: String,
}

#[derive(Deserialize)]
struct Message {
    id: String,
    #[serde(rename = "internalDate")]
    internal_date: Option<String>,
    payload: Option<Part>,
}

#[derive(Deserialize, Default)]
struct Part {
    #[serde(rename = "mimeType", default)]
    mime_type: String,
    #[serde(default)]
    filename: String,
    #[serde(default)]
    headers: Vec<Header>,
    body: Option<Body>,
    #[serde(default)]
    parts: Vec<Part>,
}
#[derive(Deserialize)]
struct Header {
    name: String,
    value: String,
}
#[derive(Deserialize)]
struct Body {
    #[serde(default)]
    size: u64,
    data: Option<String>,
}

fn b64url(data: &str) -> Option<Vec<u8>> {
    let d = data.trim_end_matches('=');
    URL_SAFE_NO_PAD.decode(d).or_else(|_| URL_SAFE.decode(data)).ok()
}

/// Walk the MIME tree (bounded depth): collect the first text/plain and
/// text/html bodies and the attachment metadata.
fn walk(part: &Part, depth: u8, plain: &mut Option<String>, html: &mut Option<String>, atts: &mut Vec<AttachmentMeta>) {
    if depth > 8 {
        return;
    }
    if !part.filename.is_empty() {
        if atts.len() < MAX_ATTACHMENTS_LISTED {
            atts.push(AttachmentMeta {
                name: clean_header(&part.filename),
                media_type: clean_header(&part.mime_type),
                size: part.body.as_ref().map_or(0, |b| b.size),
            });
        }
        return; // never decode attachment bytes
    }
    let text = |p: &Part| {
        p.body
            .as_ref()
            .and_then(|b| b.data.as_deref())
            .and_then(b64url)
            .map(|raw| String::from_utf8_lossy(&raw).into_owned())
    };
    match part.mime_type.as_str() {
        "text/plain" if plain.is_none() => *plain = text(part),
        "text/html" if html.is_none() => *html = text(part),
        _ => {}
    }
    for p in &part.parts {
        walk(p, depth + 1, plain, html, atts);
    }
}

fn to_inbound(m: Message) -> Result<InboundMessage, NetError> {
    let payload = m.payload.unwrap_or_default();
    let header = |name: &str| {
        payload
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str())
    };
    let (mut plain, mut html, mut attachments) = (None, None, Vec::new());
    walk(&payload, 0, &mut plain, &mut html, &mut attachments);
    // Prefer the plain part; fall back to HTML reduced to text.
    let text = match (plain, html) {
        (Some(p), _) if !p.trim().is_empty() => clean_text(&p, MAX_TEXT_OUTPUT),
        (_, Some(h)) => html_to_text(&h, MAX_TEXT_OUTPUT),
        (Some(p), None) => clean_text(&p, MAX_TEXT_OUTPUT),
        (None, None) => String::new(),
    };
    let ms: i128 = m
        .internal_date
        .as_deref()
        .and_then(|s| s.parse().ok())
        .ok_or(NetError::Decode)?;
    let received_at =
        OffsetDateTime::from_unix_timestamp_nanos(ms * 1_000_000).map_err(|_| NetError::Decode)?;
    Ok(InboundMessage {
        id: m.id,
        from: clean_header(header("From").unwrap_or("")),
        subject: clean_header(header("Subject").unwrap_or("")),
        text,
        received_at,
        // `find` returns the first, i.e. topmost: the one Google stamped.
        authentication_results: header("Authentication-Results").map(clean_header_long),
        attachments,
    })
}

fn clean_header_long(v: &str) -> String {
    let one_line: String = v.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    clean_text(&one_line, 4096)
}

/// RFC 5322 message for `users.messages.send`. Subject is RFC 2047 encoded
/// and the body base64 encoded, so neither can introduce a header.
pub(crate) fn rfc822(msg: &OutboundMessage) -> String {
    let subject = clean_header(&msg.subject);
    let subject_enc = if subject.is_ascii() {
        subject
    } else {
        // One encoded-word per <=45 bytes of UTF-8, split on char boundaries.
        let mut words = Vec::new();
        let mut cur = String::new();
        for ch in subject.chars() {
            if cur.len() + ch.len_utf8() > 45 {
                words.push(format!("=?UTF-8?B?{}?=", STANDARD.encode(&cur)));
                cur.clear();
            }
            cur.push(ch);
        }
        if !cur.is_empty() {
            words.push(format!("=?UTF-8?B?{}?=", STANDARD.encode(&cur)));
        }
        words.join("\r\n ")
    };
    let body64 = STANDARD.encode(msg.text.as_bytes());
    let mut wrapped = String::with_capacity(body64.len() + body64.len() / 38);
    for chunk in body64.as_bytes().chunks(76) {
        wrapped.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        wrapped.push_str("\r\n");
    }
    format!(
        "To: {}\r\nSubject: {}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\nAuto-Submitted: auto-generated\r\n\r\n{}",
        msg.to, subject_enc, wrapped
    )
}

#[async_trait::async_trait]
impl Mailbox for Gmail {
    async fn address(&self, access_token: &str) -> Result<String, NetError> {
        let p: Profile = net::send_json(
            self.http.get(self.base.join("/gmail/v1/users/me/profile")).bearer_auth(access_token),
            64 * 1024,
        )
        .await?;
        super::validate_address(&p.email_address).map(|a| a.to_ascii_lowercase()).ok_or(NetError::Decode)
    }

    async fn list_since(&self, access_token: &str, since: OffsetDateTime, max: usize) -> Result<Vec<String>, NetError> {
        let q = format!("in:inbox after:{}", since.unix_timestamp());
        let l: List = net::send_json(
            self.http
                .get(self.base.join("/gmail/v1/users/me/messages"))
                .query(&[("q", q.as_str()), ("maxResults", &max.min(100).to_string())])
                .bearer_auth(access_token),
            512 * 1024,
        )
        .await?;
        Ok(l.messages.into_iter().take(max).map(|m| m.id).filter(|id| id.len() <= 256).collect())
    }

    async fn fetch(&self, access_token: &str, id: &str) -> Result<InboundMessage, NetError> {
        let m: Message = net::send_json(
            self.http
                .get(self.base.join(&format!("/gmail/v1/users/me/messages/{}", net::seg(id))))
                .query(&[("format", "full")])
                .bearer_auth(access_token),
            MAX_MESSAGE_RESPONSE,
        )
        .await?;
        to_inbound(m)
    }

    async fn send(&self, access_token: &str, msg: &OutboundMessage) -> Result<(), NetError> {
        let to = super::validate_address(&msg.to).ok_or(NetError::Decode)?;
        let raw = URL_SAFE_NO_PAD.encode(rfc822(&OutboundMessage { to, ..msg.clone() }));
        net::send_bytes(
            self.http
                .post(self.base.join("/gmail/v1/users/me/messages/send"))
                .bearer_auth(access_token)
                .json(&serde_json::json!({ "raw": raw })),
            64 * 1024,
        )
        .await
        .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(s: &str) -> String {
        URL_SAFE_NO_PAD.encode(s)
    }

    #[test]
    fn parses_multipart_and_ignores_attachment_bytes() {
        let json = serde_json::json!({
            "id": "m1",
            "internalDate": "1700000000000",
            "payload": {
                "mimeType": "multipart/mixed",
                "headers": [
                    {"name": "From", "value": "Fab <orders@pcbfab.com>"},
                    {"name": "subject", "value": "Order BP-7K2M9QX4TZ has shipped\r\nX-Evil: 1"},
                    {"name": "Authentication-Results", "value": "mx.google.com; dmarc=pass header.from=pcbfab.com"},
                    {"name": "Authentication-Results", "value": "mx.evil.com; dmarc=pass header.from=bank.com"}
                ],
                "parts": [
                    {"mimeType": "multipart/alternative", "parts": [
                        {"mimeType": "text/html", "body": {"size": 10, "data": enc("<p>Shipped <script>x()</script></p>")}}
                    ]},
                    {"mimeType": "application/pdf", "filename": "invoice.pdf", "body": {"size": 4242, "data": enc("%PDF-evil")}}
                ]
            }
        });
        let m = to_inbound(serde_json::from_value(json).unwrap()).unwrap();
        assert_eq!(m.from, "Fab <orders@pcbfab.com>");
        assert_eq!(m.subject, "Order BP-7K2M9QX4TZ has shipped X-Evil: 1");
        assert_eq!(m.text, "Shipped");
        assert_eq!(m.received_at.unix_timestamp(), 1_700_000_000);
        assert!(m.authentication_results.unwrap().starts_with("mx.google.com"));
        assert_eq!(m.attachments, vec![AttachmentMeta { name: "invoice.pdf".into(), media_type: "application/pdf".into(), size: 4242 }]);
    }

    #[test]
    fn deep_nesting_is_bounded() {
        let mut part = serde_json::json!({"mimeType": "text/plain", "body": {"data": enc("deep")}});
        for _ in 0..50 {
            part = serde_json::json!({"mimeType": "multipart/mixed", "parts": [part]});
        }
        let m = to_inbound(
            serde_json::from_value(serde_json::json!({"id": "x", "internalDate": "1", "payload": part})).unwrap(),
        )
        .unwrap();
        assert_eq!(m.text, "");
    }

    #[test]
    fn rfc822_cannot_be_header_injected() {
        let raw = rfc822(&OutboundMessage {
            to: "buyer@example.com".into(),
            subject: "Status\r\nBcc: evil@x.com".into(),
            text: "line1\r\n.\r\nSubject: fake\r\n".into(),
        });
        let (head, body) = raw.split_once("\r\n\r\n").unwrap();
        assert!(!head.contains("\r\nBcc:"));
        assert_eq!(head.lines().filter(|l| l.starts_with("Subject:")).count(), 1);
        assert!(!body.contains("Subject"));
        let non_ascii = rfc822(&OutboundMessage { to: "a@b.co".into(), subject: "Commande expédiée ✓".into(), text: "x".into() });
        assert!(non_ascii.contains("Subject: =?UTF-8?B?"));
        assert!(non_ascii.is_ascii());
    }
}
