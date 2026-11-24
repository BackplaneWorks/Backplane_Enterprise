//! Google (Gmail API) and Microsoft 365 (Graph API) mail connectors.
//!
//! - [`oauth`]: authorisation-code + PKCE flow and refresh-token exchange.
//! - [`google`], [`microsoft`]: list / fetch / send against each API.
//! - [`sanitize`]: untrusted content → bounded plain text.
//! - [`parser`]: plain text → a status *proposal*.
//! - [`notify`]: outbound order status messages.
//! - [`ses`]: AWS SES sender for orgs without a connected mailbox.

pub mod google;
pub mod microsoft;
pub mod notify;
pub mod oauth;
pub mod parser;
pub mod sanitize;
pub mod ses;

use crate::net::NetError;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Hard caps on one sync pass.
pub const MAX_MESSAGES_PER_SYNC: usize = 50;
/// Largest API response we will read for a single message.
pub const MAX_MESSAGE_RESPONSE: usize = 4 * 1024 * 1024;
pub const MAX_ATTACHMENTS_LISTED: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    Google,
    Microsoft,
}

impl Provider {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Google => "google",
            Self::Microsoft => "microsoft",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "google" | "gmail" => Some(Self::Google),
            "microsoft" | "microsoft_graph" | "outlook" => Some(Self::Microsoft),
            _ => None,
        }
    }
    /// authserv-ids whose `Authentication-Results` we trust for this mailbox.
    pub fn trusted_authserv(self) -> &'static [&'static str] {
        match self {
            Self::Google => &["mx.google.com"],
            // Exchange Online stamps the header without an authserv-id ("").
            Self::Microsoft => &["", "*.outlook.com"],
        }
    }
}

/// Name, type and size of an attachment. Attachment bytes are never
/// downloaded, parsed or executed by the ingestion path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentMeta {
    pub name: String,
    pub media_type: String,
    pub size: u64,
}

/// One fetched message, already sanitised: every string is bounded plain text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundMessage {
    pub id: String,
    pub from: String,
    pub subject: String,
    pub text: String,
    pub received_at: OffsetDateTime,
    /// The topmost `Authentication-Results` header, if any.
    pub authentication_results: Option<String>,
    pub attachments: Vec<AttachmentMeta>,
}

/// A plain-text message to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundMessage {
    pub to: String,
    pub subject: String,
    pub text: String,
}

/// A mailbox API. `access_token` is a short-lived OAuth access token.
#[async_trait::async_trait]
pub trait Mailbox: Send + Sync {
    /// The mailbox's own address.
    async fn address(&self, access_token: &str) -> Result<String, NetError>;
    /// Ids of messages received at or after `since`, at most `max`.
    async fn list_since(&self, access_token: &str, since: OffsetDateTime, max: usize) -> Result<Vec<String>, NetError>;
    async fn fetch(&self, access_token: &str, id: &str) -> Result<InboundMessage, NetError>;
    async fn send(&self, access_token: &str, msg: &OutboundMessage) -> Result<(), NetError>;
}

/// Validate a single recipient address for outbound mail. Strict on purpose:
/// plain `local@domain`, ASCII, no display name, no comments, no line breaks,
/// nothing that could add a header or a second recipient.
pub fn validate_address(addr: &str) -> Option<String> {
    let a = addr.trim();
    if a.len() > 254 || a.len() < 3 {
        return None;
    }
    let (local, domain) = a.split_once('@')?;
    let local_ok = !local.is_empty()
        && local.len() <= 64
        && !local.starts_with('.')
        && !local.ends_with('.')
        && !local.contains("..")
        && local.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+/=?^_`{|}~.-".contains(&b));
    if !local_ok || parser::sender_domain(&format!("x@{domain}")).is_none() {
        return None;
    }
    Some(format!("{local}@{}", domain.to_ascii_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_validation_blocks_injection() {
        assert_eq!(validate_address(" Buyer@Example.COM ").as_deref(), Some("Buyer@example.com"));
        for bad in [
            "",
            "a@b",
            "a b@example.com",
            "a@example.com\r\nBcc: x@evil.com",
            "a@example.com, b@evil.com",
            "Name <a@example.com>",
            "a@example.com>",
            "\"a\"@example.com",
            "a@@example.com",
            ".a@example.com",
            "a..b@example.com",
            "a@exa mple.com",
            "é@example.com",
        ] {
            assert_eq!(validate_address(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn provider_names() {
        assert_eq!(Provider::parse("gmail"), Some(Provider::Google));
        assert_eq!(Provider::parse("microsoft_graph"), Some(Provider::Microsoft));
        assert_eq!(Provider::parse("yahoo"), None);
    }
}
