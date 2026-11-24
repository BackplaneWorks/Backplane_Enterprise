//! Domain models, public tenant-bound bridge IDs, and untrusted text sanitization.

use bp_ent_core::{Error, Result, TenantId};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Supported external bridge adapters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeKind {
    Webhook,
    Slack,
    Teams,
    Discord,
    A2a,
}

impl BridgeKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            BridgeKind::Webhook => "webhook",
            BridgeKind::Slack => "slack",
            BridgeKind::Teams => "teams",
            BridgeKind::Discord => "discord",
            BridgeKind::A2a => "a2a",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "webhook" => Ok(BridgeKind::Webhook),
            "slack" => Ok(BridgeKind::Slack),
            "teams" => Ok(BridgeKind::Teams),
            "discord" => Ok(BridgeKind::Discord),
            "a2a" => Ok(BridgeKind::A2a),
            _ => Err(Error::invalid("unknown bridge kind")),
        }
    }
}

/// Allowed traffic direction for a bridge.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeDirection {
    Inbound,
    Outbound,
    Bidirectional,
}

impl BridgeDirection {
    pub fn as_str(&self) -> &'static str {
        match self {
            BridgeDirection::Inbound => "inbound",
            BridgeDirection::Outbound => "outbound",
            BridgeDirection::Bidirectional => "bidirectional",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "inbound" => Ok(BridgeDirection::Inbound),
            "outbound" => Ok(BridgeDirection::Outbound),
            "bidirectional" => Ok(BridgeDirection::Bidirectional),
            _ => Err(Error::invalid("unknown bridge direction")),
        }
    }

    pub fn allows_inbound(&self) -> bool {
        matches!(self, BridgeDirection::Inbound | BridgeDirection::Bidirectional)
    }

    pub fn allows_outbound(&self) -> bool {
        matches!(self, BridgeDirection::Outbound | BridgeDirection::Bidirectional)
    }
}

/// Canonical outbound event names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BridgeEventKind {
    #[serde(rename = "room.post")]
    RoomPost,
    #[serde(rename = "bot.reply")]
    BotReply,
    #[serde(rename = "ask.opened")]
    AskOpened,
    #[serde(rename = "order.status_changed")]
    OrderStatusChanged,
    #[serde(rename = "release.published")]
    ReleasePublished,
}

impl BridgeEventKind {
    pub const ALL: [BridgeEventKind; 5] = [
        BridgeEventKind::RoomPost,
        BridgeEventKind::BotReply,
        BridgeEventKind::AskOpened,
        BridgeEventKind::OrderStatusChanged,
        BridgeEventKind::ReleasePublished,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            BridgeEventKind::RoomPost => "room.post",
            BridgeEventKind::BotReply => "bot.reply",
            BridgeEventKind::AskOpened => "ask.opened",
            BridgeEventKind::OrderStatusChanged => "order.status_changed",
            BridgeEventKind::ReleasePublished => "release.published",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|k| k.as_str() == s)
            .ok_or_else(|| Error::invalid("unsupported bridge event type"))
    }
}

/// Outbound event payload carrying ONLY the declared allowlisted fields
/// (never secrets, DEKs, raw BOMs, or email bodies).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum BridgeEvent {
    #[serde(rename = "room.post")]
    RoomPost {
        #[serde(rename = "roomId")]
        room_id: String,
        #[serde(rename = "postId")]
        post_id: String,
        #[serde(rename = "authorDisplay")]
        author_display: String,
        summary: String,
        #[serde(default)]
        tags: Vec<String>,
    },
    #[serde(rename = "bot.reply")]
    BotReply {
        #[serde(rename = "roomId")]
        room_id: String,
        #[serde(rename = "replyToPostId")]
        reply_to_post_id: String,
        #[serde(rename = "botName")]
        bot_name: String,
        summary: String,
    },
    #[serde(rename = "ask.opened")]
    AskOpened {
        #[serde(rename = "askId")]
        ask_id: String,
        title: String,
        #[serde(rename = "requesterDisplay")]
        requester_display: String,
        summary: String,
    },
    #[serde(rename = "order.status_changed")]
    OrderStatusChanged {
        #[serde(rename = "orderRef")]
        order_ref: String,
        #[serde(rename = "fromStatus")]
        from_status: String,
        #[serde(rename = "toStatus")]
        to_status: String,
        #[serde(rename = "updatedAt")]
        updated_at: String,
    },
    #[serde(rename = "release.published")]
    ReleasePublished {
        #[serde(rename = "boardSlug")]
        board_slug: String,
        #[serde(rename = "revisionTag")]
        revision_tag: String,
        summary: String,
        #[serde(rename = "publishedByDisplay")]
        published_by_display: String,
    },
}

impl BridgeEvent {
    pub fn kind(&self) -> BridgeEventKind {
        match self {
            BridgeEvent::RoomPost { .. } => BridgeEventKind::RoomPost,
            BridgeEvent::BotReply { .. } => BridgeEventKind::BotReply,
            BridgeEvent::AskOpened { .. } => BridgeEventKind::AskOpened,
            BridgeEvent::OrderStatusChanged { .. } => BridgeEventKind::OrderStatusChanged,
            BridgeEvent::ReleasePublished { .. } => BridgeEventKind::ReleasePublished,
        }
    }

    pub fn summary_line(&self) -> String {
        match self {
            BridgeEvent::RoomPost { room_id, author_display, summary, .. } => {
                format!("[room.post] {author_display} in {room_id}: {summary}")
            }
            BridgeEvent::BotReply { room_id, bot_name, summary, .. } => {
                format!("[bot.reply] {bot_name} in {room_id}: {summary}")
            }
            BridgeEvent::AskOpened { ask_id, title, requester_display, summary } => {
                format!("[ask.opened] {ask_id} ({title}) by {requester_display}: {summary}")
            }
            BridgeEvent::OrderStatusChanged { order_ref, from_status, to_status, .. } => {
                format!("[order.status_changed] {order_ref}: {from_status} -> {to_status}")
            }
            BridgeEvent::ReleasePublished { board_slug, revision_tag, published_by_display, summary } => {
                format!("[release.published] {board_slug} {revision_tag} by {published_by_display}: {summary}")
            }
        }
    }
}

/// Public tenant-bound bridge identifier: `bpb_<tenant_hex_32>_<bridge_hex_32>`.
///
/// The tenant hex is a routing claim only: database queries always run inside
/// `db.tenant_tx(tenant_id)` under forced PostgreSQL RLS, so a forged tenant
/// prefix matches nothing and returns `401 Unauthorized`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BridgePublicId {
    pub tenant_id: TenantId,
    pub bridge_id: Uuid,
}

impl BridgePublicId {
    pub fn format(&self) -> String {
        format!("bpb_{}_{}", self.tenant_id.0.simple(), self.bridge_id.simple())
    }

    pub fn parse(raw: &str) -> Option<Self> {
        let mut parts = raw.split('_');
        if parts.next()? != "bpb" {
            return None;
        }
        let tenant_hex = parts.next()?;
        let bridge_hex = parts.next()?;
        if parts.next().is_some() || tenant_hex.len() != 32 || bridge_hex.len() != 32 {
            return None;
        }
        let tenant_uuid = Uuid::try_parse(tenant_hex).ok()?;
        let bridge_uuid = Uuid::try_parse(bridge_hex).ok()?;
        Some(Self {
            tenant_id: TenantId(tenant_uuid),
            bridge_id: bridge_uuid,
        })
    }
}

/// Adapter-specific configuration, envelope-encrypted at rest.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdapterConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slack_channel: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discord_public_key_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discord_application_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub teams_app_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub teams_service_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub a2a_agent_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub a2a_agent_url: Option<String>,
}

/// Safe public view of a bridge (never contains raw secrets).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BridgeView {
    pub id: Uuid,
    pub public_id: String,
    pub name: String,
    pub kind: BridgeKind,
    pub enabled: bool,
    pub direction: BridgeDirection,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_url: Option<String>,
    pub subscribed_events: Vec<String>,
    pub secret_hint: String,
    pub rate_limit_rpm: i32,
    pub peer_enabled: bool,
    pub peer_scopes: Vec<String>,
    pub inbound_path: String,
    pub a2a_path: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateBridgeRequest {
    pub name: String,
    pub kind: BridgeKind,
    #[serde(default = "default_direction")]
    pub direction: BridgeDirection,
    #[serde(default)]
    pub target_url: Option<String>,
    #[serde(default)]
    pub subscribed_events: Vec<String>,
    #[serde(default = "default_rpm")]
    pub rate_limit_rpm: i32,
    #[serde(default)]
    pub peer_enabled: bool,
    #[serde(default)]
    pub peer_scopes: Vec<String>,
    /// Optional caller-supplied signing secret (e.g. Slack Signing Secret).
    /// When omitted, a cryptographically random 256-bit secret is generated.
    #[serde(default)]
    pub inbound_signing_secret: Option<String>,
    #[serde(default)]
    pub adapter_config: AdapterConfig,
}

fn default_direction() -> BridgeDirection {
    BridgeDirection::Bidirectional
}

fn default_rpm() -> i32 {
    60
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateBridgeResponse {
    pub bridge: BridgeView,
    /// Shown once upon creation; never stored or returned in plaintext again.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inbound_secret_once: Option<String>,
    /// Shown once upon creation; never stored or returned in plaintext again.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outbound_secret_once: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateBridgeRequest {
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub direction: Option<BridgeDirection>,
    pub target_url: Option<Option<String>>,
    pub subscribed_events: Option<Vec<String>>,
    pub rate_limit_rpm: Option<i32>,
    pub peer_enabled: Option<bool>,
    pub peer_scopes: Option<Vec<String>>,
    pub adapter_config: Option<AdapterConfig>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RotateSecretResponse {
    pub bridge_id: Uuid,
    pub secret_hint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inbound_secret_once: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outbound_secret_once: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeliveryView {
    pub id: Uuid,
    pub bridge_id: Uuid,
    pub direction: String,
    pub delivery_id: String,
    pub event_type: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_status: Option<i16>,
    pub created_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UntrustedExternalMessage {
    pub bridge_id: Uuid,
    pub external_actor: String,
    pub channel_ref: String,
    pub event_type: String,
    pub sanitized_text: String,
    pub trust_level: String,
}

/// Strip HTML tags and control characters from untrusted external text,
/// preserving only printable characters, tabs, and newlines up to `max_len` bytes.
pub fn sanitize_external_text(raw: &str, max_len: usize) -> String {
    let mut no_tags = String::with_capacity(raw.len().min(max_len * 2));
    let mut in_tag = false;
    for ch in raw.chars() {
        match ch {
            '<' => in_tag = true,
            '>' if in_tag => {
                in_tag = false;
                no_tags.push(' ');
            }
            _ if in_tag => {}
            '\n' | '\t' => no_tags.push(ch),
            c if c.is_control() => {}
            c => no_tags.push(c),
        }
    }
    let collapsed: String = no_tags
        .split('\n')
        .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect::<Vec<_>>()
        .join("\n");
    let trimmed = collapsed.trim();
    if trimmed.len() <= max_len {
        return trimmed.to_string();
    }
    let mut end = max_len;
    while !trimmed.is_char_boundary(end) && end > 0 {
        end -= 1;
    }
    trimmed[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_id_round_trips_and_rejects_malformed() {
        let tid = TenantId::new();
        let bid = Uuid::new_v4();
        let pub_id = BridgePublicId { tenant_id: tid, bridge_id: bid };
        let encoded = pub_id.format();
        assert!(encoded.starts_with("bpb_"));
        assert_eq!(BridgePublicId::parse(&encoded), Some(pub_id));

        for bad in [
            "",
            "bpb",
            "bpb_123_456",
            "xxx_00000000000000000000000000000000_00000000000000000000000000000000",
            &format!("{encoded}_extra"),
        ] {
            assert_eq!(BridgePublicId::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn sanitize_strips_html_and_control_chars() {
        let dirty = "<script>alert(1)</script>Hello\x00 <b>World</b>\n\tNext   line";
        let clean = sanitize_external_text(dirty, 200);
        assert_eq!(clean, "alert(1) Hello World\nNext line");
        assert!(!clean.contains('<'));
        assert!(!clean.contains('\x00'));
    }

    #[test]
    fn sanitize_truncates_on_utf8_boundary() {
        let s = "hello 🚀 world";
        let cut = sanitize_external_text(s, 8);
        assert!(cut.len() <= 8);
        assert!(std::str::from_utf8(cut.as_bytes()).is_ok());
    }
}
