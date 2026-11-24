//! Unified BridgeAdapter trait and native adapters for:
//! - Generic Bidirectional Signed Webhook (Dots, Grok, n8n, custom bots)
//! - A2A / MCP Agent Bridge
//! - Slack (Events API v0 HMAC + Block Kit outbound)
//! - Microsoft Teams (Bot Framework RS256 JWT + Adaptive Card outbound)
//! - Discord (Interactions Ed25519 + Webhook Embed outbound)

use crate::model::{
    sanitize_external_text, AdapterConfig, BridgeEvent, BridgeKind,
};
use crate::signatures::{
    sign_bp_hmac, verify_bp_hmac, verify_discord_ed25519, verify_slack_v0, verify_teams_jwt,
    JwksProvider, SignatureError, DEFAULT_TOLERANCE_SECS,
};
use async_trait::async_trait;
use bp_ent_core::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct InboundRawRequest {
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl InboundRawRequest {
    pub fn from_axum(headers: &axum::http::HeaderMap, body: &[u8]) -> Self {
        let mut map = HashMap::new();
        for (k, v) in headers {
            if let Ok(s) = v.to_str() {
                map.insert(k.as_str().to_ascii_lowercase(), s.to_string());
            }
        }
        Self {
            headers: map,
            body: body.to_vec(),
        }
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(&name.to_ascii_lowercase()).map(|s| s.as_str())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProposedAction {
    pub kind: String,
    pub target: String,
    pub summary: String,
}

#[derive(Clone, Debug)]
pub struct NormalizedInbound {
    pub delivery_id: String,
    pub event_type: String,
    pub external_actor: String,
    pub channel_ref: String,
    pub sanitized_text: String,
    pub proposed_action: Option<ProposedAction>,
}

#[derive(Clone, Debug)]
pub enum InboundOutcome {
    /// Protocol handshake challenge (Slack url_verification, Discord PING).
    /// Only emitted AFTER cryptographic signature verification has succeeded.
    Challenge { response_json: Value },
    Event(NormalizedInbound),
}

#[derive(Clone, Debug)]
pub struct OutboundHttpPayload {
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[async_trait]
pub trait BridgeAdapter: Send + Sync {
    fn kind(&self) -> BridgeKind;

    async fn verify_and_parse_inbound(
        &self,
        req: &InboundRawRequest,
        secret: &[u8],
        cfg: &AdapterConfig,
        jwks: &dyn JwksProvider,
        now: i64,
        allow_private_urls: bool,
    ) -> std::result::Result<InboundOutcome, SignatureError>;

    fn format_outbound(
        &self,
        event: &BridgeEvent,
        delivery_id: &str,
        outbound_secret: Option<&[u8]>,
        cfg: &AdapterConfig,
        now: i64,
    ) -> Result<OutboundHttpPayload>;
}

pub fn adapter_for(kind: BridgeKind) -> Box<dyn BridgeAdapter> {
    match kind {
        BridgeKind::Webhook => Box::new(WebhookAdapter { kind: BridgeKind::Webhook }),
        BridgeKind::A2a => Box::new(WebhookAdapter { kind: BridgeKind::A2a }),
        BridgeKind::Slack => Box::new(SlackAdapter),
        BridgeKind::Teams => Box::new(TeamsAdapter),
        BridgeKind::Discord => Box::new(DiscordAdapter),
    }
}

// ====================================================== Generic Webhook / A2A

pub struct WebhookAdapter {
    kind: BridgeKind,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WebhookInboundBody {
    #[serde(default)]
    event_id: Option<String>,
    #[serde(default)]
    event_type: Option<String>,
    #[serde(default)]
    actor: Option<String>,
    #[serde(default)]
    channel: Option<String>,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    proposed_action: Option<ProposedAction>,
}

#[async_trait]
impl BridgeAdapter for WebhookAdapter {
    fn kind(&self) -> BridgeKind {
        self.kind
    }

    async fn verify_and_parse_inbound(
        &self,
        req: &InboundRawRequest,
        secret: &[u8],
        _cfg: &AdapterConfig,
        _jwks: &dyn JwksProvider,
        now: i64,
        _allow_private_urls: bool,
    ) -> std::result::Result<InboundOutcome, SignatureError> {
        let sig_hdr = req
            .header("x-bp-signature")
            .ok_or(SignatureError::Malformed)?;
        verify_bp_hmac(secret, sig_hdr, &req.body, now, DEFAULT_TOLERANCE_SECS)?;

        let parsed: WebhookInboundBody =
            serde_json::from_slice(&req.body).map_err(|_| SignatureError::Malformed)?;
        let delivery_id = req
            .header("x-bp-delivery")
            .map(str::to_string)
            .or(parsed.event_id)
            .filter(|s| !s.trim().is_empty() && s.len() <= 255)
            .ok_or(SignatureError::Malformed)?;
        let raw_text = parsed.text.or(parsed.message).unwrap_or_default();

        Ok(InboundOutcome::Event(NormalizedInbound {
            delivery_id,
            event_type: sanitize_external_text(
                parsed.event_type.as_deref().unwrap_or("bot.reply"),
                120,
            ),
            external_actor: sanitize_external_text(
                parsed.actor.as_deref().unwrap_or("external-bot"),
                200,
            ),
            channel_ref: sanitize_external_text(parsed.channel.as_deref().unwrap_or(""), 200),
            sanitized_text: sanitize_external_text(&raw_text, 4000),
            proposed_action: parsed.proposed_action.map(|a| ProposedAction {
                kind: sanitize_external_text(&a.kind, 64),
                target: sanitize_external_text(&a.target, 120),
                summary: sanitize_external_text(&a.summary, 500),
            }),
        }))
    }

    fn format_outbound(
        &self,
        event: &BridgeEvent,
        delivery_id: &str,
        outbound_secret: Option<&[u8]>,
        _cfg: &AdapterConfig,
        now: i64,
    ) -> Result<OutboundHttpPayload> {
        let envelope = json!({
            "deliveryId": delivery_id,
            "timestamp": now,
            "event": event,
        });
        let body = serde_json::to_vec(&envelope).map_err(bp_ent_core::Error::internal)?;
        let mut headers = vec![
            ("content-type".to_string(), "application/json".to_string()),
            ("x-bp-delivery".to_string(), delivery_id.to_string()),
            ("x-bp-event".to_string(), event.kind().as_str().to_string()),
        ];
        if let Some(secret) = outbound_secret.filter(|s| !s.is_empty()) {
            headers.push(("x-bp-signature".to_string(), sign_bp_hmac(secret, &body, now)));
        }
        Ok(OutboundHttpPayload { headers, body })
    }
}

// ====================================================================== Slack

pub struct SlackAdapter;

#[derive(Deserialize)]
struct SlackEnvelope {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    challenge: Option<String>,
    #[serde(default)]
    event_id: Option<String>,
    #[serde(default)]
    event: Option<SlackInnerEvent>,
}

#[derive(Deserialize)]
struct SlackInnerEvent {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    user: Option<String>,
    #[serde(default)]
    channel: Option<String>,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    ts: Option<String>,
}

#[async_trait]
impl BridgeAdapter for SlackAdapter {
    fn kind(&self) -> BridgeKind {
        BridgeKind::Slack
    }

    async fn verify_and_parse_inbound(
        &self,
        req: &InboundRawRequest,
        secret: &[u8],
        _cfg: &AdapterConfig,
        _jwks: &dyn JwksProvider,
        now: i64,
        _allow_private_urls: bool,
    ) -> std::result::Result<InboundOutcome, SignatureError> {
        let ts = req
            .header("x-slack-request-timestamp")
            .ok_or(SignatureError::Malformed)?;
        let sig = req
            .header("x-slack-signature")
            .ok_or(SignatureError::Malformed)?;
        verify_slack_v0(secret, ts, sig, &req.body, now, DEFAULT_TOLERANCE_SECS)?;

        let env: SlackEnvelope =
            serde_json::from_slice(&req.body).map_err(|_| SignatureError::Malformed)?;
        if env.kind == "url_verification" {
            let challenge = env.challenge.ok_or(SignatureError::Malformed)?;
            return Ok(InboundOutcome::Challenge {
                response_json: json!({ "challenge": challenge }),
            });
        }
        let ev = env.event.ok_or(SignatureError::Malformed)?;
        let delivery_id = env
            .event_id
            .or_else(|| ev.ts.clone())
            .filter(|s| !s.trim().is_empty() && s.len() <= 255)
            .ok_or(SignatureError::Malformed)?;

        Ok(InboundOutcome::Event(NormalizedInbound {
            delivery_id,
            event_type: format!("slack.{}", sanitize_external_text(&ev.kind, 80)),
            external_actor: sanitize_external_text(ev.user.as_deref().unwrap_or("slack-user"), 200),
            channel_ref: sanitize_external_text(ev.channel.as_deref().unwrap_or(""), 200),
            sanitized_text: sanitize_external_text(ev.text.as_deref().unwrap_or(""), 4000),
            proposed_action: None,
        }))
    }

    fn format_outbound(
        &self,
        event: &BridgeEvent,
        delivery_id: &str,
        _outbound_secret: Option<&[u8]>,
        cfg: &AdapterConfig,
        _now: i64,
    ) -> Result<OutboundHttpPayload> {
        let summary = event.summary_line();
        let mut payload = json!({
            "text": summary,
            "blocks": [
                {
                    "type": "section",
                    "text": { "type": "mrkdwn", "text": summary }
                },
                {
                    "type": "context",
                    "elements": [
                        { "type": "mrkdwn", "text": format!("Backplane event `{}` · delivery `{delivery_id}`", event.kind().as_str()) }
                    ]
                }
            ]
        });
        if let Some(ref ch) = cfg.slack_channel {
            payload["channel"] = Value::String(ch.clone());
        }
        let body = serde_json::to_vec(&payload).map_err(bp_ent_core::Error::internal)?;
        Ok(OutboundHttpPayload {
            headers: vec![("content-type".to_string(), "application/json".to_string())],
            body,
        })
    }
}

// ============================================================ Microsoft Teams

pub struct TeamsAdapter;

#[derive(Deserialize)]
struct TeamsActivity {
    #[serde(default)]
    id: Option<String>,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    from: Option<TeamsAccount>,
    #[serde(default)]
    conversation: Option<TeamsConversation>,
}

#[derive(Deserialize)]
struct TeamsAccount {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Deserialize)]
struct TeamsConversation {
    #[serde(default)]
    id: Option<String>,
}

#[async_trait]
impl BridgeAdapter for TeamsAdapter {
    fn kind(&self) -> BridgeKind {
        BridgeKind::Teams
    }

    async fn verify_and_parse_inbound(
        &self,
        req: &InboundRawRequest,
        _secret: &[u8],
        cfg: &AdapterConfig,
        jwks: &dyn JwksProvider,
        now: i64,
        allow_private_urls: bool,
    ) -> std::result::Result<InboundOutcome, SignatureError> {
        let auth = req
            .header("authorization")
            .ok_or(SignatureError::Malformed)?;
        let app_id = cfg
            .teams_app_id
            .as_deref()
            .ok_or(SignatureError::MissingKey)?;
        verify_teams_jwt(auth, app_id, jwks, now, allow_private_urls).await?;

        let activity: TeamsActivity =
            serde_json::from_slice(&req.body).map_err(|_| SignatureError::Malformed)?;
        let delivery_id = activity
            .id
            .filter(|s| !s.trim().is_empty() && s.len() <= 255)
            .ok_or(SignatureError::Malformed)?;
        let actor = activity
            .from
            .as_ref()
            .and_then(|f| f.name.as_deref().or(f.id.as_deref()))
            .unwrap_or("teams-user");
        let channel = activity
            .conversation
            .as_ref()
            .and_then(|c| c.id.as_deref())
            .unwrap_or("");

        Ok(InboundOutcome::Event(NormalizedInbound {
            delivery_id,
            event_type: format!("teams.{}", sanitize_external_text(&activity.kind, 80)),
            external_actor: sanitize_external_text(actor, 200),
            channel_ref: sanitize_external_text(channel, 200),
            sanitized_text: sanitize_external_text(activity.text.as_deref().unwrap_or(""), 4000),
            proposed_action: None,
        }))
    }

    fn format_outbound(
        &self,
        event: &BridgeEvent,
        delivery_id: &str,
        _outbound_secret: Option<&[u8]>,
        _cfg: &AdapterConfig,
        _now: i64,
    ) -> Result<OutboundHttpPayload> {
        let summary = event.summary_line();
        let card = json!({
            "type": "message",
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                        { "type": "TextBlock", "text": "Backplane Enterprise", "weight": "Bolder", "size": "Medium" },
                        { "type": "TextBlock", "text": summary, "wrap": true },
                        { "type": "TextBlock", "text": format!("Event: {} · Delivery: {}", event.kind().as_str(), delivery_id), "isSubtle": true, "size": "Small" }
                    ]
                }
            }]
        });
        let body = serde_json::to_vec(&card).map_err(bp_ent_core::Error::internal)?;
        Ok(OutboundHttpPayload {
            headers: vec![("content-type".to_string(), "application/json".to_string())],
            body,
        })
    }
}

// ==================================================================== Discord

pub struct DiscordAdapter;

#[derive(Deserialize)]
struct DiscordInteraction {
    #[serde(default)]
    id: Option<String>,
    #[serde(rename = "type")]
    kind: u8,
    #[serde(default)]
    channel_id: Option<String>,
    #[serde(default)]
    member: Option<DiscordMember>,
    #[serde(default)]
    user: Option<DiscordUser>,
    #[serde(default)]
    data: Option<DiscordCommandData>,
}

#[derive(Deserialize)]
struct DiscordMember {
    user: Option<DiscordUser>,
}

#[derive(Deserialize)]
struct DiscordUser {
    id: Option<String>,
    username: Option<String>,
}

#[derive(Deserialize)]
struct DiscordCommandData {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    options: Vec<DiscordOption>,
}

#[derive(Deserialize)]
struct DiscordOption {
    name: String,
    #[serde(default)]
    value: Value,
}

#[async_trait]
impl BridgeAdapter for DiscordAdapter {
    fn kind(&self) -> BridgeKind {
        BridgeKind::Discord
    }

    async fn verify_and_parse_inbound(
        &self,
        req: &InboundRawRequest,
        _secret: &[u8],
        cfg: &AdapterConfig,
        _jwks: &dyn JwksProvider,
        now: i64,
        _allow_private_urls: bool,
    ) -> std::result::Result<InboundOutcome, SignatureError> {
        let sig_hex = req
            .header("x-signature-ed25519")
            .ok_or(SignatureError::Malformed)?;
        let ts_hdr = req
            .header("x-signature-timestamp")
            .ok_or(SignatureError::Malformed)?;
        let pubkey_hex = cfg
            .discord_public_key_hex
            .as_deref()
            .ok_or(SignatureError::MissingKey)?;

        verify_discord_ed25519(pubkey_hex, sig_hex, ts_hdr, &req.body, now, DEFAULT_TOLERANCE_SECS)?;

        let interaction: DiscordInteraction =
            serde_json::from_slice(&req.body).map_err(|_| SignatureError::Malformed)?;
        if interaction.kind == 1 {
            return Ok(InboundOutcome::Challenge {
                response_json: json!({ "type": 1 }),
            });
        }
        let delivery_id = interaction
            .id
            .filter(|s| !s.trim().is_empty() && s.len() <= 255)
            .ok_or(SignatureError::Malformed)?;
        let user = interaction
            .member
            .as_ref()
            .and_then(|m| m.user.as_ref())
            .or(interaction.user.as_ref());
        let actor = user
            .and_then(|u| u.username.as_deref().or(u.id.as_deref()))
            .unwrap_or("discord-user");
        let text = interaction
            .data
            .as_ref()
            .map(|d| {
                let cmd = d.name.as_deref().unwrap_or("command");
                let opts = d
                    .options
                    .iter()
                    .map(|o| format!("{}={}", o.name, o.value))
                    .collect::<Vec<_>>()
                    .join(" ");
                format!("/{cmd} {opts}")
            })
            .unwrap_or_default();

        Ok(InboundOutcome::Event(NormalizedInbound {
            delivery_id,
            event_type: format!("discord.interaction_{}", interaction.kind),
            external_actor: sanitize_external_text(actor, 200),
            channel_ref: sanitize_external_text(
                interaction.channel_id.as_deref().unwrap_or(""),
                200,
            ),
            sanitized_text: sanitize_external_text(&text, 4000),
            proposed_action: None,
        }))
    }

    fn format_outbound(
        &self,
        event: &BridgeEvent,
        delivery_id: &str,
        _outbound_secret: Option<&[u8]>,
        _cfg: &AdapterConfig,
        _now: i64,
    ) -> Result<OutboundHttpPayload> {
        let payload = json!({
            "content": event.summary_line(),
            // Prevent @everyone / @here / role ping abuse from untrusted summaries.
            "allowed_mentions": { "parse": [] },
            "embeds": [{
                "title": event.kind().as_str(),
                "description": event.summary_line(),
                "footer": { "text": format!("delivery {delivery_id}") }
            }]
        });
        let body = serde_json::to_vec(&payload).map_err(bp_ent_core::Error::internal)?;
        Ok(OutboundHttpPayload {
            headers: vec![("content-type".to_string(), "application/json".to_string())],
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signatures::{sign_slack_v0, StaticJwksProvider};

    #[test]
    fn outbound_formats_and_webhook_signs_validly() {
        let ev = BridgeEvent::OrderStatusChanged {
            order_ref: "BP-23456789AB".into(),
            from_status: "ordered".into(),
            to_status: "in_fabrication".into(),
            updated_at: "2026-11-23T17:00:00Z".into(),
        };
        let wh = adapter_for(BridgeKind::Webhook)
            .format_outbound(&ev, "del_1", Some(b"out_sec"), &AdapterConfig::default(), 1_000)
            .unwrap();
        let sig = wh
            .headers
            .iter()
            .find(|(k, _)| k == "x-bp-signature")
            .unwrap()
            .1
            .clone();
        assert!(verify_bp_hmac(b"out_sec", &sig, &wh.body, 1_010, 300).is_ok());

        let discord = adapter_for(BridgeKind::Discord)
            .format_outbound(&ev, "del_1", None, &AdapterConfig::default(), 1_000)
            .unwrap();
        let dv: Value = serde_json::from_slice(&discord.body).unwrap();
        assert_eq!(dv["allowed_mentions"]["parse"], json!([]));

        let slack = adapter_for(BridgeKind::Slack)
            .format_outbound(
                &ev,
                "del_1",
                None,
                &AdapterConfig {
                    slack_channel: Some("#hw-ops".into()),
                    ..Default::default()
                },
                1_000,
            )
            .unwrap();
        let sv: Value = serde_json::from_slice(&slack.body).unwrap();
        assert_eq!(sv["channel"], "#hw-ops");
    }

    #[tokio::test]
    async fn slack_challenge_only_accepted_with_valid_signature() {
        let body = br#"{"type":"url_verification","challenge":"ch_999"}"#;
        let secret = b"slack_secret_123";
        let sig = sign_slack_v0(secret, 5_000, body);
        let mut headers = HashMap::new();
        headers.insert("x-slack-request-timestamp".into(), "5000".into());
        headers.insert("x-slack-signature".into(), sig);

        let out = adapter_for(BridgeKind::Slack)
            .verify_and_parse_inbound(
                &InboundRawRequest {
                    headers: headers.clone(),
                    body: body.to_vec(),
                },
                secret,
                &AdapterConfig::default(),
                &StaticJwksProvider::default(),
                5_010,
                false,
            )
            .await
            .unwrap();
        match out {
            InboundOutcome::Challenge { response_json } => {
                assert_eq!(response_json, json!({"challenge": "ch_999"}));
            }
            _ => panic!("expected challenge"),
        }

        // Wrong secret must fail even on url_verification.
        let err = adapter_for(BridgeKind::Slack)
            .verify_and_parse_inbound(
                &InboundRawRequest {
                    headers,
                    body: body.to_vec(),
                },
                b"wrong",
                &AdapterConfig::default(),
                &StaticJwksProvider::default(),
                5_010,
                false,
            )
            .await
            .unwrap_err();
        assert_eq!(err, SignatureError::Mismatch);
    }
}
