//! Closed relay framing protocol (prevents SSRF / arbitrary host:port tunneling).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use bp_ent_core::{Error, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

/// Hard frame payload limit (1 MiB) so neither desktop nor VM can OOM the relay.
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
/// WebSocket message / frame hard limit (2 MiB).
pub const MAX_WS_MESSAGE_BYTES: usize = 2 * 1024 * 1024;

/// Strictly allowlisted logical channels bridged over a Boat tunnel.
/// There is no host, IP, or port field anywhere in the protocol, eliminating SSRF.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayChannel {
    BackplaneChat,
    FileSync,
    KicadIpc,
    BuildLogs,
    HealthPing,
}

fn serialize_b64<S: Serializer>(bytes: &[u8], s: S) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_str(&B64.encode(bytes))
}

fn deserialize_b64<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Vec<u8>, D::Error> {
    let raw = String::deserialize(d)?;
    if raw.len() > ((MAX_FRAME_BYTES * 4) / 3) + 4 {
        return Err(serde::de::Error::custom("relay payload exceeds maximum base64 length"));
    }
    B64.decode(raw.as_bytes()).map_err(serde::de::Error::custom)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayFrame {
    pub id: Uuid,
    pub channel: RelayChannel,
    #[serde(serialize_with = "serialize_b64", deserialize_with = "deserialize_b64")]
    pub payload: Vec<u8>,
}

impl RelayFrame {
    pub fn new(channel: RelayChannel, payload: Vec<u8>) -> Result<Self> {
        if payload.len() > MAX_FRAME_BYTES {
            return Err(Error::invalid(format!(
                "relay frame payload exceeds {MAX_FRAME_BYTES} bytes"
            )));
        }
        Ok(Self {
            id: Uuid::new_v4(),
            channel,
            payload,
        })
    }

    pub fn encode_json(&self) -> Result<String> {
        if self.payload.len() > MAX_FRAME_BYTES {
            return Err(Error::invalid("relay frame exceeds maximum size"));
        }
        serde_json::to_string(self).map_err(|e| Error::internal(anyhow::anyhow!("{e}")))
    }

    pub fn decode_json(raw: &str) -> Result<Self> {
        if raw.len() > MAX_WS_MESSAGE_BYTES {
            return Err(Error::invalid("encoded relay frame exceeds maximum size"));
        }
        let frame: Self = serde_json::from_str(raw)
            .map_err(|_| Error::invalid("malformed relay frame or disallowed channel"))?;
        if frame.payload.len() > MAX_FRAME_BYTES {
            return Err(Error::invalid("relay frame payload exceeds maximum size"));
        }
        Ok(frame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_valid_frame_as_base64_and_rejects_oversized_or_unknown_channel() {
        let frame = RelayFrame::new(RelayChannel::KicadIpc, b"ping".to_vec()).unwrap();
        let encoded = frame.encode_json().unwrap();
        assert!(encoded.contains("\"cGluZw==\""));
        let decoded = RelayFrame::decode_json(&encoded).unwrap();
        assert_eq!(decoded, frame);

        // Unknown / arbitrary channel must be rejected.
        let bad = r#"{"id":"00000000-0000-0000-0000-000000000000","channel":"tcp_forward_169_254_169_254","payload":""}"#;
        assert!(RelayFrame::decode_json(bad).is_err());

        // Oversized payload rejected.
        assert!(RelayFrame::new(RelayChannel::FileSync, vec![0u8; MAX_FRAME_BYTES + 1]).is_err());
    }
}
