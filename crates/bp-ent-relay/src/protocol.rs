//! Closed relay framing protocol (prevents SSRF / arbitrary host:port tunneling).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use bp_ent_core::{Error, Result};
use flate2::{read::DeflateDecoder, write::DeflateEncoder, Compression};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::io::{Read, Write};
use uuid::Uuid;

/// Hard frame payload limit (1 MiB) so neither desktop nor VM can OOM the relay.
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
/// WebSocket message / frame hard limit (2 MiB).
pub const MAX_WS_MESSAGE_BYTES: usize = 2 * 1024 * 1024;

/// Binary RelayFrame header:
/// `[version: 1B = 0x01][channel: 1B][flags: 1B][id: 16B UUID][payload...]`
pub const BIN_VERSION: u8 = 0x01;
pub const BIN_HEADER_LEN: usize = 19;
pub const BIN_FLAG_DEFLATE: u8 = 0x01;
const DEFLATE_MIN_BYTES: usize = 256;

/// Strictly allowlisted logical channels bridged over a Boat tunnel.
/// There is no host, IP, or port field anywhere in the protocol, eliminating SSRF.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum RelayChannel {
    BackplaneChat = 0,
    FileSync = 1,
    KicadIpc = 2,
    BuildLogs = 3,
    HealthPing = 4,
    SolidcraftIpc = 5,
}

impl RelayChannel {
    pub fn from_byte(b: u8) -> Result<Self> {
        match b {
            0 => Ok(Self::BackplaneChat),
            1 => Ok(Self::FileSync),
            2 => Ok(Self::KicadIpc),
            3 => Ok(Self::BuildLogs),
            4 => Ok(Self::HealthPing),
            5 => Ok(Self::SolidcraftIpc),
            _ => Err(Error::invalid("disallowed relay channel")),
        }
    }
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

    /// Encode as compact binary frame (zero base64, raw-DEFLATE when > 256 B and smaller).
    pub fn encode_bin(&self) -> Result<Vec<u8>> {
        if self.payload.len() > MAX_FRAME_BYTES {
            return Err(Error::invalid("relay frame exceeds maximum size"));
        }
        let mut flags = 0u8;
        let mut compressed: Option<Vec<u8>> = None;
        if self.payload.len() > DEFLATE_MIN_BYTES {
            let mut enc = DeflateEncoder::new(
                Vec::with_capacity(self.payload.len() / 2 + 16),
                Compression::fast(),
            );
            if enc.write_all(&self.payload).is_ok() {
                if let Ok(z) = enc.finish() {
                    if z.len() < self.payload.len() {
                        flags |= BIN_FLAG_DEFLATE;
                        compressed = Some(z);
                    }
                }
            }
        }
        let body = compressed.as_deref().unwrap_or(&self.payload);
        let total = BIN_HEADER_LEN + body.len();
        if total > MAX_WS_MESSAGE_BYTES {
            return Err(Error::invalid("encoded binary relay frame exceeds maximum size"));
        }
        let mut out = Vec::with_capacity(total);
        out.push(BIN_VERSION);
        out.push(self.channel as u8);
        out.push(flags);
        out.extend_from_slice(self.id.as_bytes());
        out.extend_from_slice(body);
        Ok(out)
    }

    /// O(1) header check for the relay forwarding hot path (zero JSON/base64/decompression).
    pub fn validate_bin_header(raw: &[u8]) -> Result<RelayChannel> {
        if raw.len() < BIN_HEADER_LEN || raw.len() > MAX_WS_MESSAGE_BYTES {
            return Err(Error::invalid("binary relay frame size out of bounds"));
        }
        if raw[0] != BIN_VERSION {
            return Err(Error::invalid("unsupported binary relay frame version"));
        }
        let ch = RelayChannel::from_byte(raw[1])?;
        if (raw[2] & !BIN_FLAG_DEFLATE) != 0 {
            return Err(Error::invalid("unsupported binary relay frame flags"));
        }
        if (raw[2] & BIN_FLAG_DEFLATE) == 0 && (raw.len() - BIN_HEADER_LEN) > MAX_FRAME_BYTES {
            return Err(Error::invalid("binary relay frame payload exceeds maximum size"));
        }
        Ok(ch)
    }

    /// Decode a binary frame, enforcing strict decompression-bomb bounds.
    pub fn decode_bin(raw: &[u8]) -> Result<Self> {
        let channel = Self::validate_bin_header(raw)?;
        let flags = raw[2];
        let id = Uuid::from_slice(&raw[3..19])
            .map_err(|_| Error::invalid("malformed binary relay frame id"))?;
        let body = &raw[BIN_HEADER_LEN..];
        let payload = if (flags & BIN_FLAG_DEFLATE) != 0 {
            let dec = DeflateDecoder::new(body);
            let mut out = Vec::new();
            dec.take((MAX_FRAME_BYTES + 1) as u64)
                .read_to_end(&mut out)
                .map_err(|_| Error::invalid("corrupt compressed relay payload"))?;
            if out.len() > MAX_FRAME_BYTES {
                return Err(Error::invalid("decompressed relay frame payload exceeds maximum size"));
            }
            out
        } else {
            if body.len() > MAX_FRAME_BYTES {
                return Err(Error::invalid("relay frame payload exceeds maximum size"));
            }
            body.to_vec()
        };
        Ok(Self {
            id,
            channel,
            payload,
        })
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

        // SolidCraft IPC channel is allowlisted and round-trips in JSON and binary.
        let sc = RelayFrame::new(RelayChannel::SolidcraftIpc, b"{\"method\":\"engine.execute\"}".to_vec()).unwrap();
        let sc_json = sc.encode_json().unwrap();
        assert!(sc_json.contains("\"solidcraft_ipc\""));
        assert_eq!(RelayFrame::decode_json(&sc_json).unwrap(), sc);
        let sc_bin = sc.encode_bin().unwrap();
        assert_eq!(RelayFrame::validate_bin_header(&sc_bin).unwrap(), RelayChannel::SolidcraftIpc);
        assert_eq!(RelayFrame::decode_bin(&sc_bin).unwrap(), sc);
    }

    #[test]
    fn binary_frame_round_trips_small_and_compressed_and_blocks_bombs() {
        let small = RelayFrame::new(RelayChannel::BackplaneChat, b"hello".to_vec()).unwrap();
        let bin_s = small.encode_bin().unwrap();
        assert_eq!(bin_s[0], BIN_VERSION);
        assert_eq!(bin_s[2], 0);
        assert_eq!(RelayFrame::validate_bin_header(&bin_s).unwrap(), RelayChannel::BackplaneChat);
        assert_eq!(RelayFrame::decode_bin(&bin_s).unwrap(), small);

        // Compressible payload > 256B uses raw-DEFLATE.
        let big_payload = b"hello world backplane enterprise ".repeat(120);
        let big = RelayFrame::new(RelayChannel::BackplaneChat, big_payload.clone()).unwrap();
        let bin_b = big.encode_bin().unwrap();
        assert_eq!(bin_b[2], BIN_FLAG_DEFLATE);
        assert!(bin_b.len() < big_payload.len() / 5);
        assert_eq!(RelayFrame::decode_bin(&bin_b).unwrap(), big);

        // Decompression bomb > MAX_FRAME_BYTES must be rejected.
        let mut bomb_raw = Vec::new();
        {
            let mut enc = DeflateEncoder::new(&mut bomb_raw, Compression::best());
            enc.write_all(&vec![b'A'; MAX_FRAME_BYTES + 128]).unwrap();
            enc.finish().unwrap();
        }
        let mut bomb_frame = Vec::with_capacity(BIN_HEADER_LEN + bomb_raw.len());
        bomb_frame.push(BIN_VERSION);
        bomb_frame.push(RelayChannel::BackplaneChat as u8);
        bomb_frame.push(BIN_FLAG_DEFLATE);
        bomb_frame.extend_from_slice(Uuid::new_v4().as_bytes());
        bomb_frame.extend_from_slice(&bomb_raw);
        assert!(RelayFrame::decode_bin(&bomb_frame).is_err());

        // Invalid version, channel, flags, and short header rejected.
        assert!(RelayFrame::validate_bin_header(&[1, 0, 0]).is_err());
        let mut bad_ver = bin_s.clone();
        bad_ver[0] = 9;
        assert!(RelayFrame::validate_bin_header(&bad_ver).is_err());
        let mut bad_ch = bin_s.clone();
        bad_ch[1] = 99;
        assert!(RelayFrame::validate_bin_header(&bad_ch).is_err());
        let mut bad_flg = bin_s;
        bad_flg[2] = 0x80;
        assert!(RelayFrame::validate_bin_header(&bad_flg).is_err());
    }
}
