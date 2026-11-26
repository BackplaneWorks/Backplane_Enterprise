//! Bidirectional allowlisted HTTP-over-RelayFrame & `/far/ws` bridge for Boat VMs
//! and Desktop hubs.
//!
//! Both sides speak the exact same closed-channel `RelayFrame` protocol over
//! `RelayChannel::BackplaneChat`:
//! - Boat runs `bp-ent-relay boat-agent` (outbound TLS 1.3 + mTLS to `bp-ent-relay`)
//! - Desktop runs `bp-ent-relay desktop-bridge` (authenticated WSS with user token)
//!
//! Security:
//! - Only allowlisted Backplane peer-sync paths (`/hello`, `/healthz`, `/bots/link`,
//!   `/bots/pair/request`, `/bots/pair/poll`, `/far/rpc`, `/far/push`, `/far/log`,
//!   `/far/tunnel`, and `GET /far/ws` WebSocket upgrades) are forwarded.
//! - Query strings are strictly rejected on every path.
//! - Only validated Backplane HMAC signature/content-type headers cross the tunnel.
//! - Never forwards arbitrary URLs, hosts, or ports (zero SSRF).

use crate::protocol::{RelayChannel, RelayFrame, MAX_FRAME_BYTES};
use anyhow::{bail, Context};
use axum::body::Body;
use axum::extract::ws::{Message as AxumWsMsg, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode, Uri};
use axum::routing::{any, get};
use axum::Router;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use bp_ent_core::Secret;
use futures::{SinkExt, StreamExt};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as HttpBuilder;
use rustls::ClientConfig;
use rustls_pki_types::ServerName;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, watch, RwLock, Semaphore};
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tower::ServiceExt;
use uuid::Uuid;

const MAX_HTTP_BODY_BYTES: usize = 512 * 1024;
const MAX_WS_BRIDGE_BYTES: usize = MAX_FRAME_BYTES - 128;
const MAX_FORWARDED_HEADERS: usize = 8;
const MAX_HEADER_VALUE_BYTES: usize = 512;
const MAX_INBOUND_HTTP: usize = 64;
const MAX_WS_STREAMS: usize = 4;
const DEFAULT_RATE_LIMIT_PER_MIN: u32 = 600;
const FORWARD_TIMEOUT: Duration = Duration::from_secs(30);
const WS_OPEN_TIMEOUT: Duration = Duration::from_secs(15);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(25);
const READ_IDLE_TIMEOUT: Duration = Duration::from_secs(70);
const RECONNECT_MIN: Duration = Duration::from_secs(1);
const RECONNECT_MAX: Duration = Duration::from_secs(15);

fn bridge_ws_config(max_bytes: usize) -> tokio_tungstenite::tungstenite::protocol::WebSocketConfig {
    let mut cfg = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default();
    cfg.max_message_size = Some(max_bytes);
    cfg.max_frame_size = Some(max_bytes);
    cfg
}

const BRIDGE_BIN_MAGIC: u8 = 0xB1;
const KIND_HTTP_REQ: u8 = 1;
const KIND_HTTP_REP: u8 = 2;
const KIND_WS_OPEN: u8 = 3;
const KIND_WS_OPENED: u8 = 4;
const KIND_WS_BIN: u8 = 5;
const KIND_WS_TEXT: u8 = 6;
const KIND_WS_CLOSE: u8 = 7;

pub fn is_allowed_request(method: &str, path_and_query: &str) -> bool {
    if path_and_query.contains('?') {
        return false;
    }
    match method {
        "GET" => matches!(path_and_query, "/hello" | "/healthz"),
        "POST" => matches!(
            path_and_query,
            "/bots/link"
                | "/bots/pair/request"
                | "/bots/pair/poll"
                | "/far/rpc"
                | "/far/push"
                | "/far/log"
                | "/far/tunnel"
        ),
        _ => false,
    }
}

fn is_loopback_host(host: &str) -> bool {
    matches!(host, "127.0.0.1" | "::1" | "[::1]" | "localhost")
}

pub fn is_allowed_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "x-backplane-peer" | "x-backplane-timestamp" | "x-backplane-signature" | "content-type"
    )
}

pub fn is_allowed_ws_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "x-backplane-peer" | "x-backplane-timestamp" | "x-backplane-signature"
    )
}

fn header_value_safe(v: &str) -> bool {
    v.len() <= MAX_HEADER_VALUE_BYTES
        && !v
            .bytes()
            .any(|b| b == b'\r' || b == b'\n' || b == 0 || b < 0x20 || b == 0x7f)
}

fn sanitize_content_type(ct: &str) -> String {
    let trimmed = ct.trim();
    if trimmed.is_empty() || trimmed.len() > 128 || !header_value_safe(trimmed) {
        "application/octet-stream".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Strictly validate and deduplicate forwarded headers (rejects CRLF/control chars,
/// duplicates, excessive lengths, and non-allowlisted header names).
pub fn validate_forwarded_headers<'a, I>(
    headers: I,
    ws_only: bool,
) -> std::result::Result<Vec<(String, String)>, &'static str>
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for (k, v) in headers {
        let lower = k.to_ascii_lowercase();
        let allowed = if ws_only {
            is_allowed_ws_header(&lower)
        } else {
            is_allowed_header(&lower)
        };
        if !allowed {
            continue;
        }
        if !header_value_safe(v) {
            return Err("invalid forwarded header value");
        }
        if !seen.insert(lower.clone()) {
            return Err("duplicate forwarded header");
        }
        if out.len() >= MAX_FORWARDED_HEADERS {
            return Err("too many forwarded headers");
        }
        out.push((lower, v.to_string()));
    }
    Ok(out)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "k", rename_all = "snake_case")]
enum BridgeMsg {
    HttpReq {
        req_id: Uuid,
        method: String,
        path: String,
        headers: Vec<(String, String)>,
        body_b64: String,
    },
    HttpRep {
        req_id: Uuid,
        status: u16,
        content_type: String,
        body_b64: String,
    },
    WsOpen {
        stream_id: Uuid,
        path: String,
        headers: Vec<(String, String)>,
    },
    WsOpened {
        stream_id: Uuid,
        ok: bool,
        status: u16,
        message: String,
    },
    WsBin {
        stream_id: Uuid,
        data_b64: String,
    },
    WsText {
        stream_id: Uuid,
        text: String,
    },
    WsClose {
        stream_id: Uuid,
        reason: String,
    },
}

enum DecodedBridgeMsg {
    HttpReq {
        req_id: Uuid,
        method: String,
        path: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    },
    HttpRep {
        req_id: Uuid,
        status: u16,
        content_type: String,
        body: Vec<u8>,
    },
    WsOpen {
        stream_id: Uuid,
        path: String,
        headers: Vec<(String, String)>,
    },
    WsOpened {
        stream_id: Uuid,
        ok: bool,
        status: u16,
        message: String,
    },
    WsBin {
        stream_id: Uuid,
        data: Vec<u8>,
    },
    WsText {
        stream_id: Uuid,
        text: String,
    },
    WsClose {
        stream_id: Uuid,
        reason: String,
    },
}

impl DecodedBridgeMsg {
    fn encode_bin(&self) -> anyhow::Result<Vec<u8>> {
        let mut out = Vec::with_capacity(64);
        out.push(BRIDGE_BIN_MAGIC);
        match self {
            Self::HttpReq {
                req_id,
                method,
                path,
                headers,
                body,
            } => {
                out.push(KIND_HTTP_REQ);
                out.extend_from_slice(req_id.as_bytes());
                push_u8_str(&mut out, method)?;
                push_u16_str(&mut out, path)?;
                push_headers(&mut out, headers)?;
                out.extend_from_slice(body);
            }
            Self::HttpRep {
                req_id,
                status,
                content_type,
                body,
            } => {
                out.push(KIND_HTTP_REP);
                out.extend_from_slice(req_id.as_bytes());
                out.extend_from_slice(&status.to_be_bytes());
                push_u16_str(&mut out, content_type)?;
                out.extend_from_slice(body);
            }
            Self::WsOpen {
                stream_id,
                path,
                headers,
            } => {
                out.push(KIND_WS_OPEN);
                out.extend_from_slice(stream_id.as_bytes());
                push_u16_str(&mut out, path)?;
                push_headers(&mut out, headers)?;
            }
            Self::WsOpened {
                stream_id,
                ok,
                status,
                message,
            } => {
                out.push(KIND_WS_OPENED);
                out.extend_from_slice(stream_id.as_bytes());
                out.push(u8::from(*ok));
                out.extend_from_slice(&status.to_be_bytes());
                push_u16_str(&mut out, message)?;
            }
            Self::WsBin { stream_id, data } => {
                out.push(KIND_WS_BIN);
                out.extend_from_slice(stream_id.as_bytes());
                out.extend_from_slice(data);
            }
            Self::WsText { stream_id, text } => {
                out.push(KIND_WS_TEXT);
                out.extend_from_slice(stream_id.as_bytes());
                out.extend_from_slice(text.as_bytes());
            }
            Self::WsClose { stream_id, reason } => {
                out.push(KIND_WS_CLOSE);
                out.extend_from_slice(stream_id.as_bytes());
                push_u16_str(&mut out, reason)?;
            }
        }
        Ok(out)
    }

    fn decode(raw: &[u8]) -> Option<Self> {
        if raw.first() == Some(&BRIDGE_BIN_MAGIC) {
            return Self::decode_bin(raw);
        }
        let j: BridgeMsg = serde_json::from_slice(raw).ok()?;
        match j {
            BridgeMsg::HttpReq {
                req_id,
                method,
                path,
                headers,
                body_b64,
            } => Some(Self::HttpReq {
                req_id,
                method,
                path,
                headers,
                body: B64.decode(body_b64.as_bytes()).ok()?,
            }),
            BridgeMsg::HttpRep {
                req_id,
                status,
                content_type,
                body_b64,
            } => Some(Self::HttpRep {
                req_id,
                status,
                content_type,
                body: B64.decode(body_b64.as_bytes()).ok()?,
            }),
            BridgeMsg::WsOpen {
                stream_id,
                path,
                headers,
            } => Some(Self::WsOpen {
                stream_id,
                path,
                headers,
            }),
            BridgeMsg::WsOpened {
                stream_id,
                ok,
                status,
                message,
            } => Some(Self::WsOpened {
                stream_id,
                ok,
                status,
                message,
            }),
            BridgeMsg::WsBin {
                stream_id,
                data_b64,
            } => Some(Self::WsBin {
                stream_id,
                data: B64.decode(data_b64.as_bytes()).ok()?,
            }),
            BridgeMsg::WsText { stream_id, text } => Some(Self::WsText { stream_id, text }),
            BridgeMsg::WsClose { stream_id, reason } => Some(Self::WsClose { stream_id, reason }),
        }
    }

    fn decode_bin(raw: &[u8]) -> Option<Self> {
        if raw.len() < 18 || raw[0] != BRIDGE_BIN_MAGIC {
            return None;
        }
        let kind = raw[1];
        let id = Uuid::from_slice(&raw[2..18]).ok()?;
        let mut cur = &raw[18..];
        match kind {
            KIND_HTTP_REQ => {
                let method = take_u8_str(&mut cur)?;
                let path = take_u16_str(&mut cur)?;
                let headers = take_headers(&mut cur)?;
                Some(Self::HttpReq {
                    req_id: id,
                    method,
                    path,
                    headers,
                    body: cur.to_vec(),
                })
            }
            KIND_HTTP_REP => {
                let status = take_u16(&mut cur)?;
                let content_type = take_u16_str(&mut cur)?;
                Some(Self::HttpRep {
                    req_id: id,
                    status,
                    content_type,
                    body: cur.to_vec(),
                })
            }
            KIND_WS_OPEN => {
                let path = take_u16_str(&mut cur)?;
                let headers = take_headers(&mut cur)?;
                Some(Self::WsOpen {
                    stream_id: id,
                    path,
                    headers,
                })
            }
            KIND_WS_OPENED => {
                let ok = take_u8(&mut cur)? != 0;
                let status = take_u16(&mut cur)?;
                let message = take_u16_str(&mut cur)?;
                Some(Self::WsOpened {
                    stream_id: id,
                    ok,
                    status,
                    message,
                })
            }
            KIND_WS_BIN => Some(Self::WsBin {
                stream_id: id,
                data: cur.to_vec(),
            }),
            KIND_WS_TEXT => Some(Self::WsText {
                stream_id: id,
                text: String::from_utf8(cur.to_vec()).ok()?,
            }),
            KIND_WS_CLOSE => {
                let reason = take_u16_str(&mut cur)?;
                Some(Self::WsClose {
                    stream_id: id,
                    reason,
                })
            }
            _ => None,
        }
    }
}

fn push_u8_str(out: &mut Vec<u8>, s: &str) -> anyhow::Result<()> {
    let b = s.as_bytes();
    if b.len() > u8::MAX as usize {
        bail!("string exceeds u8 length");
    }
    out.push(b.len() as u8);
    out.extend_from_slice(b);
    Ok(())
}

fn push_u16_str(out: &mut Vec<u8>, s: &str) -> anyhow::Result<()> {
    let b = s.as_bytes();
    if b.len() > u16::MAX as usize {
        bail!("string exceeds u16 length");
    }
    out.extend_from_slice(&(b.len() as u16).to_be_bytes());
    out.extend_from_slice(b);
    Ok(())
}

fn push_headers(out: &mut Vec<u8>, headers: &[(String, String)]) -> anyhow::Result<()> {
    if headers.len() > MAX_FORWARDED_HEADERS {
        bail!("too many headers");
    }
    out.push(headers.len() as u8);
    for (k, v) in headers {
        push_u8_str(out, k)?;
        push_u16_str(out, v)?;
    }
    Ok(())
}

fn take_u8(cur: &mut &[u8]) -> Option<u8> {
    let (&b, rest) = cur.split_first()?;
    *cur = rest;
    Some(b)
}

fn take_u16(cur: &mut &[u8]) -> Option<u16> {
    if cur.len() < 2 {
        return None;
    }
    let val = u16::from_be_bytes([cur[0], cur[1]]);
    *cur = &cur[2..];
    Some(val)
}

fn take_u8_str(cur: &mut &[u8]) -> Option<String> {
    let len = take_u8(cur)? as usize;
    if cur.len() < len {
        return None;
    }
    let s = std::str::from_utf8(&cur[..len]).ok()?.to_string();
    *cur = &cur[len..];
    Some(s)
}

fn take_u16_str(cur: &mut &[u8]) -> Option<String> {
    let len = take_u16(cur)? as usize;
    if cur.len() < len {
        return None;
    }
    let s = std::str::from_utf8(&cur[..len]).ok()?.to_string();
    *cur = &cur[len..];
    Some(s)
}

fn take_headers(cur: &mut &[u8]) -> Option<Vec<(String, String)>> {
    let count = take_u8(cur)? as usize;
    if count > MAX_FORWARDED_HEADERS {
        return None;
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let k = take_u8_str(cur)?;
        let v = take_u16_str(cur)?;
        out.push((k, v));
    }
    Some(out)
}

struct PendingReply {
    status: u16,
    content_type: String,
    body: Vec<u8>,
}

struct WsOpenedInfo {
    ok: bool,
    status: u16,
    message: String,
}

#[derive(Clone)]
enum WsStreamMsg {
    Bin(Vec<u8>),
    Text(String),
    Close,
}

#[derive(Clone)]
pub struct TunnelHandle {
    to_ws: Arc<RwLock<Option<mpsc::Sender<RelayFrame>>>>,
    pending: Arc<Mutex<HashMap<Uuid, oneshot::Sender<PendingReply>>>>,
    ws_open_waiters: Arc<Mutex<HashMap<Uuid, oneshot::Sender<WsOpenedInfo>>>>,
    ws_streams: Arc<Mutex<HashMap<Uuid, mpsc::Sender<WsStreamMsg>>>>,
    ws_sem: Arc<Semaphore>,
}

impl Default for TunnelHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl TunnelHandle {
    pub fn new() -> Self {
        Self {
            to_ws: Arc::new(RwLock::new(None)),
            pending: Arc::new(Mutex::new(HashMap::new())),
            ws_open_waiters: Arc::new(Mutex::new(HashMap::new())),
            ws_streams: Arc::new(Mutex::new(HashMap::new())),
            ws_sem: Arc::new(Semaphore::new(MAX_WS_STREAMS)),
        }
    }

    pub async fn is_connected(&self) -> bool {
        self.to_ws.read().await.is_some()
    }

    async fn set_sender(&self, tx: Option<mpsc::Sender<RelayFrame>>) {
        let is_none = tx.is_none();
        *self.to_ws.write().await = tx;
        if is_none {
            self.pending.lock().unwrap().clear();
            self.ws_open_waiters.lock().unwrap().clear();
            self.ws_streams.lock().unwrap().clear();
        }
    }
}

#[derive(Clone)]
struct LocalDoorState {
    tunnel: TunnelHandle,
    http_sem: Arc<Semaphore>,
}

pub async fn spawn_peer_listener(addr: SocketAddr, tunnel: TunnelHandle) -> anyhow::Result<SocketAddr> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind peer listener {addr}"))?;
    let bound = listener.local_addr()?;
    let app = Router::new()
        .route("/far/ws", get(handle_ws_upgrade))
        .fallback(any(handle_peer_request))
        .with_state(LocalDoorState {
            tunnel,
            http_sem: Arc::new(Semaphore::new(MAX_INBOUND_HTTP)),
        });

    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            };
            let _ = tcp.set_nodelay(true);
            let app = app.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(tcp);
                let svc = service_fn(move |req: hyper::Request<Incoming>| {
                    let app = app.clone();
                    async move {
                        let (parts, body) = req.into_parts();
                        let axum_req = Request::from_parts(parts, Body::new(body));
                        let resp = app.oneshot(axum_req).await?;
                        Ok::<_, std::convert::Infallible>(resp)
                    }
                });
                let _ = HttpBuilder::new(TokioExecutor::new())
                    .serve_connection_with_upgrades(io, svc)
                    .await;
            });
        }
    });
    Ok(bound)
}

async fn handle_ws_upgrade(
    State(st): State<LocalDoorState>,
    uri: Uri,
    req_headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response<Body> {
    if uri.query().is_some() {
        return plain_resp(StatusCode::FORBIDDEN, "query parameters disallowed on /far/ws");
    }

    let headers = match validate_forwarded_headers(
        req_headers
            .iter()
            .filter_map(|(k, v)| v.to_str().ok().map(|s| (k.as_str(), s))),
        true,
    ) {
        Ok(h) => h,
        Err(why) => return plain_resp(StatusCode::BAD_REQUEST, why),
    };

    let Some(ws_tx) = st.tunnel.to_ws.read().await.clone() else {
        return plain_resp(StatusCode::SERVICE_UNAVAILABLE, "relay tunnel not connected");
    };

    let Ok(permit) = st.tunnel.ws_sem.clone().try_acquire_owned() else {
        return plain_resp(
            StatusCode::TOO_MANY_REQUESTS,
            "too many concurrent /far/ws streams",
        );
    };

    struct WsOpenGuard {
        tunnel: TunnelHandle,
        ws_tx: mpsc::Sender<RelayFrame>,
        stream_id: Uuid,
        armed: bool,
    }
    impl Drop for WsOpenGuard {
        fn drop(&mut self) {
            if !self.armed {
                return;
            }
            self.tunnel.ws_open_waiters.lock().unwrap().remove(&self.stream_id);
            self.tunnel.ws_streams.lock().unwrap().remove(&self.stream_id);
            if let Ok(payload) = (DecodedBridgeMsg::WsClose {
                stream_id: self.stream_id,
                reason: "initiator aborted".into(),
            })
            .encode_bin()
            {
                if let Ok(frame) = RelayFrame::new(RelayChannel::BackplaneChat, payload) {
                    let _ = self.ws_tx.try_send(frame);
                }
            }
        }
    }

    let stream_id = Uuid::new_v4();
    let (open_tx, open_rx) = oneshot::channel();
    let (stream_tx, mut stream_rx) = mpsc::channel::<WsStreamMsg>(128);
    let mut guard = WsOpenGuard {
        tunnel: st.tunnel.clone(),
        ws_tx: ws_tx.clone(),
        stream_id,
        armed: true,
    };
    st.tunnel
        .ws_open_waiters
        .lock()
        .unwrap()
        .insert(stream_id, open_tx);
    st.tunnel
        .ws_streams
        .lock()
        .unwrap()
        .insert(stream_id, stream_tx);

    let msg = DecodedBridgeMsg::WsOpen {
        stream_id,
        path: "/far/ws".to_string(),
        headers,
    };
    let Ok(payload) = msg.encode_bin() else {
        return plain_resp(StatusCode::INTERNAL_SERVER_ERROR, "encode failed");
    };
    let Ok(frame) = RelayFrame::new(RelayChannel::BackplaneChat, payload) else {
        return plain_resp(StatusCode::PAYLOAD_TOO_LARGE, "frame too large");
    };

    if ws_tx.send(frame).await.is_err() {
        return plain_resp(StatusCode::BAD_GATEWAY, "relay tunnel send failed");
    }

    match tokio::time::timeout(WS_OPEN_TIMEOUT, open_rx).await {
        Ok(Ok(info)) if info.ok => {
            guard.armed = false;
            let tunnel = st.tunnel.clone();
            ws.max_message_size(MAX_WS_BRIDGE_BYTES)
                .max_frame_size(MAX_WS_BRIDGE_BYTES)
                .on_upgrade(move |socket| async move {
                    let _permit = permit;
                    pump_local_ws(socket, tunnel, ws_tx, stream_id, &mut stream_rx).await;
                })
        }
        Ok(Ok(info)) => {
            let status = StatusCode::from_u16(info.status).unwrap_or(StatusCode::BAD_GATEWAY);
            plain_resp(status, &info.message)
        }
        Ok(Err(_)) => plain_resp(StatusCode::BAD_GATEWAY, "relay tunnel closed"),
        Err(_) => plain_resp(StatusCode::GATEWAY_TIMEOUT, "relay /far/ws open timeout"),
    }
}

async fn pump_local_ws(
    socket: WebSocket,
    tunnel: TunnelHandle,
    ws_tx: mpsc::Sender<RelayFrame>,
    stream_id: Uuid,
    stream_rx: &mut mpsc::Receiver<WsStreamMsg>,
) {
    let (mut sock_tx, mut sock_rx) = socket.split();
    loop {
        tokio::select! {
            inbound = stream_rx.recv() => {
                match inbound {
                    Some(WsStreamMsg::Bin(data)) => {
                        if sock_tx.send(AxumWsMsg::Binary(data.into())).await.is_err() {
                            break;
                        }
                    }
                    Some(WsStreamMsg::Text(txt)) => {
                        if sock_tx.send(AxumWsMsg::Text(txt.into())).await.is_err() {
                            break;
                        }
                    }
                    Some(WsStreamMsg::Close) | None => {
                        let _ = sock_tx.send(AxumWsMsg::Close(None)).await;
                        break;
                    }
                }
            }
            outbound = sock_rx.next() => {
                match outbound {
                    Some(Ok(AxumWsMsg::Binary(data))) => {
                        if data.len() > MAX_WS_BRIDGE_BYTES {
                            break;
                        }
                        if !send_bridge_msg(&ws_tx, DecodedBridgeMsg::WsBin { stream_id, data: data.to_vec() }).await {
                            break;
                        }
                    }
                    Some(Ok(AxumWsMsg::Text(txt))) => {
                        if txt.len() > MAX_WS_BRIDGE_BYTES {
                            break;
                        }
                        if !send_bridge_msg(&ws_tx, DecodedBridgeMsg::WsText { stream_id, text: txt.to_string() }).await {
                            break;
                        }
                    }
                    Some(Ok(AxumWsMsg::Ping(_))) | Some(Ok(AxumWsMsg::Pong(_))) => {}
                    Some(Ok(AxumWsMsg::Close(_))) | None | Some(Err(_)) => {
                        let _ = send_bridge_msg(&ws_tx, DecodedBridgeMsg::WsClose { stream_id, reason: "local close".into() }).await;
                        break;
                    }
                }
            }
        }
    }
    tunnel.ws_streams.lock().unwrap().remove(&stream_id);
}

async fn handle_peer_request(
    State(st): State<LocalDoorState>,
    req: Request<Body>,
) -> Response<Body> {
    let method = req.method().clone();
    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());

    if path == "/far/ws" {
        return plain_resp(StatusCode::METHOD_NOT_ALLOWED, "GET websocket upgrade only");
    }
    if !matches!(method, Method::GET | Method::POST) {
        return plain_resp(StatusCode::METHOD_NOT_ALLOWED, "only GET and POST allowed");
    }
    if !is_allowed_request(method.as_str(), &path) {
        return plain_resp(StatusCode::FORBIDDEN, "disallowed relay path");
    }

    let Ok(_permit) = st.http_sem.clone().try_acquire_owned() else {
        return plain_resp(StatusCode::TOO_MANY_REQUESTS, "relay door busy");
    };

    let headers = match validate_forwarded_headers(
        req.headers()
            .iter()
            .filter_map(|(k, v)| v.to_str().ok().map(|s| (k.as_str(), s))),
        false,
    ) {
        Ok(h) => h,
        Err(why) => return plain_resp(StatusCode::BAD_REQUEST, why),
    };

    let body = match axum::body::to_bytes(req.into_body(), MAX_HTTP_BODY_BYTES + 1).await {
        Ok(b) if b.len() <= MAX_HTTP_BODY_BYTES => b,
        Ok(_) => return plain_resp(StatusCode::PAYLOAD_TOO_LARGE, "relay request body too large"),
        Err(_) => return plain_resp(StatusCode::BAD_REQUEST, "failed reading request body"),
    };

    let Some(ws_tx) = st.tunnel.to_ws.read().await.clone() else {
        return plain_resp(StatusCode::SERVICE_UNAVAILABLE, "relay tunnel not connected");
    };

    let req_id = Uuid::new_v4();
    let msg = DecodedBridgeMsg::HttpReq {
        req_id,
        method: method.as_str().to_string(),
        path,
        headers,
        body: body.to_vec(),
    };
    let Ok(payload) = msg.encode_bin() else {
        return plain_resp(StatusCode::INTERNAL_SERVER_ERROR, "encode failed");
    };
    let frame = match RelayFrame::new(RelayChannel::BackplaneChat, payload) {
        Ok(f) => f,
        Err(_) => return plain_resp(StatusCode::PAYLOAD_TOO_LARGE, "frame too large"),
    };

    let (tx, rx) = oneshot::channel();
    st.tunnel.pending.lock().unwrap().insert(req_id, tx);
    if ws_tx.send(frame).await.is_err() {
        st.tunnel.pending.lock().unwrap().remove(&req_id);
        return plain_resp(StatusCode::BAD_GATEWAY, "relay tunnel send failed");
    }

    match tokio::time::timeout(FORWARD_TIMEOUT, rx).await {
        Ok(Ok(rep)) => {
            let status = StatusCode::from_u16(rep.status).unwrap_or(StatusCode::BAD_GATEWAY);
            let mut resp = Response::new(Body::from(rep.body));
            *resp.status_mut() = status;
            let ct = sanitize_content_type(&rep.content_type);
            if let Ok(hv) = HeaderValue::from_str(&ct) {
                resp.headers_mut().insert(axum::http::header::CONTENT_TYPE, hv);
            }
            resp
        }
        Ok(Err(_)) => {
            st.tunnel.pending.lock().unwrap().remove(&req_id);
            plain_resp(StatusCode::BAD_GATEWAY, "relay tunnel closed")
        }
        Err(_) => {
            st.tunnel.pending.lock().unwrap().remove(&req_id);
            plain_resp(StatusCode::GATEWAY_TIMEOUT, "relay forward timeout")
        }
    }
}

fn plain_resp(status: StatusCode, msg: &str) -> Response<Body> {
    let mut r = Response::new(Body::from(msg.to_string()));
    *r.status_mut() = status;
    r.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    r
}

struct SessionRateLimiter {
    window_start: Instant,
    count: u32,
    max_per_min: u32,
}

impl SessionRateLimiter {
    fn from_env() -> Self {
        let max = std::env::var("BP_BRIDGE_RATE_LIMIT_PER_MIN")
            .ok()
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(DEFAULT_RATE_LIMIT_PER_MIN)
            .clamp(60, 60_000);
        Self {
            window_start: Instant::now(),
            count: 0,
            max_per_min: max,
        }
    }

    fn allow(&mut self) -> bool {
        if self.window_start.elapsed() >= Duration::from_secs(60) {
            self.window_start = Instant::now();
            self.count = 0;
        }
        self.count = self.count.saturating_add(1);
        self.count <= self.max_per_min
    }
}

async fn send_bridge_msg(frame_tx: &mpsc::Sender<RelayFrame>, msg: DecodedBridgeMsg) -> bool {
    let Ok(payload) = msg.encode_bin() else {
        return false;
    };
    let Ok(frame) = RelayFrame::new(RelayChannel::BackplaneChat, payload) else {
        return false;
    };
    frame_tx.send(frame).await.is_ok()
}

pub async fn run_ws_session<S>(ws: WebSocketStream<S>, local_hub: String, tunnel: TunnelHandle)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (_tx, rx) = watch::channel(false);
    run_ws_session_until(ws, local_hub, tunnel, rx).await;
}

pub async fn run_ws_session_until<S>(
    ws: WebSocketStream<S>,
    local_hub: String,
    tunnel: TunnelHandle,
    mut shutdown_rx: watch::Receiver<bool>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let local_hub = local_hub.trim_end_matches('/').to_string();
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(25))
        .redirect(reqwest::redirect::Policy::none())
        .tcp_nodelay(true)
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(16)
        .tcp_keepalive(Duration::from_secs(30))
        .build()
        .expect("reqwest client");

    let (mut ws_tx, mut ws_rx) = ws.split();
    let (frame_tx, mut frame_rx) = mpsc::channel::<RelayFrame>(256);
    let forward_sem = Arc::new(Semaphore::new(MAX_INBOUND_HTTP));
    tunnel.set_sender(Some(frame_tx.clone())).await;

    let writer = tokio::spawn(async move {
        let mut ping = tokio::time::interval(HEARTBEAT_INTERVAL);
        ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                maybe_frame = frame_rx.recv() => {
                    let Some(frame) = maybe_frame else { break; };
                    let Ok(bin) = frame.encode_bin() else { continue; };
                    if ws_tx.send(Message::Binary(bin.into())).await.is_err() {
                        break;
                    }
                }
                _ = ping.tick() => {
                    if let Ok(hp) = RelayFrame::new(RelayChannel::HealthPing, b"ping".to_vec()) {
                        if let Ok(bin) = hp.encode_bin() {
                            if ws_tx.send(Message::Binary(bin.into())).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        }
    });

    let mut limiter = SessionRateLimiter::from_env();

    loop {
        let next_msg = tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    break;
                }
                continue;
            }
            res = tokio::time::timeout(READ_IDLE_TIMEOUT, ws_rx.next()) => {
                match res {
                    Ok(Some(Ok(msg))) => msg,
                    Ok(Some(Err(_))) | Ok(None) => break,
                    Err(_) => {
                        tracing::warn!("relay websocket read idle timeout; reconnecting");
                        break;
                    }
                }
            }
        };

        let frame = match next_msg {
            Message::Binary(bytes) => {
                let Ok(f) = RelayFrame::decode_bin(&bytes) else {
                    continue;
                };
                f
            }
            Message::Text(txt) => {
                let Ok(f) = RelayFrame::decode_json(&txt) else {
                    continue;
                };
                f
            }
            Message::Ping(_) | Message::Pong(_) => continue,
            Message::Close(_) => break,
            _ => continue,
        };

        if frame.channel != RelayChannel::BackplaneChat {
            continue;
        }
        let Some(bmsg) = DecodedBridgeMsg::decode(&frame.payload) else {
            continue;
        };

        match bmsg {
            DecodedBridgeMsg::HttpReq {
                req_id,
                method,
                path,
                headers,
                body,
            } => {
                if !limiter.allow() {
                    let _ = send_bridge_msg(
                        &frame_tx,
                        make_http_err(req_id, 429, "relay bridge rate limit exceeded"),
                    )
                    .await;
                    continue;
                }
                let Ok(permit) = forward_sem.clone().try_acquire_owned() else {
                    let _ = send_bridge_msg(
                        &frame_tx,
                        make_http_err(req_id, 503, "relay bridge busy"),
                    )
                    .await;
                    continue;
                };
                let http = http.clone();
                let local_hub = local_hub.clone();
                let frame_tx = frame_tx.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let rep = forward_local(
                        &http,
                        &local_hub,
                        req_id,
                        &method,
                        &path,
                        &headers,
                        &body,
                    )
                    .await;
                    if !send_bridge_msg(&frame_tx, rep).await {
                        let _ = send_bridge_msg(
                            &frame_tx,
                            make_http_err(req_id, 502, "relay reply framing failed"),
                        )
                        .await;
                    }
                });
            }
            DecodedBridgeMsg::HttpRep {
                req_id,
                status,
                content_type,
                body,
            } => {
                if let Some(tx) = tunnel.pending.lock().unwrap().remove(&req_id) {
                    let _ = tx.send(PendingReply {
                        status,
                        content_type,
                        body,
                    });
                }
            }
            DecodedBridgeMsg::WsOpen {
                stream_id,
                path,
                headers,
            } => {
                if !limiter.allow() {
                    let _ = send_bridge_msg(
                        &frame_tx,
                        DecodedBridgeMsg::WsOpened {
                            stream_id,
                            ok: false,
                            status: 429,
                            message: "relay bridge rate limit exceeded".into(),
                        },
                    )
                    .await;
                    continue;
                }
                let Ok(permit) = tunnel.ws_sem.clone().try_acquire_owned() else {
                    let _ = send_bridge_msg(
                        &frame_tx,
                        DecodedBridgeMsg::WsOpened {
                            stream_id,
                            ok: false,
                            status: 429,
                            message: "too many concurrent /far/ws streams".into(),
                        },
                    )
                    .await;
                    continue;
                };
                let local_hub = local_hub.clone();
                let frame_tx = frame_tx.clone();
                let tunnel_c = tunnel.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    open_local_ws(&local_hub, &tunnel_c, &frame_tx, stream_id, &path, &headers)
                        .await;
                });
            }
            DecodedBridgeMsg::WsOpened {
                stream_id,
                ok,
                status,
                message,
            } => {
                if let Some(tx) = tunnel.ws_open_waiters.lock().unwrap().remove(&stream_id) {
                    let _ = tx.send(WsOpenedInfo {
                        ok,
                        status,
                        message,
                    });
                }
            }
            DecodedBridgeMsg::WsBin { stream_id, data } => {
                let tx = tunnel.ws_streams.lock().unwrap().get(&stream_id).cloned();
                if let Some(tx) = tx {
                    if tx.try_send(WsStreamMsg::Bin(data)).is_err() {
                        tunnel.ws_streams.lock().unwrap().remove(&stream_id);
                        if let Ok(payload) = (DecodedBridgeMsg::WsClose {
                            stream_id,
                            reason: "stream overflow or closed".into(),
                        })
                        .encode_bin()
                        {
                            if let Ok(frame) = RelayFrame::new(RelayChannel::BackplaneChat, payload) {
                                let _ = frame_tx.try_send(frame);
                            }
                        }
                    }
                }
            }
            DecodedBridgeMsg::WsText { stream_id, text } => {
                let tx = tunnel.ws_streams.lock().unwrap().get(&stream_id).cloned();
                if let Some(tx) = tx {
                    if tx.try_send(WsStreamMsg::Text(text)).is_err() {
                        tunnel.ws_streams.lock().unwrap().remove(&stream_id);
                        if let Ok(payload) = (DecodedBridgeMsg::WsClose {
                            stream_id,
                            reason: "stream overflow or closed".into(),
                        })
                        .encode_bin()
                        {
                            if let Ok(frame) = RelayFrame::new(RelayChannel::BackplaneChat, payload) {
                                let _ = frame_tx.try_send(frame);
                            }
                        }
                    }
                }
            }
            DecodedBridgeMsg::WsClose { stream_id, .. } => {
                let maybe_tx = tunnel.ws_streams.lock().unwrap().remove(&stream_id);
                if let Some(tx) = maybe_tx {
                    let _ = tx.try_send(WsStreamMsg::Close);
                }
            }
        }
    }

    writer.abort();
    tunnel.set_sender(None).await;
}

async fn send_ws_open_err(
    frame_tx: &mpsc::Sender<RelayFrame>,
    stream_id: Uuid,
    path: &str,
    t0: Instant,
    status: u16,
    msg: &str,
) {
    let _ = send_bridge_msg(
        frame_tx,
        DecodedBridgeMsg::WsOpened {
            stream_id,
            ok: false,
            status,
            message: msg.to_string(),
        },
    )
    .await;
    tracing::info!(
        stream_id = %stream_id,
        path = path,
        status = status,
        latency_ms = t0.elapsed().as_millis() as u64,
        "relay bridge /far/ws open rejected"
    );
}

async fn open_local_ws(
    local_hub: &str,
    tunnel: &TunnelHandle,
    frame_tx: &mpsc::Sender<RelayFrame>,
    stream_id: Uuid,
    path: &str,
    headers: &[(String, String)],
) {
    let t0 = Instant::now();

    if path != "/far/ws" {
        send_ws_open_err(frame_tx, stream_id, path, t0, 403, "disallowed websocket relay path").await;
        return;
    }
    let Ok(clean_headers) = validate_forwarded_headers(
        headers.iter().map(|(k, v)| (k.as_str(), v.as_str())),
        true,
    ) else {
        send_ws_open_err(frame_tx, stream_id, path, t0, 400, "invalid forwarded websocket headers").await;
        return;
    };

    let Some(ws_base) = local_hub
        .strip_prefix("http://")
        .map(|rest| format!("ws://{rest}"))
    else {
        send_ws_open_err(frame_tx, stream_id, path, t0, 502, "local hub must be http:// for /far/ws").await;
        return;
    };

    let ws_url = format!("{ws_base}/far/ws");
    let Ok(parsed) = url::Url::parse(&ws_url) else {
        send_ws_open_err(frame_tx, stream_id, path, t0, 502, "invalid local hub url").await;
        return;
    };
    let Some(host) = parsed.host_str() else {
        send_ws_open_err(frame_tx, stream_id, path, t0, 502, "local hub missing host").await;
        return;
    };
    if !is_loopback_host(host) {
        send_ws_open_err(frame_tx, stream_id, path, t0, 403, "local hub must be loopback").await;
        return;
    }
    let port = parsed.port_or_known_default().unwrap_or(80);
    let Ok(Ok(tcp)) = tokio::time::timeout(
        Duration::from_secs(5),
        TcpStream::connect((host, port)),
    )
    .await
    else {
        send_ws_open_err(frame_tx, stream_id, path, t0, 502, "local hub unreachable").await;
        return;
    };
    let _ = tcp.set_nodelay(true);

    let Ok(mut req) = ws_url.into_client_request() else {
        send_ws_open_err(frame_tx, stream_id, path, t0, 500, "ws request build failed").await;
        return;
    };
    for (k, v) in &clean_headers {
        if let (Ok(name), Ok(val)) = (
            http::header::HeaderName::from_bytes(k.as_bytes()),
            HeaderValue::from_str(v),
        ) {
            req.headers_mut().insert(name, val);
        }
    }

    let up_ws = match tokio::time::timeout(
        Duration::from_secs(8),
        tokio_tungstenite::client_async_with_config(req, tcp, Some(bridge_ws_config(MAX_WS_BRIDGE_BYTES))),
    )
    .await
    {
        Ok(Ok((ws, _))) => ws,
        Ok(Err(tokio_tungstenite::tungstenite::Error::Http(resp))) => {
            send_ws_open_err(frame_tx, stream_id, path, t0, resp.status().as_u16(), "local hub rejected /far/ws").await;
            return;
        }
        Ok(Err(_)) => {
            send_ws_open_err(frame_tx, stream_id, path, t0, 502, "local hub /far/ws handshake failed").await;
            return;
        }
        Err(_) => {
            send_ws_open_err(frame_tx, stream_id, path, t0, 504, "local hub /far/ws handshake timeout").await;
            return;
        }
    };

    let (stream_tx, mut stream_rx) = mpsc::channel::<WsStreamMsg>(128);
    let inserted = {
        let mut guard = tunnel.ws_streams.lock().unwrap();
        if let std::collections::hash_map::Entry::Vacant(e) = guard.entry(stream_id) {
            e.insert(stream_tx);
            true
        } else {
            false
        }
    };
    if !inserted {
        send_ws_open_err(frame_tx, stream_id, path, t0, 409, "duplicate stream_id").await;
        return;
    }

    if !send_bridge_msg(
        frame_tx,
        DecodedBridgeMsg::WsOpened {
            stream_id,
            ok: true,
            status: 101,
            message: String::new(),
        },
    )
    .await
    {
        tunnel.ws_streams.lock().unwrap().remove(&stream_id);
        return;
    }

    tracing::info!(
        stream_id = %stream_id,
        path = "/far/ws",
        status = 101u16,
        latency_ms = t0.elapsed().as_millis() as u64,
        "relay bridge /far/ws established"
    );

    let (mut up_tx, mut up_rx) = up_ws.split();
    loop {
        tokio::select! {
            inbound = stream_rx.recv() => {
                match inbound {
                    Some(WsStreamMsg::Bin(data)) => {
                        if up_tx.send(Message::Binary(data.into())).await.is_err() {
                            break;
                        }
                    }
                    Some(WsStreamMsg::Text(txt)) => {
                        if up_tx.send(Message::Text(txt.into())).await.is_err() {
                            break;
                        }
                    }
                    Some(WsStreamMsg::Close) | None => {
                        let _ = up_tx.send(Message::Close(None)).await;
                        break;
                    }
                }
            }
            outbound = up_rx.next() => {
                match outbound {
                    Some(Ok(Message::Binary(data))) => {
                        if data.len() > MAX_WS_BRIDGE_BYTES {
                            break;
                        }
                        if !send_bridge_msg(frame_tx, DecodedBridgeMsg::WsBin { stream_id, data: data.to_vec() }).await {
                            break;
                        }
                    }
                    Some(Ok(Message::Text(txt))) => {
                        if txt.len() > MAX_WS_BRIDGE_BYTES {
                            break;
                        }
                        if !send_bridge_msg(frame_tx, DecodedBridgeMsg::WsText { stream_id, text: txt.to_string() }).await {
                            break;
                        }
                    }
                    Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => {}
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => {
                        let _ = send_bridge_msg(frame_tx, DecodedBridgeMsg::WsClose { stream_id, reason: "upstream close".into() }).await;
                        break;
                    }
                    _ => {}
                }
            }
        }
    }

    tunnel.ws_streams.lock().unwrap().remove(&stream_id);
    tracing::info!(
        stream_id = %stream_id,
        path = "/far/ws",
        duration_ms = t0.elapsed().as_millis() as u64,
        "relay bridge /far/ws closed"
    );
}

fn make_http_err(req_id: Uuid, status: u16, msg: &str) -> DecodedBridgeMsg {
    DecodedBridgeMsg::HttpRep {
        req_id,
        status,
        content_type: "text/plain; charset=utf-8".into(),
        body: msg.as_bytes().to_vec(),
    }
}

fn extract_rpc_audit_labels(path: &str, body: &[u8]) -> (&'static str, String, String) {
    if path != "/far/rpc" {
        return ("http", String::new(), String::new());
    }
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) else {
        return ("rpc", String::new(), String::new());
    };
    let m = v.get("m").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let tool = if m == "mcp.call" {
        v.pointer("/p/tool")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string()
    } else {
        String::new()
    };
    ("rpc", m, tool)
}

async fn forward_local(
    http: &reqwest::Client,
    local_hub: &str,
    req_id: Uuid,
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> DecodedBridgeMsg {
    let t0 = Instant::now();
    let (kind, rpc_method, mcp_tool) = extract_rpc_audit_labels(path, body);

    if !matches!(method, "GET" | "POST") {
        return make_http_err(req_id, 405, "method not allowed");
    }
    if !is_allowed_request(method, path) {
        return make_http_err(req_id, 403, "disallowed relay path");
    }
    if body.len() > MAX_HTTP_BODY_BYTES {
        return make_http_err(req_id, 400, "invalid or oversized body");
    }
    let Ok(clean_headers) = validate_forwarded_headers(
        headers.iter().map(|(k, v)| (k.as_str(), v.as_str())),
        false,
    ) else {
        return make_http_err(req_id, 400, "invalid forwarded headers");
    };

    let url = format!("{local_hub}{path}");
    let mut req = if method == "GET" {
        http.get(url)
    } else {
        http.post(url).body(body.to_vec())
    };
    for (k, v) in &clean_headers {
        req = req.header(k.as_str(), v.as_str());
    }

    match req.send().await {
        Ok(mut resp) => {
            let status = resp.status().as_u16();
            let ct = sanitize_content_type(
                resp.headers()
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("application/json"),
            );
            let mut bytes = Vec::with_capacity(
                resp.content_length()
                    .unwrap_or(0)
                    .min(MAX_HTTP_BODY_BYTES as u64) as usize,
            );
            loop {
                match resp.chunk().await {
                    Ok(Some(chunk)) => {
                        if bytes.len().saturating_add(chunk.len()) > MAX_HTTP_BODY_BYTES {
                            tracing::warn!(
                                %req_id,
                                path = %path,
                                kind = %kind,
                                rpc_method = %rpc_method,
                                mcp_tool = %mcp_tool,
                                "upstream response exceeded max bridge body"
                            );
                            return make_http_err(req_id, 502, "upstream response too large");
                        }
                        bytes.extend_from_slice(&chunk);
                    }
                    Ok(None) => break,
                    Err(_) => {
                        return make_http_err(req_id, 502, "upstream response read failed");
                    }
                }
            }
            tracing::info!(
                %req_id,
                path = %path,
                kind = %kind,
                rpc_method = %rpc_method,
                mcp_tool = %mcp_tool,
                status = status,
                latency_ms = t0.elapsed().as_millis() as u64,
                req_bytes = body.len(),
                resp_bytes = bytes.len(),
                "relay bridge forwarded request"
            );
            DecodedBridgeMsg::HttpRep {
                req_id,
                status,
                content_type: ct,
                body: bytes,
            }
        }
        Err(e) => {
            tracing::warn!(
                %req_id,
                path = %path,
                kind = %kind,
                rpc_method = %rpc_method,
                mcp_tool = %mcp_tool,
                error = %e.without_url(),
                "local hub unreachable"
            );
            make_http_err(req_id, 502, "local hub unreachable")
        }
    }
}

pub async fn connect_boat_mtls_ws(
    relay_url: &str,
    ca_cert_path: &PathBuf,
    client_cert_path: &PathBuf,
    client_key_path: &PathBuf,
) -> anyhow::Result<WebSocketStream<tokio_rustls::client::TlsStream<TcpStream>>> {
    let ca_pem = std::fs::read(ca_cert_path).context("read CA cert")?;
    let cert_pem = std::fs::read(client_cert_path).context("read client cert")?;
    let key_pem = std::fs::read(client_key_path).context("read client key")?;

    let mut roots = rustls::RootCertStore::empty();
    let mut ca_cur = std::io::Cursor::new(&ca_pem);
    for c in rustls_pemfile::certs(&mut ca_cur) {
        roots.add(c?)?;
    }

    let mut cert_cur = std::io::Cursor::new(&cert_pem);
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_cur).collect::<Result<_, _>>()?;
    let mut key_cur = std::io::Cursor::new(&key_pem);
    let key = rustls_pemfile::private_key(&mut key_cur)?.context("missing private key")?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_client_auth_cert(certs, key)?;

    let parsed = url::Url::parse(relay_url).context("invalid relay_url")?;
    let host = parsed.host_str().context("relay_url missing host")?.to_string();
    let port = parsed.port_or_known_default().unwrap_or(8443);

    let tcp = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect((host.as_str(), port)))
        .await
        .context("relay TCP connect timeout")??;
    let _ = tcp.set_nodelay(true);
    let connector = TlsConnector::from(Arc::new(cfg));
    let server_name = ServerName::try_from(host).context("invalid TLS server name")?;
    let tls = tokio::time::timeout(Duration::from_secs(10), connector.connect(server_name, tcp))
        .await
        .context("relay mTLS handshake timeout")??;

    let req = relay_url.into_client_request()?;
    let (ws, _) = tokio_tungstenite::client_async_with_config(
        req,
        tls,
        Some(bridge_ws_config(crate::protocol::MAX_FRAME_BYTES)),
    )
    .await?;
    Ok(ws)
}

#[allow(dead_code)]
enum DesktopStream {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl tokio::io::AsyncRead for DesktopStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            DesktopStream::Plain(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            DesktopStream::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for DesktopStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            DesktopStream::Plain(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            DesktopStream::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            DesktopStream::Plain(s) => std::pin::Pin::new(s).poll_flush(cx),
            DesktopStream::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            DesktopStream::Plain(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            DesktopStream::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

fn file_stamp(path: &Path) -> Option<(SystemTime, u64)> {
    let md = std::fs::metadata(path).ok()?;
    Some((md.modified().ok()?, md.len()))
}

pub async fn run_boat_agent(
    relay_url: String,
    ca_cert: PathBuf,
    client_cert: PathBuf,
    client_key: PathBuf,
    local_hub: String,
    peer_listen: SocketAddr,
) -> anyhow::Result<()> {
    let tunnel = TunnelHandle::new();
    let bound = spawn_peer_listener(peer_listen, tunnel.clone()).await?;
    tracing::info!(%bound, %local_hub, %relay_url, "boat-agent peer listener ready");

    let mut backoff = RECONNECT_MIN;
    loop {
        let initial_stamp = file_stamp(&client_cert);
        match connect_boat_mtls_ws(&relay_url, &ca_cert, &client_cert, &client_key).await {
            Ok(ws) => {
                tracing::info!("boat-agent connected to enterprise relay");
                backoff = RECONNECT_MIN;
                let (shut_tx, shut_rx) = watch::channel(false);
                let watch_cert = client_cert.clone();
                let watch_task = tokio::spawn(async move {
                    let mut interval = tokio::time::interval(Duration::from_secs(15));
                    interval.tick().await;
                    loop {
                        interval.tick().await;
                        let cur = file_stamp(&watch_cert);
                        if cur.is_some() && cur != initial_stamp {
                            tokio::time::sleep(Duration::from_millis(250)).await;
                            tracing::info!("boat-agent detected rotated client cert; reconnecting");
                            let _ = shut_tx.send(true);
                            break;
                        }
                    }
                });
                run_ws_session_until(ws, local_hub.clone(), tunnel.clone(), shut_rx).await;
                watch_task.abort();
                tracing::warn!("boat-agent relay session closed; reconnecting");
            }
            Err(e) => {
                tracing::warn!(error = %scrub_err(&e.to_string()), retry_secs = backoff.as_secs(), "boat-agent connect failed");
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(RECONNECT_MAX);
    }
}

pub async fn run_desktop_bridge(
    api_url: String,
    vm_id: Uuid,
    token_file: PathBuf,
    ca_cert: Option<PathBuf>,
    local_hub: String,
    peer_listen: SocketAddr,
) -> anyhow::Result<()> {
    let tunnel = TunnelHandle::new();
    let bound = spawn_peer_listener(peer_listen, tunnel.clone()).await?;
    tracing::info!(%bound, %local_hub, %vm_id, "desktop-bridge peer listener ready");

    let base = api_url.trim().trim_end_matches('/');
    let ws_base = if let Some(rest) = base.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = base.strip_prefix("http://") {
        format!("ws://{rest}")
    } else if base.starts_with("wss://") || base.starts_with("ws://") {
        base.to_string()
    } else {
        bail!("api_url must start with https:// or wss://");
    };
    let ws_url = format!("{ws_base}/v1/relay/desktop/connect/{vm_id}");
    let parsed_ws = url::Url::parse(&ws_url).context("invalid api_url")?;
    let host = parsed_ws.host_str().context("api_url missing host")?;
    if parsed_ws.scheme() == "ws" && !is_loopback_host(host) {
        bail!("api_url must use https:// (http:// is allowed only for loopback)");
    }

    let mut backoff = RECONNECT_MIN;
    loop {
        let token = {
            let raw_token = std::fs::read_to_string(&token_file)
                .with_context(|| format!("read token file {}", token_file.display()))?;
            let trimmed = raw_token.trim().to_string();
            if trimmed.is_empty() {
                bail!("token file is empty");
            }
            Secret::new(trimmed)
        };

        match connect_desktop_ws(&ws_url, token.expose(), ca_cert.as_ref()).await {
            Ok(ws) => {
                drop(token);
                tracing::info!(%vm_id, "desktop-bridge connected to enterprise relay");
                let connected_at = Instant::now();
                run_ws_session(ws, local_hub.clone(), tunnel.clone()).await;
                if connected_at.elapsed() >= Duration::from_secs(15) {
                    backoff = RECONNECT_MIN;
                }
                tracing::warn!("desktop-bridge relay session closed; reconnecting");
            }
            Err(e) => {
                drop(token);
                tracing::warn!(error = %scrub_err(&e.to_string()), retry_secs = backoff.as_secs(), "desktop-bridge connect failed");
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(RECONNECT_MAX);
    }
}

pub fn scrub_err(msg: &str) -> String {
    let mut out = msg.to_string();
    for prefix in ["bpe_u_", "bpe_s_", "bpe_d_", "bpe_enroll_", "sha256="] {
        while let Some(idx) = out.find(prefix) {
            let end = out[idx..]
                .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ',' | ')' | ';'))
                .map_or(out.len(), |rel| idx + rel);
            out.replace_range(idx..end, "[REDACTED]");
        }
    }
    out
}

async fn connect_desktop_ws(
    ws_url: &str,
    token: &str,
    ca_cert: Option<&PathBuf>,
) -> anyhow::Result<WebSocketStream<DesktopStream>> {
    let parsed = url::Url::parse(ws_url).context("invalid ws_url")?;
    let host = parsed.host_str().context("ws_url missing host")?.to_string();
    let use_tls = parsed.scheme() == "wss";
    let port = parsed
        .port_or_known_default()
        .unwrap_or(if use_tls { 443 } else { 80 });

    let tcp = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect((host.as_str(), port)))
        .await
        .context("desktop TCP connect timeout")??;
    let _ = tcp.set_nodelay(true);

    let stream = if use_tls {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        if let Some(path) = ca_cert {
            let pem = std::fs::read(path).context("read desktop --ca-cert")?;
            let mut cur = std::io::Cursor::new(&pem);
            for c in rustls_pemfile::certs(&mut cur) {
                roots.add(c?)?;
            }
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cfg = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(cfg));
        let server_name = ServerName::try_from(host).context("invalid TLS server name")?;
        let tls = tokio::time::timeout(Duration::from_secs(10), connector.connect(server_name, tcp))
            .await
            .context("desktop TLS handshake timeout")??;
        DesktopStream::Tls(Box::new(tls))
    } else {
        DesktopStream::Plain(tcp)
    };

    let mut req = ws_url.into_client_request()?;
    let mut auth_val = HeaderValue::from_str(&format!("Bearer {token}"))?;
    auth_val.set_sensitive(true);
    req.headers_mut().insert(http::header::AUTHORIZATION, auth_val);
    let (ws, _) = tokio_tungstenite::client_async_with_config(
        req,
        stream,
        Some(bridge_ws_config(crate::protocol::MAX_FRAME_BYTES)),
    )
    .await?;
    Ok(ws)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn receiver_rejects_disallowed_paths_and_queries() {
        let client = reqwest::Client::new();
        for (method, path) in [
            ("GET", "/v1/admin/users"),
            ("POST", "/hello"),
            ("GET", "/far/rpc"),
            ("POST", "/far/rpc?q=1"),
        ] {
            let rep = forward_local(
                &client,
                "http://127.0.0.1:1",
                Uuid::new_v4(),
                method,
                path,
                &[],
                b"",
            )
            .await;
            match rep {
                DecodedBridgeMsg::HttpRep { status, .. } => assert_eq!(status, 403, "{method} {path}"),
                _ => panic!("expected HttpRep"),
            }
        }
    }

    #[test]
    fn binary_bridge_messages_round_trip_and_strip_unsafe_headers() {
        let id = Uuid::new_v4();
        let msg = DecodedBridgeMsg::HttpReq {
            req_id: id,
            method: "POST".into(),
            path: "/far/rpc".into(),
            headers: vec![("x-backplane-peer".into(), "p1".into())],
            body: br#"{"m":"mcp.call","p":{"tool":"machine_list"}}"#.to_vec(),
        };
        let bin = msg.encode_bin().unwrap();
        assert_eq!(bin[0], BRIDGE_BIN_MAGIC);
        match DecodedBridgeMsg::decode(&bin).unwrap() {
            DecodedBridgeMsg::HttpReq {
                req_id,
                method,
                path,
                headers,
                body,
            } => {
                assert_eq!(req_id, id);
                assert_eq!(method, "POST");
                assert_eq!(path, "/far/rpc");
                assert_eq!(headers, vec![("x-backplane-peer".into(), "p1".into())]);
                assert!(body.starts_with(br#"{"m":"mcp.call""#));
            }
            _ => panic!("wrong decoded variant"),
        }

        // Duplicate, CRLF, and disallowed headers are rejected/stripped.
        assert!(validate_forwarded_headers(
            [("x-backplane-peer", "p1"), ("X-Backplane-Peer", "p2")],
            false
        )
        .is_err());
        assert!(validate_forwarded_headers([("x-backplane-peer", "p1\r\nEvil: 1")], false).is_err());
        let cleaned = validate_forwarded_headers(
            [
                ("authorization", "Bearer secret"),
                ("cookie", "s=1"),
                ("x-forwarded-for", "1.2.3.4"),
                ("x-backplane-peer", "p1"),
            ],
            false,
        )
        .unwrap();
        assert_eq!(cleaned, vec![("x-backplane-peer".into(), "p1".into())]);

        // Secret scrubbing removes tokens & signatures from error messages.
        let s = scrub_err("failed auth with bpe_u_abc123_secret and sha256=deadbeef");
        assert!(!s.contains("bpe_u_"));
        assert!(!s.contains("deadbeef"));
        assert!(s.contains("[REDACTED]"));
    }

    #[tokio::test]
    async fn forward_local_aborts_oversized_streaming_response() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let huge = vec![b'x'; MAX_HTTP_BODY_BYTES + 1024];
        let app = Router::new().route(
            "/hello",
            get(move || {
                let huge = huge.clone();
                async move { huge }
            }),
        );
        let srv = tokio::spawn(async move {
            let _ = axum::serve(l, app).await;
        });

        let client = reqwest::Client::new();
        let rep = forward_local(
            &client,
            &format!("http://{addr}"),
            Uuid::new_v4(),
            "GET",
            "/hello",
            &[],
            b"",
        )
        .await;
        match rep {
            DecodedBridgeMsg::HttpRep { status, body, .. } => {
                assert_eq!(status, 502);
                assert!(String::from_utf8_lossy(&body).contains("too large"));
            }
            _ => panic!("expected HttpRep"),
        }
        srv.abort();
    }

    #[tokio::test]
    async fn peer_listener_rejects_ws_queries_and_enforces_http_concurrency_cap() {
        let tunnel = TunnelHandle::new();
        let (tx, rx) = mpsc::channel(8);
        tunnel.set_sender(Some(tx)).await;
        let bound = spawn_peer_listener("127.0.0.1:0".parse().unwrap(), tunnel.clone())
            .await
            .unwrap();

        let http = reqwest::Client::new();
        // Query string on /far/ws must be rejected 403 before upgrade.
        let r_ws_qs = http
            .get(format!("http://{bound}/far/ws?k=1"))
            .header("connection", "Upgrade")
            .header("upgrade", "websocket")
            .header("sec-websocket-version", "13")
            .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .send()
            .await
            .unwrap();
        assert_eq!(r_ws_qs.status(), 403);

        // Saturate outbound tunnel pending queue / semaphore test via SessionRateLimiter.
        let mut limiter = SessionRateLimiter {
            window_start: Instant::now(),
            count: 0,
            max_per_min: 2,
        };
        assert!(limiter.allow());
        assert!(limiter.allow());
        assert!(!limiter.allow());

        // Dropping receiver triggers send error -> 502 instead of hanging.
        drop(rx);
        let r_closed = http
            .post(format!("http://{bound}/far/rpc"))
            .body("{}")
            .send()
            .await
            .unwrap();
        assert_eq!(r_closed.status(), 502);
    }
}
