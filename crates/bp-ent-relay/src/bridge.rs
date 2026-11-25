//! Bidirectional allowlisted HTTP-over-RelayFrame bridge for Boat VMs and
//! Desktop hubs.
//!
//! Both sides speak the exact same closed-channel `RelayFrame` protocol over
//! `RelayChannel::BackplaneChat`:
//! - Boat runs `bp-ent-relay boat-agent` (outbound TLS 1.3 + mTLS to `bp-ent-relay`)
//! - Desktop runs `bp-ent-relay desktop-bridge` (authenticated WSS with user token)
//!
//! Security:
//! - Only allowlisted Backplane peer-sync paths (`/healthz`, `/bots/link`,
//!   `/far/rpc`, `/far/push`, `/far/log`, `/far/tunnel`) are forwarded.
//! - Only allowlisted signature/content-type headers cross the tunnel.
//! - Never forwards arbitrary URLs, hosts, or ports (zero SSRF).

use crate::protocol::{RelayChannel, RelayFrame};
use anyhow::{bail, Context};
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderValue, Method, Request, Response, StatusCode};
use axum::routing::any;
use axum::Router;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use futures::{SinkExt, StreamExt};
use rustls::ClientConfig;
use rustls_pki_types::ServerName;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, RwLock};
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use uuid::Uuid;

const MAX_HTTP_BODY_BYTES: usize = 512 * 1024;
const FORWARD_TIMEOUT: Duration = Duration::from_secs(30);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(25);
const RECONNECT_MIN: Duration = Duration::from_secs(1);
const RECONNECT_MAX: Duration = Duration::from_secs(15);

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

#[derive(Clone, Debug, Serialize, Deserialize)]
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
}

struct PendingReply {
    status: u16,
    content_type: String,
    body: Vec<u8>,
}

#[derive(Clone)]
pub struct TunnelHandle {
    to_ws: Arc<RwLock<Option<mpsc::Sender<RelayFrame>>>>,
    pending: Arc<Mutex<HashMap<Uuid, oneshot::Sender<PendingReply>>>>,
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
        }
    }

    pub async fn is_connected(&self) -> bool {
        self.to_ws.read().await.is_some()
    }

    async fn set_sender(&self, tx: Option<mpsc::Sender<RelayFrame>>) {
        *self.to_ws.write().await = tx;
        if self.to_ws.read().await.is_none() {
            self.pending.lock().unwrap().clear();
        }
    }
}

#[derive(Clone)]
struct LocalDoorState {
    tunnel: TunnelHandle,
}

pub async fn spawn_peer_listener(addr: SocketAddr, tunnel: TunnelHandle) -> anyhow::Result<SocketAddr> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind peer listener {addr}"))?;
    let bound = listener.local_addr()?;
    let app = Router::new()
        .fallback(any(handle_peer_request))
        .with_state(LocalDoorState { tunnel });
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!(error = %e, "peer listener stopped");
        }
    });
    Ok(bound)
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
        return plain_resp(StatusCode::NOT_FOUND, "websocket bridge disabled over relay");
    }
    if !matches!(method, Method::GET | Method::POST) {
        return plain_resp(StatusCode::METHOD_NOT_ALLOWED, "only GET and POST allowed");
    }
    if !is_allowed_request(method.as_str(), &path) {
        return plain_resp(StatusCode::FORBIDDEN, "disallowed relay path");
    }

    let mut headers = Vec::new();
    for (k, v) in req.headers() {
        let name = k.as_str();
        if is_allowed_header(name) {
            if let Ok(val) = v.to_str() {
                headers.push((name.to_string(), val.to_string()));
            }
        }
    }

    let body = match axum::body::to_bytes(req.into_body(), MAX_HTTP_BODY_BYTES + 1).await {
        Ok(b) if b.len() <= MAX_HTTP_BODY_BYTES => b,
        Ok(_) => return plain_resp(StatusCode::PAYLOAD_TOO_LARGE, "relay request body too large"),
        Err(_) => return plain_resp(StatusCode::BAD_REQUEST, "failed reading request body"),
    };

    let Some(ws_tx) = st.tunnel.to_ws.read().await.clone() else {
        return plain_resp(StatusCode::SERVICE_UNAVAILABLE, "relay tunnel not connected");
    };

    let req_id = Uuid::new_v4();
    let msg = BridgeMsg::HttpReq {
        req_id,
        method: method.as_str().to_string(),
        path,
        headers,
        body_b64: B64.encode(&body),
    };
    let payload = match serde_json::to_vec(&msg) {
        Ok(p) => p,
        Err(_) => return plain_resp(StatusCode::INTERNAL_SERVER_ERROR, "encode failed"),
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
            if let Ok(ct) = HeaderValue::from_str(&rep.content_type) {
                resp.headers_mut().insert(axum::http::header::CONTENT_TYPE, ct);
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

pub async fn run_ws_session<S>(
    ws: WebSocketStream<S>,
    local_hub: String,
    tunnel: TunnelHandle,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let local_hub = local_hub.trim_end_matches('/').to_string();
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(25))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("reqwest client");

    let (mut ws_tx, mut ws_rx) = ws.split();
    let (frame_tx, mut frame_rx) = mpsc::channel::<RelayFrame>(256);
    let forward_sem = Arc::new(tokio::sync::Semaphore::new(64));
    tunnel.set_sender(Some(frame_tx.clone())).await;

    let writer = tokio::spawn(async move {
        let mut ping = tokio::time::interval(HEARTBEAT_INTERVAL);
        ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                maybe_frame = frame_rx.recv() => {
                    let Some(frame) = maybe_frame else { break; };
                    let Ok(json) = frame.encode_json() else { continue; };
                    if ws_tx.send(Message::Text(json.into())).await.is_err() {
                        break;
                    }
                }
                _ = ping.tick() => {
                    if let Ok(hp) = RelayFrame::new(RelayChannel::HealthPing, b"ping".to_vec()) {
                        if let Ok(json) = hp.encode_json() {
                            if ws_tx.send(Message::Text(json.into())).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        }
    });

    while let Some(Ok(msg)) = ws_rx.next().await {
        match msg {
            Message::Text(txt) => {
                let Ok(frame) = RelayFrame::decode_json(&txt) else {
                    continue;
                };
                if frame.channel != RelayChannel::BackplaneChat {
                    continue;
                }
                let Ok(bmsg) = serde_json::from_slice::<BridgeMsg>(&frame.payload) else {
                    continue;
                };
                match bmsg {
                    BridgeMsg::HttpReq {
                        req_id,
                        method,
                        path,
                        headers,
                        body_b64,
                    } => {
                        let Ok(permit) = forward_sem.clone().try_acquire_owned() else {
                            let rep = BridgeMsg::HttpRep {
                                req_id,
                                status: 503,
                                content_type: "text/plain; charset=utf-8".into(),
                                body_b64: B64.encode(b"relay bridge busy"),
                            };
                            if let Ok(payload) = serde_json::to_vec(&rep) {
                                if let Ok(frame) =
                                    RelayFrame::new(RelayChannel::BackplaneChat, payload)
                                {
                                    let _ = frame_tx.send(frame).await;
                                }
                            }
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
                                &body_b64,
                            )
                            .await;
                            if let Ok(payload) = serde_json::to_vec(&rep) {
                                if let Ok(frame) =
                                    RelayFrame::new(RelayChannel::BackplaneChat, payload)
                                {
                                    let _ = frame_tx.send(frame).await;
                                }
                            }
                        });
                    }
                    BridgeMsg::HttpRep {
                        req_id,
                        status,
                        content_type,
                        body_b64,
                    } => {
                        let body = B64.decode(body_b64.as_bytes()).unwrap_or_default();
                        if let Some(tx) = tunnel.pending.lock().unwrap().remove(&req_id) {
                            let _ = tx.send(PendingReply {
                                status,
                                content_type,
                                body,
                            });
                        }
                    }
                }
            }
            Message::Close(_) => break,
            _ => {}
        }
    }

    writer.abort();
    tunnel.set_sender(None).await;
}

async fn forward_local(
    http: &reqwest::Client,
    local_hub: &str,
    req_id: Uuid,
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body_b64: &str,
) -> BridgeMsg {
    let make_err = |status: u16, msg: &str| BridgeMsg::HttpRep {
        req_id,
        status,
        content_type: "text/plain; charset=utf-8".into(),
        body_b64: B64.encode(msg.as_bytes()),
    };

    if !matches!(method, "GET" | "POST") {
        return make_err(405, "method not allowed");
    }
    if !is_allowed_request(method, path) {
        return make_err(403, "disallowed relay path");
    }
    let body = match B64.decode(body_b64.as_bytes()) {
        Ok(b) if b.len() <= MAX_HTTP_BODY_BYTES => b,
        _ => return make_err(400, "invalid or oversized body"),
    };

    let url = format!("{local_hub}{path}");
    let mut req = if method == "GET" {
        http.get(url)
    } else {
        http.post(url).body(body)
    };
    for (k, v) in headers {
        if is_allowed_header(k) {
            req = req.header(k.as_str(), v.as_str());
        }
    }

    match req.send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let ct = resp
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("application/json")
                .to_string();
            let bytes = resp.bytes().await.unwrap_or_default();
            if bytes.len() > MAX_HTTP_BODY_BYTES {
                return make_err(502, "upstream response too large");
            }
            BridgeMsg::HttpRep {
                req_id,
                status,
                content_type: ct,
                body_b64: B64.encode(&bytes),
            }
        }
        Err(e) => {
            tracing::warn!(error = %e.without_url(), "local hub unreachable");
            make_err(502, "local hub unreachable")
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
    let connector = TlsConnector::from(Arc::new(cfg));
    let server_name = ServerName::try_from(host).context("invalid TLS server name")?;
    let tls = tokio::time::timeout(Duration::from_secs(10), connector.connect(server_name, tcp))
        .await
        .context("relay mTLS handshake timeout")??;

    let req = relay_url.into_client_request()?;
    let (ws, _) = tokio_tungstenite::client_async(req, tls).await?;
    Ok(ws)
}

#[allow(dead_code)]
enum DesktopStream {
    Plain(TcpStream),
    Tls(tokio_rustls::client::TlsStream<TcpStream>),
}

impl tokio::io::AsyncRead for DesktopStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            DesktopStream::Plain(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            DesktopStream::Tls(s) => std::pin::Pin::new(s).poll_read(cx, buf),
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
            DesktopStream::Tls(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            DesktopStream::Plain(s) => std::pin::Pin::new(s).poll_flush(cx),
            DesktopStream::Tls(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            DesktopStream::Plain(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            DesktopStream::Tls(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
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
        match connect_boat_mtls_ws(&relay_url, &ca_cert, &client_cert, &client_key).await {
            Ok(ws) => {
                tracing::info!("boat-agent connected to enterprise relay");
                backoff = RECONNECT_MIN;
                run_ws_session(ws, local_hub.clone(), tunnel.clone()).await;
                tracing::warn!("boat-agent relay session closed; reconnecting");
            }
            Err(e) => {
                tracing::warn!(error = %e, retry_secs = backoff.as_secs(), "boat-agent connect failed");
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
        let token = std::fs::read_to_string(&token_file)
            .with_context(|| format!("read token file {}", token_file.display()))?;
        let token = token.trim();
        if token.is_empty() {
            bail!("token file is empty");
        }

        match connect_desktop_ws(&ws_url, token, ca_cert.as_ref()).await {
            Ok(ws) => {
                tracing::info!(%vm_id, "desktop-bridge connected to enterprise relay");
                backoff = RECONNECT_MIN;
                run_ws_session(ws, local_hub.clone(), tunnel.clone()).await;
                tracing::warn!("desktop-bridge relay session closed; reconnecting");
            }
            Err(e) => {
                tracing::warn!(error = %e, retry_secs = backoff.as_secs(), "desktop-bridge connect failed");
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(RECONNECT_MAX);
    }
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
        DesktopStream::Tls(tls)
    } else {
        DesktopStream::Plain(tcp)
    };

    let mut req = ws_url.into_client_request()?;
    req.headers_mut().insert(
        http::header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}"))?,
    );
    let (ws, _) = tokio_tungstenite::client_async(req, stream).await?;
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
            let rep = forward_local(&client, "http://127.0.0.1:1", Uuid::new_v4(), method, path, &[], "")
                .await;
            match rep {
                BridgeMsg::HttpRep { status, .. } => assert_eq!(status, 403, "{method} {path}"),
                _ => panic!("expected HttpRep"),
            }
        }
    }
}
