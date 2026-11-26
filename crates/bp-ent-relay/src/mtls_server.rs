//! Pure-Rust TLS 1.3 + mandatory mTLS listener for Boat VM outbound tunnels.
//!
//! Security properties:
//! - TLS 1.3 ONLY (`with_protocol_versions(&[&rustls::version::TLS13])`).
//! - Mandatory `WebPkiClientVerifier` rooted strictly at `BoatCa`.
//! - Extracts the verified peer leaf DER certificate directly from the TLS
//!   session (`peer_certificates()`), runs `verify_client_cert_der` (`<= 24h`
//!   lifetime + SPIFFE SAN URI), and injects `Extension<VerifiedBoatIdentity>`.
//! - Never trusts any HTTP header (`X-Tenant-Id`, `X-Vm-Id`, etc.) for Boat identity.
//! - Auto-rotates the 7-day server certificate before expiry (`RotatingServerCertResolver`).
//! - Enforces a 10s TLS handshake timeout and bounded connection semaphore.

use crate::ca::{verify_client_cert_der, BoatCa, VerifiedBoatIdentity};
use axum::body::Body;
use axum::extract::Request;
use axum::Router;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as HttpBuilder;
use rustls::server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier};
use rustls::sign::CertifiedKey;
use rustls::{RootCertStore, ServerConfig};
use std::fmt;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;

pub const DEFAULT_MAX_MTLS_CONNECTIONS: usize = 1024;
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const SERVER_CERT_ROTATE_INTERVAL: Duration = Duration::from_secs(5 * 24 * 60 * 60);

struct CachedServerCert {
    certified_key: Arc<CertifiedKey>,
    rotate_after: Instant,
}

/// Automatically reissues the 7-day server certificate from `BoatCa` every 5 days.
struct RotatingServerCertResolver {
    ca: BoatCa,
    dns_names: Vec<String>,
    cached: RwLock<CachedServerCert>,
}

impl fmt::Debug for RotatingServerCertResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RotatingServerCertResolver")
            .field("dns_names", &self.dns_names)
            .finish_non_exhaustive()
    }
}

impl RotatingServerCertResolver {
    fn new(ca: BoatCa, dns_names: Vec<String>) -> bp_ent_core::Result<Self> {
        let initial = Self::mint(&ca, &dns_names)?;
        Ok(Self {
            ca,
            dns_names,
            cached: RwLock::new(initial),
        })
    }

    fn mint(ca: &BoatCa, dns_names: &[String]) -> bp_ent_core::Result<CachedServerCert> {
        let refs: Vec<&str> = dns_names.iter().map(String::as_str).collect();
        let (cert_chain, key_der) = ca.issue_server_cert(&refs)?;
        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der)
            .map_err(|e| bp_ent_core::Error::internal(anyhow::anyhow!("signing key: {e}")))?;
        Ok(CachedServerCert {
            certified_key: Arc::new(CertifiedKey::new(cert_chain, signing_key)),
            rotate_after: Instant::now() + SERVER_CERT_ROTATE_INTERVAL,
        })
    }
}

impl ResolvesServerCert for RotatingServerCertResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if let Ok(guard) = self.cached.read() {
            if Instant::now() < guard.rotate_after {
                return Some(guard.certified_key.clone());
            }
        }
        if let Ok(mut guard) = self.cached.write() {
            if Instant::now() >= guard.rotate_after {
                if let Ok(fresh) = Self::mint(&self.ca, &self.dns_names) {
                    *guard = fresh;
                }
            }
            return Some(guard.certified_key.clone());
        }
        None
    }
}

pub struct MtlsRelayServer {
    acceptor: TlsAcceptor,
    app: Router,
    conn_limit: Arc<Semaphore>,
}

impl MtlsRelayServer {
    pub fn new(ca: &BoatCa, dns_names: &[&str], app: Router) -> bp_ent_core::Result<Self> {
        let server_config = build_mtls_server_config(ca, dns_names)?;
        Ok(Self {
            acceptor: TlsAcceptor::from(Arc::new(server_config)),
            app,
            conn_limit: Arc::new(Semaphore::new(DEFAULT_MAX_MTLS_CONNECTIONS)),
        })
    }

    pub async fn serve(&self, listener: TcpListener) -> anyhow::Result<()> {
        loop {
            let (tcp, peer_addr) = listener.accept().await?;
            let Ok(permit) = self.conn_limit.clone().try_acquire_owned() else {
                tracing::warn!(%peer_addr, "mTLS connection cap reached; dropping socket");
                drop(tcp);
                continue;
            };
            let acceptor = self.acceptor.clone();
            let app = self.app.clone();

            tokio::spawn(async move {
                let _permit = permit;
                if let Err(err) = handle_connection(acceptor, app, tcp, peer_addr).await {
                    tracing::debug!(%peer_addr, error = %err, "mTLS boat connection closed");
                }
            });
        }
    }
}

pub fn build_mtls_server_config(
    ca: &BoatCa,
    dns_names: &[&str],
) -> bp_ent_core::Result<ServerConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = RootCertStore::empty();
    roots
        .add(ca.ca_cert_der())
        .map_err(|e| bp_ent_core::Error::internal(anyhow::anyhow!("add Boat CA root: {e}")))?;

    let client_verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
            .build()
            .map_err(|e| bp_ent_core::Error::internal(anyhow::anyhow!("client verifier: {e}")))?;

    let resolver = Arc::new(RotatingServerCertResolver::new(
        ca.clone(),
        dns_names.iter().map(|s| (*s).to_string()).collect(),
    )?);

    let mut cfg = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| bp_ent_core::Error::internal(anyhow::anyhow!("tls 1.3 versions: {e}")))?
        .with_client_cert_verifier(client_verifier)
        .with_cert_resolver(resolver);
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(cfg)
}

async fn handle_connection(
    acceptor: TlsAcceptor,
    app: Router,
    tcp: tokio::net::TcpStream,
    peer_addr: SocketAddr,
) -> anyhow::Result<()> {
    let _ = tcp.set_nodelay(true);
    let tls_stream = tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp))
        .await
        .map_err(|_| anyhow::anyhow!("mTLS handshake timeout from {peer_addr}"))??;

    let leaf_der = tls_stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certs| certs.first())
        .ok_or_else(|| anyhow::anyhow!("missing mTLS peer leaf certificate from {peer_addr}"))?
        .as_ref()
        .to_vec();

    let identity: VerifiedBoatIdentity =
        verify_client_cert_der(&leaf_der, OffsetDateTime::now_utc())
            .map_err(|_| anyhow::anyhow!("peer certificate rejected by SPIFFE/TTL policy"))?;

    let io = TokioIo::new(tls_stream);
    let svc = service_fn(move |req: hyper::Request<Incoming>| {
        let app = app.clone();
        let identity = identity.clone();
        async move {
            let (mut parts, body) = req.into_parts();
            // Always overwrite any extension and ignore any untrusted headers.
            parts.extensions.insert(identity);
            let axum_req = Request::from_parts(parts, Body::new(body));
            let resp = app.oneshot(axum_req).await?;
            Ok::<_, std::convert::Infallible>(resp)
        }
    });

    HttpBuilder::new(TokioExecutor::new())
        .serve_connection_with_upgrades(io, svc)
        .await
        .map_err(|e| anyhow::anyhow!("hyper mTLS serve error: {e}"))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::get, Extension, Json};
    use rustls::ClientConfig;
    use rustls_pki_types::ServerName;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::TlsConnector;
    use uuid::Uuid;

    #[tokio::test]
    async fn mtls_server_enforces_tls13_extracts_cert_identity_and_ignores_forged_headers() {
        let ca = BoatCa::generate_ephemeral("Test Boat CA").unwrap();
        let tenant = bp_ent_core::TenantId::new();
        let vm_id = Uuid::new_v4();
        let issued = ca
            .issue_device_cert(tenant, vm_id, Duration::from_secs(3600))
            .unwrap();

        let app = Router::new().route(
            "/whoami",
            get(|Extension(id): Extension<VerifiedBoatIdentity>| async move {
                Json(serde_json::json!({
                    "tenant_id": id.tenant_id,
                    "vm_id": id.vm_id,
                }))
            }),
        );

        let server = Arc::new(MtlsRelayServer::new(&ca, &["localhost"], app).unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn({
            let server = server.clone();
            async move {
                let _ = server.serve(listener).await;
            }
        });

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = RootCertStore::empty();
        roots.add(ca.ca_cert_der()).unwrap();

        let client_certs: Vec<_> = rustls_pemfile::certs(&mut issued.cert_pem.as_bytes())
            .map(|r| r.unwrap())
            .collect();
        let client_key =
            rustls_pemfile::private_key(&mut issued.key_pem.expose().as_bytes())
                .unwrap()
                .unwrap();

        let client_cfg = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_client_auth_cert(client_certs, client_key)
            .unwrap();

        let connector = TlsConnector::from(Arc::new(client_cfg));
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut tls = connector
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .unwrap();

        let forged_tenant = Uuid::new_v4();
        let req = format!(
            "GET /whoami HTTP/1.1\r\nHost: localhost\r\nX-Tenant-Id: {forged_tenant}\r\nX-Vm-Id: {forged_tenant}\r\nConnection: close\r\n\r\n"
        );
        tls.write_all(req.as_bytes()).await.unwrap();
        let mut resp = String::new();
        tls.read_to_string(&mut resp).await.unwrap();

        assert!(resp.contains("200 OK"), "resp was: {resp}");
        assert!(resp.contains(&tenant.to_string()));
        assert!(resp.contains(&vm_id.to_string()));
        assert!(!resp.contains(&forged_tenant.to_string()));

        // A client without a client cert must fail handshake.
        let tcp_noauth = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut roots2 = RootCertStore::empty();
        roots2.add(ca.ca_cert_der()).unwrap();
        let unauth_cfg = ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots2)
        .with_no_client_auth();
        let unauth_conn = TlsConnector::from(Arc::new(unauth_cfg));
        let mut tls_noauth = unauth_conn
            .connect(ServerName::try_from("localhost").unwrap(), tcp_noauth)
            .await
            .unwrap();
        let _ = tls_noauth
            .write_all(b"GET /whoami HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await;
        let mut buf = Vec::new();
        let res = tls_noauth.read_to_end(&mut buf).await;
        assert!(res.is_err() || buf.is_empty(), "unauthenticated mTLS should fail");

        server_task.abort();
    }
}
