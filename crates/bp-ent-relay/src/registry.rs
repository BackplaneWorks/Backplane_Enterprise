//! In-memory registry of active Boat VM outbound mTLS tunnels.
//!
//! Strictly keyed by `(TenantId, vm_id)` so a Boat VM tunnel from tenant A can
//! never be looked up or bridged by a caller in tenant B.

use crate::protocol::RelayFrame;
use bp_ent_core::{Error, Result, TenantId};
use std::collections::HashMap;
use std::sync::Arc;
use time::OffsetDateTime;
use tokio::sync::{mpsc, watch, Mutex, Notify, RwLock};
use uuid::Uuid;

/// Opaque validated frame forwarded across the relay without re-parsing JSON or base64.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TunnelPacket {
    Bin(Vec<u8>),
    Json(RelayFrame),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct VmKey {
    pub tenant_id: TenantId,
    pub vm_id: Uuid,
}

impl VmKey {
    pub fn new(tenant_id: TenantId, vm_id: Uuid) -> Self {
        Self { tenant_id, vm_id }
    }
}

#[derive(Clone)]
struct ActiveClient {
    client_session_id: Uuid,
    tx: mpsc::Sender<TunnelPacket>,
}

#[derive(Clone)]
struct ActiveTunnel {
    session_id: Uuid,
    connected_at: OffsetDateTime,
    last_heartbeat: Arc<Mutex<OffsetDateTime>>,
    to_vm_tx: mpsc::Sender<TunnelPacket>,
    active_client: Arc<Mutex<Option<ActiveClient>>>,
    shutdown_tx: watch::Sender<bool>,
}

#[derive(Clone, Default)]
pub struct TunnelRegistry {
    tunnels: Arc<RwLock<HashMap<VmKey, ActiveTunnel>>>,
    wake_waiters: Arc<RwLock<HashMap<VmKey, Arc<Notify>>>>,
}

impl TunnelRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a newly authenticated Boat VM outbound mTLS tunnel.
    /// Returns `(session_id, rx_from_clients, shutdown_rx)` and notifies any
    /// waiting desktop session. If a previous tunnel existed for the same VM,
    /// it is signalled to shut down.
    pub async fn register_vm(
        &self,
        tenant_id: TenantId,
        vm_id: Uuid,
    ) -> (Uuid, mpsc::Receiver<TunnelPacket>, watch::Receiver<bool>) {
        let key = VmKey::new(tenant_id, vm_id);
        let session_id = Uuid::new_v4();
        let (to_vm_tx, to_vm_rx) = mpsc::channel(256);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let now = OffsetDateTime::now_utc();
        let tunnel = ActiveTunnel {
            session_id,
            connected_at: now,
            last_heartbeat: Arc::new(Mutex::new(now)),
            to_vm_tx,
            active_client: Arc::new(Mutex::new(None)),
            shutdown_tx,
        };
        if let Some(prev) = self.tunnels.write().await.insert(key, tunnel) {
            let _ = prev.shutdown_tx.send(true);
        }

        if let Some(notify) = self.wake_waiters.read().await.get(&key).cloned() {
            notify.notify_waiters();
        }
        (session_id, to_vm_rx, shutdown_rx)
    }

    /// Immediately terminate and remove any live tunnel for `(tenant_id, vm_id)`
    /// (called on cert revocation, VM stop, or VM termination).
    pub async fn force_disconnect_vm(&self, tenant_id: TenantId, vm_id: Uuid) -> bool {
        let key = VmKey::new(tenant_id, vm_id);
        if let Some(tunnel) = self.tunnels.write().await.remove(&key) {
            let _ = tunnel.shutdown_tx.send(true);
            *tunnel.active_client.lock().await = None;
            true
        } else {
            false
        }
    }

    /// Unregister only if the disconnecting session matches `session_id`.
    pub async fn unregister_vm(&self, tenant_id: TenantId, vm_id: Uuid, session_id: Uuid) {
        let key = VmKey::new(tenant_id, vm_id);
        let mut map = self.tunnels.write().await;
        if let Some(existing) = map.get(&key) {
            if existing.session_id == session_id {
                let _ = existing.shutdown_tx.send(true);
                map.remove(&key);
            }
        }
    }

    pub async fn is_connected(&self, tenant_id: TenantId, vm_id: Uuid) -> bool {
        self.tunnels
            .read()
            .await
            .contains_key(&VmKey::new(tenant_id, vm_id))
    }

    pub async fn has_active_client(&self, tenant_id: TenantId, vm_id: Uuid) -> bool {
        let Some(tunnel) = self
            .tunnels
            .read()
            .await
            .get(&VmKey::new(tenant_id, vm_id))
            .cloned()
        else {
            return false;
        };
        let active = tunnel
            .active_client
            .lock()
            .await
            .as_ref()
            .is_some_and(|c| !c.tx.is_closed());
        active
    }

    pub async fn touch_heartbeat(&self, tenant_id: TenantId, vm_id: Uuid) {
        if let Some(t) = self.tunnels.read().await.get(&VmKey::new(tenant_id, vm_id)) {
            *t.last_heartbeat.lock().await = OffsetDateTime::now_utc();
        }
    }

    /// Return a `Notify` signalled when `(tenant_id, vm_id)` dials in.
    pub async fn wake_notifier(&self, tenant_id: TenantId, vm_id: Uuid) -> Arc<Notify> {
        let key = VmKey::new(tenant_id, vm_id);
        let mut map = self.wake_waiters.write().await;
        map.entry(key).or_insert_with(|| Arc::new(Notify::new())).clone()
    }

    /// Attach a desktop/web client to the active VM tunnel.
    /// Rejects a second concurrent client with `409 Conflict` so an existing
    /// user's reply stream can never be silently hijacked.
    pub async fn attach_client(
        &self,
        tenant_id: TenantId,
        vm_id: Uuid,
        client_session_id: Uuid,
    ) -> Result<(
        mpsc::Sender<TunnelPacket>,
        mpsc::Receiver<TunnelPacket>,
        watch::Receiver<bool>,
    )> {
        let key = VmKey::new(tenant_id, vm_id);
        let tunnel = self
            .tunnels
            .read()
            .await
            .get(&key)
            .cloned()
            .ok_or(Error::NotFound)?;

        let mut guard = tunnel.active_client.lock().await;
        if let Some(existing) = guard.as_ref() {
            if !existing.tx.is_closed() {
                return Err(Error::conflict(
                    "boat vm already has an active desktop session",
                ));
            }
        }

        let (to_client_tx, to_client_rx) = mpsc::channel(256);
        *guard = Some(ActiveClient {
            client_session_id,
            tx: to_client_tx,
        });
        Ok((
            tunnel.to_vm_tx,
            to_client_rx,
            tunnel.shutdown_tx.subscribe(),
        ))
    }

    /// Release the active client slot when `client_session_id` disconnects.
    pub async fn detach_client(
        &self,
        tenant_id: TenantId,
        vm_id: Uuid,
        client_session_id: Uuid,
    ) {
        let key = VmKey::new(tenant_id, vm_id);
        if let Some(tunnel) = self.tunnels.read().await.get(&key).cloned() {
            let mut guard = tunnel.active_client.lock().await;
            if guard
                .as_ref()
                .is_some_and(|c| c.client_session_id == client_session_id)
            {
                *guard = None;
            }
        }
    }

    /// Forward a frame received from a Boat VM to its currently attached desktop client.
    pub async fn forward_from_vm(
        &self,
        tenant_id: TenantId,
        vm_id: Uuid,
        packet: TunnelPacket,
    ) -> Result<()> {
        let key = VmKey::new(tenant_id, vm_id);
        let tunnel = self
            .tunnels
            .read()
            .await
            .get(&key)
            .cloned()
            .ok_or(Error::NotFound)?;
        *tunnel.last_heartbeat.lock().await = OffsetDateTime::now_utc();
        let maybe_tx = tunnel
            .active_client
            .lock()
            .await
            .as_ref()
            .map(|c| c.tx.clone());
        if let Some(tx) = maybe_tx {
            if tokio::time::timeout(std::time::Duration::from_secs(5), tx.send(packet))
                .await
                .is_err()
            {
                tracing::warn!(
                    %tenant_id,
                    %vm_id,
                    "dropping vm->desktop packet: client channel backpressured or closed"
                );
            }
        }
        Ok(())
    }

    pub async fn connected_since(&self, tenant_id: TenantId, vm_id: Uuid) -> Option<OffsetDateTime> {
        self.tunnels
            .read()
            .await
            .get(&VmKey::new(tenant_id, vm_id))
            .map(|t| t.connected_at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::RelayChannel;
    use axum::http::StatusCode;

    #[tokio::test]
    async fn tunnels_are_strictly_isolated_by_tenant_and_reject_concurrent_hijack() {
        let reg = TunnelRegistry::new();
        let tenant_a = TenantId::new();
        let tenant_b = TenantId::new();
        let vm_id = Uuid::new_v4();

        let (sess_a, mut vm_rx_a, mut shut_rx) = reg.register_vm(tenant_a, vm_id).await;
        assert!(reg.is_connected(tenant_a, vm_id).await);
        assert!(!reg.is_connected(tenant_b, vm_id).await);
        assert!(reg
            .attach_client(tenant_b, vm_id, Uuid::new_v4())
            .await
            .is_err());

        // First client attaches.
        let c1 = Uuid::new_v4();
        let (to_vm_a, _from_vm_a, _c1_shut) = reg.attach_client(tenant_a, vm_id, c1).await.unwrap();
        let frame = RelayFrame::new(RelayChannel::BackplaneChat, b"hello".to_vec()).unwrap();
        let pkt = TunnelPacket::Json(frame);
        to_vm_a.send(pkt.clone()).await.unwrap();
        assert_eq!(vm_rx_a.recv().await.unwrap(), pkt);

        // Concurrent second client is rejected with 409 Conflict (no silent hijack).
        let c2 = Uuid::new_v4();
        let err = reg.attach_client(tenant_a, vm_id, c2).await.unwrap_err();
        assert_eq!(err.status(), StatusCode::CONFLICT);

        // After first client detaches, second client can attach.
        reg.detach_client(tenant_a, vm_id, c1).await;
        assert!(reg.attach_client(tenant_a, vm_id, c2).await.is_ok());

        // force_disconnect_vm signals shutdown watch and drops tunnel.
        assert!(reg.force_disconnect_vm(tenant_a, vm_id).await);
        shut_rx.changed().await.unwrap();
        assert!(*shut_rx.borrow());
        assert!(!reg.is_connected(tenant_a, vm_id).await);
        reg.unregister_vm(tenant_a, vm_id, sess_a).await;
    }
}
