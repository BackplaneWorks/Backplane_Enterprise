//! Backplane Enterprise Zero-Tailscale Boat VM Relay (`bp-ent-relay`).
//!
//! Provides:
//! - Short-lived (`<= 24h`) X.509 device CA with SPIFFE SAN identities (`ca`)
//! - Pure-Rust TLS 1.3 + mandatory mTLS listener with cert auto-rotation (`mtls_server`)
//! - Strict tenant-scoped active tunnel registry (`registry`)
//! - Closed-channel base64 relay framing with zero SSRF (`protocol`)
//! - Boat VM lifecycle, idle auto-stop, wake-on-connect, and Stripe `UsageRecord` metering (`lifecycle`)
//! - Axum HTTP/WebSocket routes & SQLx migrations (`routes`)

#![forbid(unsafe_code)]

pub mod bridge;
pub mod ca;
pub mod lifecycle;
pub mod mtls_server;
pub mod protocol;
pub mod registry;
pub mod routes;

pub use ca::{
    BoatCa, IssuedDeviceCert, SignedDeviceCert, VerifiedBoatIdentity, MAX_DEVICE_CERT_TTL_SECS,
};
pub use lifecycle::{
    reap_idle_vms, InMemoryUsageMeterSink, LocalMockProvisioner, NoopUsageMeterSink,
    UsageMeterSink, UsageRecord, VmProvisioner, VmState,
};
pub use mtls_server::MtlsRelayServer;
pub use protocol::{RelayChannel, RelayFrame, MAX_FRAME_BYTES, MAX_WS_MESSAGE_BYTES};
pub use registry::{TunnelPacket, TunnelRegistry};
pub use routes::{
    client_router_with_state, migrator, mtls_router_with_state, router, router_with_state,
    BoatVmDto, RelayConfig, RelayState,
};
