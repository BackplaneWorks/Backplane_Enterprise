# `bp-ent-relay` — Zero-Tailscale Boat VM Relay

Manages Backplane Enterprise Boat VMs (`boat_vms`), short-lived (`<= 24h`) X.509 SPIFFE mTLS device certificates (`BoatCa`), the TLS 1.3-only outbound mTLS relay listener (`MtlsRelayServer`), and compute-hour metering (`UsageRecord`).

## Required Environment Configuration

`BoatCa::from_env()` fails closed unless a CA is explicitly configured:

- **Production (recommended):** `BP_BOAT_CA_CERT_FILE` and `BP_BOAT_CA_KEY_FILE` (mounted from a Kubernetes Secret / Secrets Manager / Docker volume).
- **Inline PEM alternative:** `BP_BOAT_CA_CERT_PEM` and `BP_BOAT_CA_KEY_PEM`.
- **Local dev only:** `BP_BOAT_CA_EPHEMERAL=1` generates an ephemeral in-memory CA on boot.

## Default Provisioner & Metering Sink Notice

`RelayState::from_ctx(ctx)` wires `LocalMockProvisioner` (recording start/stop/terminate actions in memory) and `NoopUsageMeterSink` (persisting `UsageRecord` rows in `boat_vm_usage_records` without forwarding externally) by default. Production deployments and `bp-ent-api` integration should construct `RelayState::with_ca` and inject a real cloud EC2/ECS `VmProvisioner` implementation and the Stripe-backed `UsageMeterSink` from `bp-ent-orders`.

## Enrollment & Self-Renewal (Key Never Leaves VM)

1. An admin calls `POST /v1/vms/{id}/enroll` to mint a 15-minute single-use `bpe_enroll_...` token.
2. On boot, the Boat VM generates an ECDSA keypair locally and exchanges `(enrollmentToken, csrPem)` at `POST /v1/relay/boat/enroll` for its initial `<= 24h` mTLS cert.
3. Every 18 hours, the Boat VM generates a fresh keypair + CSR and calls `POST /v1/relay/boat/renew` over its active mTLS connection (`Extension<VerifiedBoatIdentity>`).
