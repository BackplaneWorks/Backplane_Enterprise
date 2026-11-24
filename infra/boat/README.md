# Managed Boat VM Image & Zero-Tailscale Outbound mTLS Agent

Managed Boat VMs run in private subnets with **zero inbound ports** (no SSH, no Tailscale, no public IP).

## Architecture

1. **Image (`packer/boat-vm.pkr.hcl`)**: Ubuntu 24.04 AMI preloaded with pinned `backplane-hub`, pinned `Backplane_KiCad` (`10.99.0-bp.13.5`), headless Xvfb, UFW default-deny inbound, and hardened systemd units.
2. **Bootstrap (`cloud-init/user-data.yaml.tmpl`)**: Provisions a short-lived (`<= 24h`) X.509 mTLS device certificate carrying SPIFFE SAN URI:
   `spiffe://backplane.enterprise/tenant/<tenant_uuid>/vm/<vm_uuid>`
3. **Outbound Tunnel (`agent/boat-relay-agent.sh` + `systemd/bp-boat-relay-agent.service`)**: Dials outbound TLS 1.3 + mTLS to `bp-ent-relay` (`:8443/v1/relay/boat/connect`). The relay extracts `(tenant_id, vm_id)` strictly from the verified client certificate SAN and bridges only allowlisted channels (`BackplaneChat`, `FileSync`, `KicadIpc`, `BuildLogs`, `HealthPing`).
4. **Automatic Rotation (`systemd/bp-boat-cert-renew.timer`)**: Renews the device certificate every 18 hours prior to the hard 24-hour expiration cap.
