# Backplane Enterprise Quickstart

Run the Enterprise control plane, enroll a Boat container (with zero inbound ports or Tailscale), link your Desktop hub through the Enterprise relay, and enable account-based mobile push.

## 1. Start the Control Plane

```bash
cd infra/docker
cp .env.example .env
# Edit .env and set strong passwords plus:
#   BP_KEK="v1:$(openssl rand -base64 32)"
#   BP_PUBLIC_ORIGIN=https://enterprise.example.com
#   BP_API_BASE_URL=https://enterprise.example.com
#   BP_INSECURE_COOKIES=0
#   BP_TRUSTED_PROXY_HOPS=1
#   BP_RELAY_MTLS_HOST=app,localhost
# Optional APNs (or BP_APNS_MOCK_URL for local testing):
#   BP_APNS_KEY_FILE=/etc/backplane-apns/AuthKey.p8
#   BP_APNS_KEY_ID=YOURKEYID1
#   BP_APNS_TEAM_ID=YOURTEAMID
docker compose up -d --build
curl -fsS http://127.0.0.1:8080/readyz
```

If exposing locally over HTTPS (for example via a tailnet or reverse proxy on port `8480`), proxy `127.0.0.1:8080` over HTTPS and set `BP_PUBLIC_ORIGIN` / `BP_API_BASE_URL` to that `https://` origin.

## 2. Create Your Organization, SSO, and User Token

```bash
# 1. Create the org and invite your org_admin email:
docker compose exec app bp-service tenant create \
  --name "My Hardware Org" --slug my-org --admin-email person@example.com

# 2. Configure Google OIDC (set GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET in env):
docker compose exec app bp-service idp add \
  --slug my-org --provider oidc --name "Google" \
  --issuer https://accounts.google.com \
  --client-id "$GOOGLE_CLIENT_ID" \
  --client-secret-env GOOGLE_CLIENT_SECRET \
  --domain example.com

# 3. Issue a user API token (activates an invited user with --activate):
mkdir -p ~/.backplane-enterprise-local
chmod 0700 ~/.backplane-enterprise-local
(
  umask 077
  docker compose exec app bp-service token issue \
    --slug my-org --email person@example.com --name "desktop-hub" --ttl-days 90 --activate \
    > ~/.backplane-enterprise-local/user.token
)
```

Register `https://<your-origin>/v1/auth/callback` as an authorized redirect URI on your Google Cloud OAuth client.

## 3. Create, Wake, and Enroll a Boat

```bash
TOKEN=$(cat ~/.backplane-enterprise-local/user.token)
API=https://enterprise.example.com

# Create and wake the VM:
VM_ID=$(curl -fsS -X POST "$API/v1/vms" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"my-boat"}' | jq -r '.id')
curl -fsS -X POST "$API/v1/vms/$VM_ID/wake" -H "Authorization: Bearer $TOKEN" >/dev/null

# Mint a single-use enrollment token (valid 15m):
ENROLL_TOKEN=$(curl -fsS -X POST "$API/v1/vms/$VM_ID/enroll" \
  -H "Authorization: Bearer $TOKEN" | jq -r '.enrollmentToken')
```

Stage `backplane-hub`, `bp-ent-relay`, `infra/boat/agent/boat-relay-agent.sh`, and `infra/boat/entrypoint.sh` into a Docker build context, build `infra/boat/Dockerfile`, and run it on the `docker_bp_internal` network with **no published ports**:

```bash
docker run -d --name my-boat \
  --network docker_bp_internal \
  -e VM_ID="$VM_ID" \
  -e ENROLLMENT_TOKEN="$ENROLL_TOKEN" \
  -e RELAY_API_URL=http://app:8080 \
  -e RELAY_MTLS_API_URL=https://app:8443 \
  -e RELAY_MTLS_URL=wss://app:8443/v1/relay/boat/connect \
  backplane-boat:latest
```

Confirm `"tunnelState": "connected_mtls"` via `GET $API/v1/vms/$VM_ID`.

## 4. Link Your Desktop Hub Over the Relay

Run `desktop-bridge` on your workstation (loopback only, authenticated with your user token):

```bash
bp-ent-relay desktop-bridge \
  --api-url "$API" \
  --vm-id "$VM_ID" \
  --token-file ~/.backplane-enterprise-local/user.token \
  --local-hub http://127.0.0.1:3797 \
  --peer-listen 127.0.0.1:3796
```

Now pair the Boat hub (`http://127.0.0.1:3799` inside the Boat reaches your Desktop hub) with your Desktop hub (`http://127.0.0.1:3796` on your workstation reaches the Boat hub) using Backplane's pairing flow (`POST /bots/pair/request`, `POST /bots/pair/poll`, and signed `POST /bots/link`). Both hubs sync projects, threads, and Uberbot ops over the Enterprise mTLS/WSS relay.

## 5. Enable Account-Based Mobile Push

Any authenticated Enterprise account (no subscription required) can send pushes to its own registered devices:

1. **On the Boat hub:** create `<boat-home>/secrets/enterprise.json` (`0600`) containing `{"url":"https://enterprise.example.com","token":"<your-user-token>"}`. When no local APNs `.p8` key is configured, the hub automatically delivers alerts through `POST /v1/push/send`.
2. **On iPhone:** open **Settings → Notifications**, enter your Enterprise URL and user token under **Enterprise Push**, and tap **Sign in**. Your APNs device token is registered under your Enterprise account only (`GET /v1/push/devices`, strictly isolated per user).
