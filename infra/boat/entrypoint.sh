#!/usr/bin/env bash
set -euo pipefail

# Containerized Boat VM entrypoint:
# 1. Enrolls a <=24h mTLS certificate via single-use ENROLLMENT_TOKEN on first boot.
# 2. Starts local backplane-hub (--no-tailscale, loopback only).
# 3. Starts outbound TLS 1.3 mTLS relay agent (bp-ent-relay boat-agent).
# 4. Renews the device certificate every 18 hours.

CERT_DIR="${CERT_DIR:-/etc/backplane-boat/certs}"
BOAT_HOME="${BOAT_HOME:-/var/lib/backplane-boat/home}"
BOAT_PORT="${BOAT_PORT:-3798}"
RENEW_INTERVAL_SECS="${RENEW_INTERVAL_SECS:-64800}"

mkdir -p "${BOAT_HOME}" "${CERT_DIR}"

if [[ ! -f "${CERT_DIR}/device.crt" || ! -f "${CERT_DIR}/device.key" || ! -f "${CERT_DIR}/ca.pem" ]]; then
  /usr/local/bin/boat-relay-agent.sh enroll
fi

backplane-hub \
  --home "${BOAT_HOME}" \
  --port "${BOAT_PORT}" \
  --host 127.0.0.1 \
  --no-tailscale \
  --foreground &
HUB_PID=$!

/usr/local/bin/boat-relay-agent.sh run &
AGENT_PID=$!

(
  while true; do
    sleep "${RENEW_INTERVAL_SECS}"
    /usr/local/bin/boat-relay-agent.sh renew || true
  done
) &
RENEW_PID=$!

cleanup() {
  kill "${RENEW_PID}" "${AGENT_PID}" "${HUB_PID}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

wait -n "${HUB_PID}" "${AGENT_PID}"
