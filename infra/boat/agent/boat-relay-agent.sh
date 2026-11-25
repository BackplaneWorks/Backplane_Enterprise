#!/usr/bin/env bash
set -euo pipefail

# Backplane Enterprise Boat VM Outbound mTLS Relay Agent
# Dials outbound TLS 1.3 + mutual TLS (client X.509 cert with SPIFFE SAN URI
# spiffe://backplane.enterprise/tenant/<tenant_id>/vm/<vm_id>, lifetime <=24h)
# to bp-ent-relay. Never opens inbound listening ports and never requires Tailscale.

CONFIG_FILE="${BOAT_CONFIG_FILE:-/etc/backplane-boat/config.env}"
if [[ -f "${CONFIG_FILE}" ]]; then
  # shellcheck disable=SC1090
  source "${CONFIG_FILE}"
fi

RELAY_MTLS_URL="${RELAY_MTLS_URL:?RELAY_MTLS_URL must be set (e.g. wss://relay.example.com:8443/v1/relay/boat/connect)}"
CERT_DIR="${CERT_DIR:-/etc/backplane-boat/certs}"
CA_CERT="${CERT_DIR}/ca.pem"
DEVICE_CERT="${CERT_DIR}/device.crt"
DEVICE_KEY="${CERT_DIR}/device.key"
LOCAL_HUB_URL="${LOCAL_HUB_URL:-http://127.0.0.1:3798}"
PEER_LISTEN_ADDR="${PEER_LISTEN_ADDR:-127.0.0.1:3799}"
MODE="${1:-run}"

require_certs() {
  for f in "${CA_CERT}" "${DEVICE_CERT}" "${DEVICE_KEY}"; do
    if [[ ! -r "${f}" ]]; then
      echo "boat-relay-agent: missing required mTLS credential file: ${f}" >&2
      exit 1
    fi
  done
}

enroll_cert() {
  local enroll_tok="${ENROLLMENT_TOKEN:?ENROLLMENT_TOKEN must be set for enrollment}"
  local api_url="${RELAY_API_URL:?RELAY_API_URL must be set for enrollment}"
  local vm_id="${VM_ID:?VM_ID must be set for enrollment}"

  mkdir -p "${CERT_DIR}"
  chmod 0700 "${CERT_DIR}"

  local tmp_dir
  tmp_dir="$(mktemp -d)"
  trap 'rm -rf "${tmp_dir}"' RETURN

  local new_key="${tmp_dir}/device.key"
  local new_csr="${tmp_dir}/device.csr"
  local req_json="${tmp_dir}/enroll-req.json"
  local resp_json="${tmp_dir}/enroll-resp.json"

  openssl ecparam -name prime256v1 -genkey -noout -out "${new_key}"
  chmod 0600 "${new_key}"
  openssl req -new -key "${new_key}" -subj "/CN=boat-${vm_id}" -out "${new_csr}"

  ENROLLMENT_TOKEN="${enroll_tok}" jq -n --rawfile csr "${new_csr}" \
    '{enrollmentToken: $ENV.ENROLLMENT_TOKEN, csrPem: $csr, ttlSecs: 86400}' > "${req_json}"

  local curl_ca=()
  if [[ -n "${ENROLL_CA_CERT:-}" ]]; then
    if [[ ! -r "${ENROLL_CA_CERT}" ]]; then
      echo "boat-relay-agent: ENROLL_CA_CERT is not readable: ${ENROLL_CA_CERT}" >&2
      exit 1
    fi
    curl_ca=(--cacert "${ENROLL_CA_CERT}")
  fi

  curl --fail --silent --show-error \
    "${curl_ca[@]}" \
    -X POST "${api_url%/}/v1/relay/boat/enroll" \
    -H "Content-Type: application/json" \
    --data-binary "@${req_json}" \
    -o "${resp_json}"

  jq -er '.caCertPem' "${resp_json}" > "${CA_CERT}"
  jq -er '.certPem' "${resp_json}" > "${DEVICE_CERT}"
  cp "${new_key}" "${DEVICE_KEY}"
  chmod 0644 "${CA_CERT}"
  chmod 0640 "${DEVICE_CERT}"
  chmod 0600 "${DEVICE_KEY}"
  echo "boat-relay-agent: enrolled <=24h mTLS device certificate via local CSR"
}

renew_cert() {
  require_certs
  # mTLS renewal talks directly to the mTLS listener (POST /v1/relay/boat/renew)
  # using a locally generated ECDSA P-256 keypair + CSR so the private key
  # NEVER leaves the Boat VM.
  RELAY_MTLS_API_URL="${RELAY_MTLS_API_URL:-${RELAY_API_URL:?RELAY_MTLS_API_URL or RELAY_API_URL must be set}}"
  VM_ID="${VM_ID:?VM_ID must be set}"

  local tmp_dir
  tmp_dir="$(mktemp -d)"
  trap 'rm -rf "${tmp_dir}"' RETURN

  local next_key="${tmp_dir}/device.key.next"
  local next_csr="${tmp_dir}/device.csr"
  local payload_json="${tmp_dir}/req.json"
  local resp_json="${tmp_dir}/resp.json"

  openssl ecparam -name prime256v1 -genkey -noout -out "${next_key}"
  chmod 0600 "${next_key}"
  openssl req -new -key "${next_key}" -subj "/CN=boat-${VM_ID}" -out "${next_csr}"

  jq -n --rawfile csr "${next_csr}" '{csrPem: $csr, ttlSecs: 86400}' > "${payload_json}"

  curl --fail --silent --show-error \
    --tlsv1.3 \
    --cacert "${CA_CERT}" \
    --cert "${DEVICE_CERT}" \
    --key "${DEVICE_KEY}" \
    -X POST "${RELAY_MTLS_API_URL%/}/v1/relay/boat/renew" \
    -H "Content-Type: application/json" \
    --data-binary "@${payload_json}" \
    -o "${resp_json}"

  local next_crt="${CERT_DIR}/device.crt.next"
  local installed_key="${CERT_DIR}/device.key.next"
  jq -er '.certPem' "${resp_json}" > "${next_crt}"
  cp "${next_key}" "${installed_key}"
  chmod 0640 "${next_crt}"
  chmod 0600 "${installed_key}"
  mv "${next_crt}" "${DEVICE_CERT}"
  mv "${installed_key}" "${DEVICE_KEY}"
  echo "boat-relay-agent: renewed <=24h mTLS device certificate via local CSR"
}

run_tunnel() {
  require_certs
  if [[ "${RELAY_MTLS_URL}" != wss://* ]]; then
    echo "boat-relay-agent: RELAY_MTLS_URL must use wss:// (TLS 1.3 + mTLS required)" >&2
    exit 1
  fi

  if command -v bp-ent-relay >/dev/null 2>&1; then
    echo "boat-relay-agent: dialing outbound TLS 1.3 mTLS tunnel to ${RELAY_MTLS_URL}"
    exec bp-ent-relay boat-agent \
      --relay-url "${RELAY_MTLS_URL}" \
      --ca-cert "${CA_CERT}" \
      --client-cert "${DEVICE_CERT}" \
      --client-key "${DEVICE_KEY}" \
      --local-hub "${LOCAL_HUB_URL}" \
      --peer-listen "${PEER_LISTEN_ADDR}"
  fi

  echo "boat-relay-agent: bp-ent-relay binary is required for mTLS tunnel" >&2
  exit 127
}

case "${MODE}" in
  enroll)
    enroll_cert
    ;;
  run)
    run_tunnel
    ;;
  renew)
    renew_cert
    ;;
  *)
    echo "Usage: $0 {enroll|run|renew}" >&2
    exit 2
    ;;
esac
