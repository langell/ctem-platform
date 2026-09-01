#!/usr/bin/env bash
# Mint a Keycloak access token for the seeded demo org and print it.
# Paste the JWT at http://localhost:3000/login — the UI has no password form.
set -euo pipefail

ISSUER="${OIDC_ISSUER:-http://localhost:8080/realms/ctem}"
TOKEN_URL="${ISSUER}/protocol/openid-connect/token"
CLIENT_ID="${OIDC_CLIENT_ID:-ctem-api}"
CLIENT_SECRET="${OIDC_CLIENT_SECRET:-ctem-demo}"
USERNAME="${DEMO_USERNAME:-analyst}"
PASSWORD="${DEMO_PASSWORD:-demo}"

if ! command -v curl >/dev/null; then
  echo "curl is required for make demo-token" >&2
  exit 1
fi

echo "waiting for ${ISSUER}…" >&2
for _ in $(seq 1 60); do
  if curl -sf "${ISSUER}" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

if ! curl -sf "${ISSUER}" >/dev/null 2>&1; then
  echo "Keycloak realm is not up at ${ISSUER}. Start infra with: make infra" >&2
  exit 1
fi

body="$(
  curl -sS -X POST "${TOKEN_URL}" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "grant_type=password" \
    --data-urlencode "client_id=${CLIENT_ID}" \
    --data-urlencode "client_secret=${CLIENT_SECRET}" \
    --data-urlencode "username=${USERNAME}" \
    --data-urlencode "password=${PASSWORD}"
)"

token="$(
  python3 -c 'import json,sys; print(json.load(sys.stdin).get("access_token") or "")' <<<"${body}"
)"

if [[ -z "${token}" ]]; then
  echo "Keycloak did not issue an access token:" >&2
  echo "${body}" >&2
  exit 1
fi

echo "${token}"
