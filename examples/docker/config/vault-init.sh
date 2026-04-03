#!/bin/sh
# =============================================================================
# Vault Initialization Script for PQC Demo
# =============================================================================
# Reads pre-generated ML-KEM key files (DER format), base64-encodes them,
# and stores them in Vault KV v2 using the HTTP API directly (wget, no vault CLI).
# =============================================================================

set -e

VAULT_ADDR="${VAULT_ADDR:-http://vault:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-pqc-demo-token}"
SECRET_PATH="${SECRET_PATH:-kroxylicious/pqc}"
PUB_KEY_FILE="${PUB_KEY_FILE:-/keys/pqc-public.der}"
PRIV_KEY_FILE="${PRIV_KEY_FILE:-/keys/pqc-private.der}"
X25519_PUB_KEY_FILE="${X25519_PUB_KEY_FILE:-/keys/x25519-public.der}"
X25519_PRIV_KEY_FILE="${X25519_PRIV_KEY_FILE:-/keys/x25519-private.der}"

echo "Waiting for Vault to be ready at ${VAULT_ADDR}..."
until wget -qO /dev/null "${VAULT_ADDR}/v1/sys/health" 2>/dev/null; do
  sleep 1
done
echo "Vault is ready."

# Base64-encode the DER key files
PUB_KEY_B64=$(base64 -w 0 "${PUB_KEY_FILE}")
PRIV_KEY_B64=$(base64 -w 0 "${PRIV_KEY_FILE}")
X25519_PUB_B64=$(base64 -w 0 "${X25519_PUB_KEY_FILE}")
X25519_PRIV_B64=$(base64 -w 0 "${X25519_PRIV_KEY_FILE}")

echo "Storing ML-KEM + X25519 key pairs in Vault at secret/data/${SECRET_PATH}..."
BODY="{\"data\":{\"publicKey\":\"${PUB_KEY_B64}\",\"privateKey\":\"${PRIV_KEY_B64}\",\"x25519PublicKey\":\"${X25519_PUB_B64}\",\"x25519PrivateKey\":\"${X25519_PRIV_B64}\"}}"

wget -qO /dev/null \
  --header="X-Vault-Token: ${VAULT_TOKEN}" \
  --header="Content-Type: application/json" \
  --post-data="${BODY}" \
  "${VAULT_ADDR}/v1/secret/data/${SECRET_PATH}"

echo "Keys stored. Verifying..."
wget -qO /dev/null \
  --header="X-Vault-Token: ${VAULT_TOKEN}" \
  "${VAULT_ADDR}/v1/secret/data/${SECRET_PATH}"

echo "Keys successfully stored and verified in Vault."
