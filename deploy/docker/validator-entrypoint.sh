#!/bin/sh
# Validator container entrypoint for shyvoting-abci.
# Starts ABCI first (socket must be ready before CometBFT connects),
# waits for the port, then execs CometBFT.

set -e

CHAIN_ID="${CHAIN_ID:-shyvoting-1}"
KMS_KEY_ID="${KMS_KEY_ID:-}"
DB_PATH="${DB_PATH:-/data/db}"
ABCI_ADDR="${ABCI_ADDR:-tcp://0.0.0.0:26658}"
COMETBFT_HOME="${COMETBFT_HOME:-/cometbft}"
LOG_LEVEL="${LOG_LEVEL:-info}"

# Identity mode — set by deployment shyconfig.
# didit | zk | identus | wallet
IDENTITY_MODE="${IDENTITY_MODE:-didit}"
DIDIT_PUBKEY="${DIDIT_PUBKEY:-}"
ZK_VK_PATH="${ZK_VK_PATH:-}"
IDENTUS_ISSUER_PUBKEY="${IDENTUS_ISSUER_PUBKEY:-}"

echo "[entrypoint] Starting shyvoting-abci on ${ABCI_ADDR} (identity_mode=${IDENTITY_MODE}) ..."
shyvoting-abci \
  --addr                  "$ABCI_ADDR" \
  --chain-id              "$CHAIN_ID" \
  --kms-key-id            "$KMS_KEY_ID" \
  --db-path               "$DB_PATH" \
  --log-level             "$LOG_LEVEL" \
  --identity-mode         "$IDENTITY_MODE" \
  --didit-pubkey          "$DIDIT_PUBKEY" \
  --zk-vk-path            "$ZK_VK_PATH" \
  --identus-issuer-pubkey "$IDENTUS_ISSUER_PUBKEY" &

ABCI_PID=$!

echo "[entrypoint] Waiting for ABCI socket on port 26658 ..."
i=0
while ! nc -z 127.0.0.1 26658 2>/dev/null; do
  i=$((i+1))
  if [ $i -ge 30 ]; then
    echo "[entrypoint] ERROR: ABCI did not open port 26658 within 15s" >&2
    exit 1
  fi
  sleep 0.5
done
echo "[entrypoint] ABCI ready. Starting CometBFT ..."

trap 'kill $ABCI_PID; exit 0' TERM INT

exec cometbft start --home "$COMETBFT_HOME"
