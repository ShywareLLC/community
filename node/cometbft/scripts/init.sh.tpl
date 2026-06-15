#!/bin/bash
set -euo pipefail

# Protocol-shared CometBFT init script template.
# Deployment vars injected at provisioning time:
#   CHAIN_ID, MONIKER, TIMEOUT_PROPOSE, TIMEOUT_COMMIT
# These are set in each deployment's cloud-init.sh via the validator Terraform module.

CMTHOME=${CMTHOME:-$HOME/.cometbft}

echo "Initializing CometBFT node at $CMTHOME"

cometbft init --home "$CMTHOME"

if [ -f "config/genesis.json.template" ]; then
  echo "Using genesis template"
  cp config/genesis.json.template "$CMTHOME/config/genesis.json"
fi

cat > "$CMTHOME/config/config.toml" <<EOF
proxy_app = "tcp://127.0.0.1:26658"
moniker   = "${MONIKER}"

[rpc]
laddr                = "tcp://0.0.0.0:26657"
cors_allowed_origins = ["*"]

[p2p]
laddr             = "tcp://0.0.0.0:26656"
external_address  = ""
seed_mode         = false
persistent_peers  = ""

[mempool]
size         = 5000
max_tx_bytes = 1048576

[consensus]
timeout_propose   = "${TIMEOUT_PROPOSE}"
timeout_prevote   = "1s"
timeout_precommit = "1s"
timeout_commit    = "${TIMEOUT_COMMIT}"

[instrumentation]
prometheus             = true
prometheus_listen_addr = ":26660"
EOF

echo "✅ CometBFT initialized — chain: ${CHAIN_ID}, moniker: ${MONIKER}"
echo "   ABCI: tcp://127.0.0.1:26658  RPC: tcp://0.0.0.0:26657  P2P: tcp://0.0.0.0:26656"
