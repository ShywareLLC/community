#!/usr/bin/env bash
# amb-setup.sh — one-time AMB member enrollment + channel + chaincode setup on EC2.
# Run after creating a new AMB member or when credentials need to be refreshed.
#
# Required env vars (export before running or source from .env):
#   AMB_NETWORK_ID       e.g. n-GEV5GR5MKVACRJVKE55KAEAVBY
#   AMB_MEMBER_ID        e.g. m-XXXXXXXXXXXXXXXXXXXXXXXXXXXX
#   AMB_NODE_ENDPOINT    e.g. nd-XXXX.m-XXXX.n-XXXX.managedblockchain.us-east-1.amazonaws.com:30003
#   AMB_CA_ENDPOINT      e.g. ca.m-XXXX.n-XXXX.managedblockchain.us-east-1.amazonaws.com:30002
#   AMB_ADMIN_USERNAME   e.g. admin
#   AMB_ADMIN_PASSWORD   e.g. YourPassword123!
#
# Optional overrides:
#   CHANNEL   (default: shyware)
#   CHAINCODE (default: shyware)
set -euo pipefail

CHANNEL="${CHANNEL:-shyware}"
CHAINCODE="${CHAINCODE:-shyware}"
MSP_DIR="/home/ubuntu/fabric/admin/msp"
TLS_CERT="/home/ubuntu/managedblockchain-tls-chain.pem"
CHAINCODE_SRC="/home/ubuntu/microservice/shyware/domain/state/fabric"

# ── 0. Validate env ──────────────────────────────────────────────────────────
for var in AMB_NETWORK_ID AMB_MEMBER_ID AMB_NODE_ENDPOINT AMB_CA_ENDPOINT AMB_ADMIN_USERNAME AMB_ADMIN_PASSWORD; do
  [ -n "${!var:-}" ] || { echo "❌ $var is required"; exit 1; }
done

echo "▶ Network  : $AMB_NETWORK_ID"
echo "▶ Member   : $AMB_MEMBER_ID"
echo "▶ Peer     : $AMB_NODE_ENDPOINT"
echo "▶ CA       : $AMB_CA_ENDPOINT"

# ── 1. TLS cert ─────────────────────────────────────────────────────────────
if [ ! -f "$TLS_CERT" ]; then
  echo "▶ Downloading AMB TLS cert…"
  aws s3 cp s3://us-east-1.managedblockchain/etc/managedblockchain-tls-chain.pem "$TLS_CERT"
fi

# ── 2. fabric-ca-client ──────────────────────────────────────────────────────
if ! command -v fabric-ca-client &>/dev/null; then
  echo "▶ Installing fabric-ca-client…"
  GOPATH=/home/ubuntu/go
  mkdir -p "$GOPATH"
  export GOPATH
  export PATH="$GOPATH/bin:$PATH"
  go install github.com/hyperledger/fabric-ca/cmd/fabric-ca-client@v1.5.7
fi

# ── 3. Enroll admin ──────────────────────────────────────────────────────────
if [ ! -f "$MSP_DIR/signcerts/cert.pem" ]; then
  echo "▶ Enrolling admin with AMB CA…"
  mkdir -p "$MSP_DIR"
  export FABRIC_CA_CLIENT_HOME="$MSP_DIR/.."
  fabric-ca-client enroll \
    -u "https://${AMB_ADMIN_USERNAME}:${AMB_ADMIN_PASSWORD}@${AMB_CA_ENDPOINT}" \
    --tls.certfiles "$TLS_CERT" \
    -M "$MSP_DIR"
  echo "✓ Admin enrolled — cert at $MSP_DIR/signcerts/cert.pem"
else
  echo "✓ Admin cert already exists, skipping enrollment"
fi

# ── 4. Peer binary ───────────────────────────────────────────────────────────
if ! command -v peer &>/dev/null; then
  echo "▶ Downloading Fabric peer binary…"
  curl -sSL https://bit.ly/2ysbOFE | bash -s -- 2.4.9 1.5.7 -d -s
  export PATH="$HOME/fabric-samples/bin:$PATH"
fi

export CORE_PEER_TLS_ENABLED=true
export CORE_PEER_TLS_ROOTCERT_FILE="$TLS_CERT"
export CORE_PEER_ADDRESS="$AMB_NODE_ENDPOINT"
export CORE_PEER_LOCALMSPID="$AMB_MEMBER_ID"
export CORE_PEER_MSPCONFIGPATH="$MSP_DIR"
# AMB orderer endpoint: static per network, follows known pattern
# Try aws CLI first; fall back to constructed endpoint if not available
REGION="${AWS_REGION:-us-east-1}"
if [ -z "${ORDERER:-}" ]; then
  ORDERER=$(aws managedblockchain get-network \
    --network-id "$AMB_NETWORK_ID" \
    --query 'Network.FrameworkAttributes.Fabric.OrderingServiceEndpoint' \
    --output text)
fi
echo "▶ Orderer  : $ORDERER"

# ── 5. Create / join channel ─────────────────────────────────────────────────
CHANNEL_BLOCK="/home/ubuntu/fabric/${CHANNEL}.block"
if ! peer channel list | grep -q "^${CHANNEL}$"; then
  if [ ! -f "$CHANNEL_BLOCK" ]; then
    echo "▶ Fetching channel block…"
    peer channel fetch oldest "$CHANNEL_BLOCK" \
      -c "$CHANNEL" \
      -o "$ORDERER" \
      --tls --cafile "$TLS_CERT"
  fi
  echo "▶ Joining peer to channel $CHANNEL…"
  peer channel join -b "$CHANNEL_BLOCK"
else
  echo "✓ Already joined channel $CHANNEL"
fi

# ── 6. Package, install, instantiate chaincode ───────────────────────────────
CC_PKG="/home/ubuntu/fabric/${CHAINCODE}.tar.gz"

if [ ! -f "$CC_PKG" ]; then
  echo "▶ Packaging chaincode…"
  pushd "$CHAINCODE_SRC" >/dev/null
  go mod vendor
  popd >/dev/null
  peer lifecycle chaincode package "$CC_PKG" \
    --path "$CHAINCODE_SRC" \
    --lang golang \
    --label "${CHAINCODE}_1.0"
fi

PKG_ID=$(peer lifecycle chaincode queryinstalled 2>&1 \
  | grep "${CHAINCODE}_1.0" | awk -F'Package ID: ' '{print $2}' | awk -F', Label' '{print $1}')

if [ -z "$PKG_ID" ]; then
  echo "▶ Installing chaincode…"
  peer lifecycle chaincode install "$CC_PKG"
  PKG_ID=$(peer lifecycle chaincode queryinstalled 2>&1 \
    | grep "${CHAINCODE}_1.0" | awk -F'Package ID: ' '{print $2}' | awk -F', Label' '{print $1}')
else
  echo "✓ Chaincode already installed"
fi
echo "  Package ID: $PKG_ID"

echo "▶ Approving chaincode…"
peer lifecycle chaincode approveformyorg \
  -o "$ORDERER" --tls --cafile "$TLS_CERT" \
  --channelID "$CHANNEL" --name "$CHAINCODE" \
  --version 1.0 --package-id "$PKG_ID" --sequence 1

echo "▶ Committing chaincode…"
peer lifecycle chaincode commit \
  -o "$ORDERER" --tls --cafile "$TLS_CERT" \
  --channelID "$CHANNEL" --name "$CHAINCODE" \
  --version 1.0 --sequence 1 \
  --peerAddresses "$AMB_NODE_ENDPOINT" \
  --tlsRootCertFiles "$TLS_CERT"

echo ""
echo "✓ AMB setup complete."
echo ""
echo "Add these to GitHub secrets (Settings → Secrets → Actions):"
echo "  AMB_ADMIN_CERT_PATH = $MSP_DIR/signcerts/cert.pem"
echo "  AMB_ADMIN_KEY_PATH  = $MSP_DIR/keystore/"
echo "  FABRIC_MODE         = amb"
echo ""
echo "Then trigger a deploy to restart the scytale process with the new credentials."
