#!/usr/bin/env bash
# run-amb-setup.sh — Load AMB credentials from SSM, then call amb-setup.sh.
# Run this directly on EC2 (not via CI) to deploy chaincode one time.
#
#   ssh -i scytale-ec2.pem ubuntu@<EC2_IP>
#   cd ~/microservice && bash shyware/deploy/node/run-amb-setup.sh
#
set -euo pipefail

REGION="${AWS_REGION:-us-east-1}"
export AWS_DEFAULT_REGION="$REGION"

ssm() { aws ssm get-parameter --name "$1" --with-decryption --query Parameter.Value --output text; }

echo "▶ Loading credentials from SSM…"
export AMB_NETWORK_ID="$(ssm AMB_NETWORK_ID)"
export AMB_MEMBER_ID="$(ssm AMB_MEMBER_ID)"
export AMB_NODE_ENDPOINT="$(ssm AMB_NODE_ENDPOINT)"
export AMB_CA_ENDPOINT="$(ssm AMB_CA_ENDPOINT)"
export AMB_ADMIN_USERNAME="admin"
export AMB_ADMIN_PASSWORD="Scytale2026!"

echo "▶ Network  : $AMB_NETWORK_ID"
echo "▶ Member   : $AMB_MEMBER_ID"
echo "▶ Peer     : $AMB_NODE_ENDPOINT"

DIR="$(cd "$(dirname "$0")" && pwd)"
exec bash "${DIR}/amb-setup.sh"
