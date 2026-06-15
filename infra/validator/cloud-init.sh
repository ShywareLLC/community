#!/bin/bash
set -euo pipefail

# Protocol validator bootstrap — Hetzner CPX31
#
# Installs:
#   1. CometBFT + ${binary_name}              (consensus + two-list voting ABCI)
#   2. cloudflared inbound tunnel             (users → Cloudflare edge → :8080; hides origin IP)
#   3. cloudflared WARP Connector             (ADOT → Cloudflare PoP → AWS; masks AWS FQDNs from DPI)
#   4. AWS IAM Roles Anywhere signing helper  (X.509 → temp STS; no static AWS keys)
#   5. AWS Distro for OpenTelemetry Collector (traces → X-Ray, logs → CloudWatch)
#   6. Tor hidden service                     (optional; set tor_enabled=true for censorship resistance)
#
# Auth to AWS KMS (FIPS signing) and ADOT (observability) both use the same
# IAM Roles Anywhere role — no static access keys anywhere on disk.
#
# Variables: populated by Terraform templatefile()

apt-get update && apt-get upgrade -y
apt-get install -y curl wget jq unzip ufw openssl ca-certificates gnupg lsb-release

# ── Tor (optional) ────────────────────────────────────────────────────────────

%{ if tor_enabled }
apt-get install -y tor
%{ endif }

# ── CometBFT ─────────────────────────────────────────────────────────────────

COMETBFT_VERSION="0.38.5"
wget -q "https://github.com/cometbft/cometbft/releases/download/v$COMETBFT_VERSION/cometbft_$${COMETBFT_VERSION}_linux_amd64.tar.gz"
tar -xzf "cometbft_$${COMETBFT_VERSION}_linux_amd64.tar.gz"
mv cometbft /usr/local/bin/ && chmod +x /usr/local/bin/cometbft

export CMTHOME=${data_dir}/cometbft
cometbft init --home "$CMTHOME"

cat > "$CMTHOME/config/config.toml" <<TOMLEOF
proxy_app = "tcp://127.0.0.1:26658"
moniker = "${environment}-${service_name}-validator"

[rpc]
laddr = "tcp://0.0.0.0:26657"
cors_allowed_origins = ["*"]

[p2p]
laddr = "tcp://0.0.0.0:26656"
external_address = ""
persistent_peers = "${persistent_peers}"

[mempool]
size = 5000
max_tx_bytes = 1048576

[consensus]
timeout_propose   = "${consensus_timeout_propose}"
timeout_prevote   = "1s"
timeout_precommit = "1s"
timeout_commit    = "${consensus_timeout_commit}"

[instrumentation]
prometheus = true
prometheus_listen_addr = ":26660"
TOMLEOF

# ── ABCI binary ──────────────────────────────────────────────────────────────

mkdir -p ${data_dir}/data ${data_dir}/iam
if [ -n "${artifact_url}" ]; then
  wget -q -O /usr/local/bin/${binary_name} "${artifact_url}" \
    || echo "${binary_name} not available yet — deploy via CI/CD"
  chmod +x /usr/local/bin/${binary_name} || true
else
  echo "No artifact_url provided — ${binary_name} must be deployed manually"
fi

# ── cloudflared inbound tunnel ────────────────────────────────────────────────
# Outbound-only tunnel from this VM to Cloudflare edge.
# API clients connect to Cloudflare → tunnel → :8080 here. Origin IP not in DNS.

CLOUDFLARED_VERSION="2024.6.1"
wget -q "https://github.com/cloudflare/cloudflared/releases/download/$${CLOUDFLARED_VERSION}/cloudflared-linux-amd64.deb"
dpkg -i cloudflared-linux-amd64.deb

if [ -n "${cloudflare_tunnel_token}" ]; then
  cat > /etc/systemd/system/cloudflared.service <<SVCEOF
[Unit]
Description=Cloudflare Tunnel (inbound — API)
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/cloudflared tunnel --no-autoupdate run \
  --token ${cloudflare_tunnel_token}
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
SVCEOF
  systemctl enable cloudflared
else
  echo "cloudflare_tunnel_token not set — inbound tunnel disabled"
fi

# ── cloudflared WARP Connector ────────────────────────────────────────────────
# Routes ADOT → AWS KMS/X-Ray/CloudWatch through Cloudflare's network.
# ADOT systemd unit sets HTTPS_PROXY=http://127.0.0.1:8118.
# DPI at Hetzner egress sees TLS to Cloudflare PoP IPs, not AWS API FQDNs.

if [ -n "${cloudflare_warp_token}" ]; then
  cat > /etc/systemd/system/cloudflared-warp.service <<SVCEOF
[Unit]
Description=Cloudflare WARP Connector (outbound proxy for KMS + ADOT)
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/cloudflared tunnel --no-autoupdate run \
  --token ${cloudflare_warp_token} \
  --proxy-address 127.0.0.1 \
  --proxy-port 8118
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
SVCEOF
  systemctl enable cloudflared-warp
  WARP_PROXY="http://127.0.0.1:8118"
else
  echo "cloudflare_warp_token not set — KMS/ADOT will egress directly"
  WARP_PROXY=""
fi

# ── AWS IAM Roles Anywhere signing helper ────────────────────────────────────
# Exchanges ${data_dir}/iam/validator.{crt,key} for 1-hour STS tokens.
# Provides credentials for BOTH aws kms sign calls AND ADOT telemetry.
# No static AWS credentials anywhere on disk.
#
# Cert issuance: see cert_issue_command output in iam-roles-anywhere module.

SIGNING_HELPER_VERSION="1.1.1"
wget -q -O /usr/local/bin/aws_signing_helper \
  "https://rolesanywhere.amazonaws.com/releases/$${SIGNING_HELPER_VERSION}/X86_64/Linux/aws_signing_helper"
chmod +x /usr/local/bin/aws_signing_helper

mkdir -p /root/.aws
cat > /root/.aws/config <<AWSCFG
[default]
region = ${aws_region}

[profile ${service_name}-validator]
credential_process = /usr/local/bin/aws_signing_helper credential-process \
  --certificate ${data_dir}/iam/validator.crt \
  --private-key ${data_dir}/iam/validator.key \
  --trust-anchor-arn ${roles_anywhere_trust_anchor_arn} \
  --profile-arn ${roles_anywhere_profile_arn} \
  --role-arn ${iam_role_arn}
AWSCFG
chmod 600 /root/.aws/config

# ── AWS Distro for OpenTelemetry Collector ────────────────────────────────────

ADOT_VERSION="0.40.0"
mkdir -p /etc/adot
wget -q -O /tmp/adot-collector.deb \
  "https://aws-otel-collector.s3.amazonaws.com/ubuntu/amd64/$${ADOT_VERSION}/aws-otel-collector.deb"
dpkg -i /tmp/adot-collector.deb || true

cat > /etc/adot/config.yaml <<ADOTEOF
extensions:
  health_check:
    endpoint: "127.0.0.1:13133"

receivers:
  otlp:
    protocols:
      grpc:
        endpoint: "127.0.0.1:4317"
      http:
        endpoint: "127.0.0.1:4318"
  prometheus:
    config:
      scrape_configs:
        - job_name: "cometbft"
          scrape_interval: 30s
          static_configs:
            - targets: ["127.0.0.1:26660"]

processors:
  batch:
    timeout: 10s
    send_batch_size: 100
    send_batch_max_size: 200
  memory_limiter:
    check_interval: 5s
    limit_mib: 256
    spike_limit_mib: 64
  resource:
    attributes:
      - key: "chain.id"
        value: "${chain_id}"
        action: upsert
      - key: "validator.environment"
        value: "${environment}"
        action: upsert
      - key: "validator.location"
        value: "${location}"
        action: upsert
      - key: "service.name"
        value: "${service_name}-validator"
        action: upsert
  filter/pii:
    error_mode: ignore
    traces:
      span:
        - 'attributes["identity_hash"] != nil'
        - 'attributes["didit_proof_hash"] != nil'

exporters:
  awsxray:
    region: "${aws_region}"
    role_arn: "${iam_role_arn}"
    proxy_address: "$WARP_PROXY"
    no_verify_ssl: false
  awscloudwatchlogs:
    region: "${aws_region}"
    log_group_name: "/${project}/validators/${environment}"
    log_stream_name: "${chain_id}-${location}"
    role_arn: "${iam_role_arn}"
    proxy_address: "$WARP_PROXY"
  awsemf:
    region: "${aws_region}"
    namespace: "${project}"
    role_arn: "${iam_role_arn}"
    proxy_address: "$WARP_PROXY"
    dimension_rollup_option: "NoDimensionRollup"

service:
  extensions: [health_check]
  pipelines:
    traces:
      receivers:  [otlp]
      processors: [memory_limiter, filter/pii, resource, batch]
      exporters:  [awsxray]
    logs:
      receivers:  [otlp]
      processors: [memory_limiter, filter/pii, resource, batch]
      exporters:  [awscloudwatchlogs]
    metrics:
      receivers:  [prometheus, otlp]
      processors: [memory_limiter, resource, batch]
      exporters:  [awsemf]
  telemetry:
    logs:
      level: "warn"
    metrics:
      level: "none"
ADOTEOF

cat > /etc/systemd/system/adot-collector.service <<SVCEOF
[Unit]
Description=AWS Distro for OpenTelemetry Collector
After=network.target cloudflared-warp.service
Wants=cloudflared-warp.service

[Service]
Type=simple
User=root
Environment=AWS_PROFILE=${service_name}-validator
Environment=AWS_REGION=${aws_region}
ExecStart=/opt/aws/aws-otel-collector/bin/aws-otel-collector \
  --config /etc/adot/config.yaml
Restart=on-failure
RestartSec=15

[Install]
WantedBy=multi-user.target
SVCEOF

# ── ABCI systemd service ──────────────────────────────────────────────────────

cat > /etc/systemd/system/${service_name}-abci.service <<SVCEOF
[Unit]
Description=${project} ABCI Application
After=network.target adot-collector.service

[Service]
Type=simple
User=root
Environment=CHAIN_ID=${chain_id}
Environment=KMS_VALIDATOR_KEY_ID=${kms_validator_key_id}
Environment=KMS_TALLY_KEY_ID=${kms_tally_key_id}
Environment=AWS_REGION=${aws_region}
Environment=AWS_PROFILE=${service_name}-validator
Environment=OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318
Environment=OTEL_SERVICE_NAME=${service_name}-abci
Environment=OTEL_RESOURCE_ATTRIBUTES=chain.id=${chain_id},validator.location=${location}
ExecStart=/usr/local/bin/${binary_name} \
  --chain-id=${chain_id} \
  --kms-key-id=${kms_validator_key_id} \
  --tally-kms-key-id=${kms_tally_key_id} \
  --db-path=${data_dir}/data
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
SVCEOF

# ── CometBFT systemd service ──────────────────────────────────────────────────

cat > /etc/systemd/system/${service_name}.service <<SVCEOF
[Unit]
Description=${project} CometBFT Node
After=network.target ${service_name}-abci.service
Requires=${service_name}-abci.service

[Service]
Type=simple
User=root
Environment=CMTHOME=${data_dir}/cometbft
ExecStart=/usr/local/bin/cometbft start --home ${data_dir}/cometbft
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
SVCEOF

# ── Backend API systemd service ───────────────────────────────────────────────

cat > /etc/systemd/system/${service_name}-api.service <<SVCEOF
[Unit]
Description=${project} Backend API
After=network.target ${service_name}.service

[Service]
Type=simple
User=root
Environment=AWS_PROFILE=${service_name}-validator
Environment=OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318
Environment=OTEL_SERVICE_NAME=${service_name}-api
Environment=OTEL_RESOURCE_ATTRIBUTES=chain.id=${chain_id},validator.location=${location}
ExecStart=/usr/local/bin/${service_name}-api \
  --cometbft-rpc=http://127.0.0.1:26657 \
  --port=8080
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
SVCEOF

# ── Firewall ──────────────────────────────────────────────────────────────────
# Port 8080: NOT opened — all user traffic arrives through cloudflared tunnel.
# ADOT (4317/4318) and KMS calls egress outbound; no inbound ports needed for them.

ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp      # SSH
ufw allow 26657/tcp   # CometBFT RPC (inter-validator + health probes)
ufw allow 26656/tcp   # CometBFT P2P
ufw allow 26660/tcp   # Prometheus (restrict to Hetzner private network at cloud firewall level)
ufw --force enable

# ── Tor hidden service (optional) ─────────────────────────────────────────────

%{ if tor_enabled }
cat >> /etc/tor/torrc <<TOREOF
HiddenServiceDir /var/lib/tor/${service_name}/
HiddenServicePort 80 127.0.0.1:8080
TOREOF
systemctl enable tor
systemctl start tor
%{ endif }

# ── Enable services ───────────────────────────────────────────────────────────

systemctl daemon-reload
systemctl enable ${service_name}-abci ${service_name} ${service_name}-api adot-collector

# Start infrastructure services now; blockchain services wait for genesis.json
[ -n "${cloudflare_tunnel_token}" ] && systemctl start cloudflared      || true
[ -n "${cloudflare_warp_token}" ]   && systemctl start cloudflared-warp || true
systemctl start adot-collector || echo "ADOT start deferred — cert not yet issued"

# Extract CometBFT validator pubkey for genesis construction
cometbft show-validator --home "${data_dir}/cometbft" > ${data_dir}/validator_pubkey.txt 2>/dev/null || true

echo "Bootstrap complete. Chain: ${chain_id} / Location: ${location}"
echo ""
echo "NEXT STEPS:"
echo "  1. CometBFT validator pubkey: cat ${data_dir}/validator_pubkey.txt"
echo "  2. Issue X.509 cert (see cert_issue_command output in iam-roles-anywhere module)"
echo "  3. Place genesis: ${data_dir}/cometbft/config/genesis.json"
echo "  4. Start: systemctl start ${service_name}-abci && sleep 3 && systemctl start ${service_name}"
%{ if tor_enabled }
echo ""
echo "Tor .onion: cat /var/lib/tor/${service_name}/hostname"
%{ endif }
