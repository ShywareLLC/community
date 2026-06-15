# Protocol validator — shared Hetzner CPX31 module.
# Compute is Hetzner (EU jurisdiction). KMS signing and ADOT observability
# call AWS over HTTPS; key material never leaves AWS HSM.
# Auth: IAM Roles Anywhere (X.509 cert → 1-hour STS token; no static keys).
#
# Chain-specific values (binary_name, service_name, data_dir, chain_id, etc.)
# are passed as variables by the deployment wrapper.

resource "hcloud_ssh_key" "validator" {
  name       = "${var.environment}-${var.project}-validator"
  public_key = var.ssh_public_key
}

resource "hcloud_server" "validator" {
  name        = "${var.environment}-${var.project}-validator"
  image       = "ubuntu-22.04"
  server_type = "cpx31"   # 4 vCPU, 8GB RAM, 160GB SSD — ~$14/mo
  location    = var.location

  ssh_keys     = [hcloud_ssh_key.validator.id]
  firewall_ids = [var.firewall_id]

  network {
    network_id = var.network_id
    ip         = var.private_ip
  }

  user_data = templatefile("${path.module}/cloud-init.sh", {
    environment                     = var.environment
    project                         = var.project
    chain_id                        = var.chain_id
    location                        = var.location
    binary_name                     = var.binary_name
    service_name                    = var.service_name
    data_dir                        = var.data_dir
    persistent_peers                = var.persistent_peers
    artifact_url                    = var.artifact_url
    kms_validator_key_id            = var.kms_validator_key_id
    kms_tally_key_id                = var.kms_tally_key_id
    aws_region                      = var.aws_region
    iam_role_arn                    = var.iam_role_arn
    roles_anywhere_trust_anchor_arn = var.roles_anywhere_trust_anchor_arn
    roles_anywhere_profile_arn      = var.roles_anywhere_profile_arn
    cloudflare_tunnel_token         = var.cloudflare_tunnel_token
    cloudflare_warp_token           = var.cloudflare_warp_token
    tor_enabled                     = var.tor_enabled
    consensus_timeout_propose       = var.consensus_timeout_propose
    consensus_timeout_commit        = var.consensus_timeout_commit
  })

  labels = {
    environment  = var.environment
    project      = var.project
    role         = "validator"
    managed-by   = "terraform"
    jurisdiction = var.jurisdiction
  }
}
# ── Required ─────────────────────────────────────────────────────────────────

variable "environment"     { type = string }
variable "project"         { type = string }   # "populist" | "seda-haqq"
variable "network_id"      { type = string }
variable "firewall_id"     { type = string }
variable "ssh_public_key"  { type = string }

# ── Chain ─────────────────────────────────────────────────────────────────────

variable "chain_id"        { type = string }
variable "binary_name"     { type = string }   # "populist-abci" | "seda-haqq-abci"
variable "service_name"    { type = string }   # "populist"      | "seda-haqq"
variable "data_dir"        { type = string }   # "/opt/populist" | "/opt/seda-haqq"
variable "artifact_url"    { type = string; default = "" }
variable "persistent_peers" { type = string; default = "" }

# ── KMS signing (FIPS 140-2 L3) ──────────────────────────────────────────────

variable "kms_validator_key_id" { type = string }
variable "kms_tally_key_id"     { type = string }

# ── IAM Roles Anywhere (replaces static access keys) ─────────────────────────

variable "iam_role_arn"                    { type = string }
variable "roles_anywhere_trust_anchor_arn" { type = string }
variable "roles_anywhere_profile_arn"      { type = string }
variable "aws_region"                      { type = string; default = "us-east-1" }

# ── Cloudflare ────────────────────────────────────────────────────────────────
# Tunnel: Cloudflare edge → :8080 (hides Hetzner origin IP)
# WARP:   ADOT → Cloudflare PoP → AWS (masks AWS FQDNs from DPI)

variable "cloudflare_tunnel_token" {
  type      = string
  sensitive = true
  default   = ""
}

variable "cloudflare_warp_token" {
  type      = string
  sensitive = true
  default   = ""
}

# ── Network / topology ────────────────────────────────────────────────────────

variable "location"     { type = string; default = "nbg1" }   # Hetzner location code
variable "private_ip"   { type = string; default = "10.0.0.10" }
variable "jurisdiction" { type = string; default = "eu" }     # label only

# ── Chain timing ──────────────────────────────────────────────────────────────

variable "consensus_timeout_propose" { type = string; default = "2s" }
variable "consensus_timeout_commit"  { type = string; default = "3s" }

# ── Optional features ─────────────────────────────────────────────────────────

variable "tor_enabled" { type = bool; default = false }

output "server_id"         { value = hcloud_server.validator.id }
output "server_ip"         { value = hcloud_server.validator.ipv4_address }
output "server_name"       { value = hcloud_server.validator.name }
output "ssh_key_id"        { value = hcloud_ssh_key.validator.id }
