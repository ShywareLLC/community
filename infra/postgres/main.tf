# Shared Hetzner PostgreSQL module — used by both blockchain/ and seda-haqq/.
# Parameterized by project so database name, users, and labels are correct
# for each deployment. Private IP is also parameterized so each deployment
# can sit on its own Hetzner VPC CIDR.

resource "hcloud_server" "postgres" {
  name        = "${var.environment}-${var.project}-postgres"
  image       = "ubuntu-22.04"
  server_type = "cpx31"  # 4 vCPU, 8 GB RAM, 160 GB SSD
  location    = var.location

  firewall_ids = [var.firewall_id]

  network {
    network_id = var.network_id
    ip         = var.private_ip
  }

  user_data = templatefile("${path.module}/cloud-init.sh", {
    project              = var.project
    private_ip           = var.private_ip
    postgres_password    = var.postgres_password
    api_reader_password  = var.api_reader_password
  })

  labels = {
    environment = var.environment
    project     = var.project
    role        = "postgres"
  }
}

resource "hcloud_volume" "postgres_data" {
  name      = "${var.environment}-${var.project}-postgres-data"
  size      = 100  # GB — separate from boot disk
  server_id = hcloud_server.postgres.id
  automount = true
  format    = "ext4"

  labels = {
    environment = var.environment
    project     = var.project
  }
}
variable "project"             { type = string }
variable "environment"         { type = string }
variable "network_id"          { type = string }
variable "firewall_id"         { type = string }
variable "private_ip"          { type = string; default = "10.0.1.30" }
variable "location"            { type = string; default = "ash" }
variable "postgres_password"   { type = string; sensitive = true }
variable "api_reader_password" { type = string; sensitive = true }

output "server_id"  { value = hcloud_server.postgres.id }
output "private_ip" { value = var.private_ip }
output "volume_id"  { value = hcloud_volume.postgres_data.id }
