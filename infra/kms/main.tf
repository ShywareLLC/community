# Protocol KMS signing keys — shared module.
# Creates ECC_NIST_P256 asymmetric signing keys for validator block-signing
# and tally attestation. Key material is FIPS 140-2 Level 3 HSM-backed.
# Neither key can decrypt; both are sign-only (key_usage = "SIGN_VERIFY").
#
# Used by both blockchain/ and seda-haqq/ deployments.
# Instantiate once per environment; pass outputs into iam-roles-anywhere/ and validator/ modules.

terraform {
  required_version = ">= 1.7.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Validator signing key — used by the ABCI app for consensus participation signatures.
resource "aws_kms_key" "validator" {
  description              = "${var.environment} ${var.project} validator signing key"
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"  # FIPS 140-2 L3; Ed25519 not available in KMS

  deletion_window_in_days = 30
  enable_key_rotation     = false  # Asymmetric keys do not support automatic rotation

  tags = {
    project     = var.project
    environment = var.environment
    purpose     = "validator-signing"
    managed-by  = "terraform"
  }
}

resource "aws_kms_alias" "validator" {
  name          = "alias/${var.environment}-${var.project}-validator"
  target_key_id = aws_kms_key.validator.key_id
}

# Tally signing key — used by the ABCI app to sign the closed tally record.
resource "aws_kms_key" "tally" {
  description              = "${var.environment} ${var.project} tally signing key"
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"

  deletion_window_in_days = 30
  enable_key_rotation     = false

  tags = {
    project     = var.project
    environment = var.environment
    purpose     = "tally-signing"
    managed-by  = "terraform"
  }
}

resource "aws_kms_alias" "tally" {
  name          = "alias/${var.environment}-${var.project}-tally"
  target_key_id = aws_kms_key.tally.key_id
}

# CloudWatch log group for KMS CloudTrail audit events.
resource "aws_cloudwatch_log_group" "kms_audit" {
  name              = "/aws/kms/${var.environment}-${var.project}"
  retention_in_days = 90

  tags = {
    project     = var.project
    environment = var.environment
    managed-by  = "terraform"
  }
}
variable "project"     { type = string }   # "populist" | "seda-haqq"
variable "environment" { type = string }   # "production" | "staging"

output "validator_key_arn" { value = aws_kms_key.validator.arn }
output "tally_key_arn"     { value = aws_kms_key.tally.arn }
output "validator_key_id"  { value = aws_kms_key.validator.key_id }
output "tally_key_id"      { value = aws_kms_key.tally.key_id }
