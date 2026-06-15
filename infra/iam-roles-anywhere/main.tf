# Protocol IAM Roles Anywhere — shared module.
# Replaces static IAM access keys on validators with certificate-based auth.
#
# Design: each Hetzner validator generates a local X.509 keypair on first boot.
# The operator issues a cert signed by this ACM PCA. The aws_signing_helper
# credential-process exchanges the cert for 1-hour STS tokens — no static keys.
#
# Single IAM role covers:
#   • kms:Sign + read-only on validator and tally KMS keys (FIPS signing)
#   • ADOT observability: X-Ray write, CloudWatch Logs /{project}/, CloudWatch Metrics
#
# PrivateLink note: full isolation requires AWS Direct Connect to Hetzner.
# In the interim, ADOT egresses via Cloudflare WARP Connector so DPI at
# Hetzner egress sees TLS to Cloudflare IPs, not AWS API FQDNs.

# ── Private CA (ACM PCA) as trust anchor ────────────────────────────────────

resource "aws_acmpca_certificate_authority" "this" {
  type = "ROOT"

  certificate_authority_configuration {
    key_algorithm     = "RSA_4096"
    signing_algorithm = "SHA512WITHRSA"

    subject {
      common_name         = "${var.project} Validator CA"
      organization        = var.project
      organizational_unit = "Validators"
      country             = "EU"
    }
  }

  revocation_configuration {
    crl_configuration {
      enabled = false  # CRL distribution would expose infrastructure; use OCSP stapling in future
    }
  }

  tags = {
    project    = var.project
    managed-by = "terraform"
  }
}

resource "aws_acmpca_certificate" "root" {
  certificate_authority_arn   = aws_acmpca_certificate_authority.this.arn
  certificate_signing_request = aws_acmpca_certificate_authority.this.certificate_signing_request
  signing_algorithm           = "SHA512WITHRSA"
  template_arn                = "arn:aws:acm-pca:::template/RootCACertificate/V1"

  validity {
    type  = "DAYS"
    value = 90
  }
}

resource "aws_acmpca_certificate_authority_certificate" "root" {
  certificate_authority_arn = aws_acmpca_certificate_authority.this.arn
  certificate               = aws_acmpca_certificate.root.certificate
  certificate_chain         = aws_acmpca_certificate.root.certificate_chain
}

# ── Roles Anywhere trust anchor ──────────────────────────────────────────────

resource "aws_rolesanywhere_trust_anchor" "this" {
  name    = "${var.project}-validators"
  enabled = true

  source {
    source_data {
      acm_pca_arn = aws_acmpca_certificate_authority.this.arn
    }
    source_type = "AWS_ACM_PCA"
  }

  depends_on = [aws_acmpca_certificate_authority_certificate.root]

  tags = {
    project    = var.project
    managed-by = "terraform"
  }
}

# ── IAM role assumed by validators ───────────────────────────────────────────

resource "aws_iam_role" "adot_collector" {
  name = "${var.project}-adot-collector"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowRolesAnywhere"
      Effect    = "Allow"
      Principal = { Service = "rolesanywhere.amazonaws.com" }
      Action    = ["sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"]
      Condition = {
        ArnEquals = {
          "aws:SourceArn" = aws_rolesanywhere_trust_anchor.this.arn
        }
      }
    }]
  })

  tags = {
    project    = var.project
    managed-by = "terraform"
  }
}

resource "aws_iam_role_policy" "validator" {
  name = "kms-sign-adot"
  role = aws_iam_role.adot_collector.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # ── KMS signing (FIPS) ───────────────────────────────────────────────
      {
        Sid    = "KMSSignOnly"
        Effect = "Allow"
        Action = [
          "kms:Sign",
          "kms:GetPublicKey",
          "kms:DescribeKey",
        ]
        Resource = var.kms_key_arns
      },
      {
        Sid    = "DenyAllOtherKMS"
        Effect = "Deny"
        Action = [
          "kms:CreateKey", "kms:DeleteAlias", "kms:DisableKey",
          "kms:EnableKeyRotation", "kms:PutKeyPolicy", "kms:ScheduleKeyDeletion",
          "kms:UpdateKeyDescription", "kms:Decrypt", "kms:Encrypt",
          "kms:GenerateDataKey*", "kms:ReEncrypt*",
        ]
        Resource = "*"
      },
      # ── X-Ray (ADOT traces) ───────────────────────────────────────────────
      {
        Sid    = "XRayWrite"
        Effect = "Allow"
        Action = [
          "xray:PutTraceSegments",
          "xray:PutTelemetryRecords",
          "xray:GetSamplingRules",
          "xray:GetSamplingTargets",
          "xray:GetSamplingStatisticSummaries",
        ]
        Resource = "*"
      },
      # ── CloudWatch Logs (scoped to /{project}/ prefix) ────────────────────
      {
        Sid    = "CloudWatchLogsWrite"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams",
        ]
        Resource = "arn:aws:logs:${var.aws_region}:${var.aws_account_id}:log-group:/${var.project}/*"
      },
      # ── CloudWatch Metrics (namespace-scoped) ─────────────────────────────
      {
        Sid      = "CloudWatchMetrics"
        Effect   = "Allow"
        Action   = ["cloudwatch:PutMetricData"]
        Resource = "*"
        Condition = {
          StringEquals = {
            "cloudwatch:namespace" = var.cloudwatch_namespace
          }
        }
      },
    ]
  })
}

# ── Roles Anywhere profile ───────────────────────────────────────────────────

resource "aws_rolesanywhere_profile" "this" {
  name      = "${var.project}-adot"
  enabled   = true
  role_arns = [aws_iam_role.adot_collector.arn]

  # 1-hour session max — signing_helper auto-refreshes before expiry
  duration_seconds             = 3600
  session_policy               = null
  require_instance_properties  = false

  tags = {
    project    = var.project
    managed-by = "terraform"
  }
}
variable "project"              { type = string }   # "populist" | "seda-haqq"
variable "aws_account_id"       { type = string }   # required for CloudWatch Logs ARN scoping
variable "aws_region"           { type = string; default = "us-east-1" }
variable "kms_key_arns"         { type = list(string) }   # validator + tally key ARNs
variable "cloudwatch_namespace" { type = string }   # "Populist" | "SedaHaqq"

output "trust_anchor_arn" {
  value       = aws_rolesanywhere_trust_anchor.this.arn
  description = "IAM Roles Anywhere trust anchor ARN"
}

output "profile_arn" {
  value       = aws_rolesanywhere_profile.this.arn
  description = "IAM Roles Anywhere profile ARN"
}

output "role_arn" {
  value       = aws_iam_role.adot_collector.arn
  description = "IAM role ARN (KMS signing + ADOT)"
}

output "pca_arn" {
  value       = aws_acmpca_certificate_authority.this.arn
  description = "ACM PCA ARN for issuing validator certificates"
}

output "cert_issue_command" {
  description = "Manual cert issuance instructions for each Hetzner VM"
  value = <<-CMD
    # On each Hetzner VM — generate keypair and CSR:
    #   openssl genrsa -out /opt/${var.project}/iam/validator.key 4096
    #   openssl req -new -key /opt/${var.project}/iam/validator.key \
    #     -subj "/CN=validator-$HOSTNAME/O=${var.project}/C=EU" \
    #     -out /tmp/validator.csr
    #
    # On operator machine (with AWS credentials):
    #   aws acm-pca issue-certificate \
    #     --certificate-authority-arn ${aws_acmpca_certificate_authority.this.arn} \
    #     --csr fileb:///tmp/validator.csr --signing-algorithm SHA256WITHRSA \
    #     --validity Value=30,Type=DAYS
    #   aws acm-pca get-certificate ... --output text > /opt/${var.project}/iam/validator.crt
  CMD
}
