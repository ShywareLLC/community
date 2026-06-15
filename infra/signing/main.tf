# Protocol signing — composite module.
# Wraps kms/ + iam-roles-anywhere/ as a single deployable unit.
# One call per deployment; outputs wire directly into validator/ module.

module "kms" {
  source      = "../kms"
  project     = var.project
  environment = var.environment
}

module "iam_roles_anywhere" {
  source               = "../iam-roles-anywhere"
  project              = var.project
  aws_account_id       = var.aws_account_id
  aws_region           = var.aws_region
  kms_key_arns         = [module.kms.validator_key_arn, module.kms.tally_key_arn]
  cloudwatch_namespace = var.cloudwatch_namespace
}
variable "project"              { type = string }   # "populist" | "seda-haqq"
variable "environment"          { type = string }
variable "aws_account_id"       { type = string }
variable "aws_region"           { type = string; default = "us-east-1" }
variable "cloudwatch_namespace" { type = string }   # "Populist" | "SedaHaqq"

output "kms_validator_key_id"  { value = module.kms.validator_key_id }
output "kms_validator_key_arn" { value = module.kms.validator_key_arn }
output "kms_tally_key_id"      { value = module.kms.tally_key_id }
output "kms_tally_key_arn"     { value = module.kms.tally_key_arn }
output "kms_key_arns"          { value = [module.kms.validator_key_arn, module.kms.tally_key_arn] }

output "trust_anchor_arn"  { value = module.iam_roles_anywhere.trust_anchor_arn }
output "profile_arn"       { value = module.iam_roles_anywhere.profile_arn }
output "role_arn"          { value = module.iam_roles_anywhere.role_arn }
output "pca_arn"           { value = module.iam_roles_anywhere.pca_arn }
output "cert_issue_command" {
  value     = module.iam_roles_anywhere.cert_issue_command
  sensitive = false
}
