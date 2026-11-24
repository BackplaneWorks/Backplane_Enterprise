variable "name_prefix" { type = string }
variable "environment" { type = string }

# Single shared AWS KMS CMK ($1/mo flat) with annual rotation enabled.
# Wraps per-tenant random DEKs with EncryptionContext={bpe:tenant_id} and encrypts
# RDS, S3 (Bucket Keys enabled), and Secrets Manager — full cryptographic
# tenant isolation without paying $1/tenant/month.
resource "aws_kms_key" "shared" {
  description             = "${var.name_prefix}-${var.environment} shared CMK (RDS, S3, Secrets, Tenant DEK Envelope)"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_kms_alias" "shared" {
  name          = "alias/${var.name_prefix}-${var.environment}-shared"
  target_key_id = aws_kms_key.shared.key_id
}

# Persistent Boat Device CA shared across all ECS replicas and restarts.
resource "tls_private_key" "boat_ca" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "tls_self_signed_cert" "boat_ca" {
  private_key_pem = tls_private_key.boat_ca.private_key_pem

  subject {
    organization = "Backplane Enterprise"
    common_name  = "${var.name_prefix}-${var.environment} Boat Device CA"
  }

  validity_period_hours = 87600 # 10 years
  is_ca_certificate     = true

  allowed_uses = [
    "cert_signing",
    "crl_signing",
    "digital_signature",
  ]
}

resource "aws_secretsmanager_secret" "boat_ca" {
  name       = "${var.name_prefix}/${var.environment}/boat-ca"
  kms_key_id = aws_kms_key.shared.arn
}

resource "aws_secretsmanager_secret_version" "boat_ca" {
  secret_id = aws_secretsmanager_secret.boat_ca.id
  secret_string = jsonencode({
    cert_pem = tls_self_signed_cert.boat_ca.cert_pem
    key_pem  = tls_private_key.boat_ca.private_key_pem
  })
}

output "shared_key_arn" { value = aws_kms_key.shared.arn }
output "boat_ca_secret_arn" { value = aws_secretsmanager_secret.boat_ca.arn }
