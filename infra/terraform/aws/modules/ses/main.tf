variable "domain" { type = string }

resource "aws_ses_domain_identity" "this" {
  domain = var.domain
}

resource "aws_ses_domain_dkim" "this" {
  domain = aws_ses_domain_identity.this.domain
}

output "domain_identity_arn" { value = aws_ses_domain_identity.this.arn }
output "verification_token" { value = aws_ses_domain_identity.this.verification_token }
output "dkim_tokens" { value = aws_ses_domain_dkim.this.dkim_tokens }
