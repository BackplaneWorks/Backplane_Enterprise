variable "aws_region" {
  type        = string
  description = "AWS region for Backplane Enterprise deployment"
  default     = "us-east-1"
}

variable "environment" {
  type        = string
  description = "Deployment environment name (e.g. prod, staging)"
  default     = "prod"
}

variable "name_prefix" {
  type        = string
  description = "Resource name prefix"
  default     = "bp-ent"
}

variable "vpc_cidr" {
  type        = string
  description = "CIDR block for the enterprise VPC"
  default     = "10.42.0.0/16"
}

variable "availability_zones" {
  type        = list(string)
  description = "Two AZs for ALB/RDS subnet group (zero NAT gateways provisioned)"
  default     = ["us-east-1a", "us-east-1b"]
}

variable "portal_domain" {
  type        = string
  description = "HTTPS domain for the web portal and API (e.g. enterprise.example.com)"
}

variable "relay_mtls_domain" {
  type        = string
  description = "Hostname Boat VMs connect to for outbound mTLS (:8443)"
  default     = "relay.enterprise.example.com"
}

variable "acm_certificate_arn" {
  type        = string
  description = "ACM certificate ARN for the ALB HTTPS (TLS 1.3) listener"
}

variable "ses_domain" {
  type        = string
  description = "Domain configured in Amazon SES for outbound order notifications"
  default     = ""
}

variable "app_image" {
  type        = string
  description = "ARM64 container image URI for unified `bp-ent-api` (with embedded /app/web)"
}

variable "ecs_desired_count" {
  type        = number
  description = "Number of consolidated ARM64 Fargate tasks (1 for lean baseline, 2+ for HA)"
  default     = 1
}

variable "ecs_task_cpu" {
  type        = string
  description = "Fargate ARM64 CPU units (256 = 0.25 vCPU, 512 = 0.5 vCPU)"
  default     = "256"
}

variable "ecs_task_memory" {
  type        = string
  description = "Fargate ARM64 memory MiB"
  default     = "512"
}

variable "db_instance_class" {
  type        = string
  description = "Shared RDS PostgreSQL 16 Graviton class (db.t4g.micro default for <$1/user/mo COGS)"
  default     = "db.t4g.micro"
}

variable "db_allocated_storage" {
  type        = number
  description = "Initial RDS gp3 storage in GiB"
  default     = 20
}

variable "db_multi_az" {
  type        = bool
  description = "Enable Multi-AZ RDS Postgres (false by default for lean unit economics)"
  default     = false
}

variable "enable_boat_mtls_nlb" {
  type        = bool
  description = "Provision NLB :8443 TCP passthrough for Boat VM outbound mTLS tunnels"
  default     = true
}

variable "enable_managed_waf_rules" {
  type        = bool
  description = "Add AWSManagedRulesCommonRuleSet to WAFv2 (rate-limit rule is always active)"
  default     = false
}

variable "boat_relay_idle_timeout_secs" {
  type        = number
  description = "Seconds of inactivity before an idle Boat VM is stopped (900s = 15m aggressive auto-stop)"
  default     = 900
}

variable "ses_from_email" {
  type        = string
  description = "Verified SES sender address (`BP_SES_FROM`), optional"
  default     = ""
}

variable "stripe_secret_key_arn" {
  type        = string
  description = "Optional Secrets Manager ARN for `STRIPE_SECRET_KEY`"
  default     = ""
}

variable "stripe_webhook_secret_arn" {
  type        = string
  description = "Optional Secrets Manager ARN for `STRIPE_WEBHOOK_SECRET`"
  default     = ""
}

variable "stripe_seat_price_id" {
  type        = string
  description = "Optional Stripe recurring seat price ID (`STRIPE_SEAT_PRICE_ID`)"
  default     = ""
}

variable "stripe_vm_price_id" {
  type        = string
  description = "Optional Stripe metered VM price ID (`STRIPE_VM_PRICE_ID`, meter `boat_vm_minutes`)"
  default     = ""
}

variable "stripe_vm_meter_event" {
  type        = string
  description = "Stripe meter event name (`STRIPE_VM_METER_EVENT`)"
  default     = "boat_vm_minutes"
}

variable "google_mail_client_id" {
  type        = string
  description = "Optional Google OAuth client ID for Gmail mail sync"
  default     = ""
}

variable "google_mail_client_secret_arn" {
  type        = string
  description = "Optional Secrets Manager ARN for `GOOGLE_MAIL_CLIENT_SECRET`"
  default     = ""
}

variable "microsoft_mail_client_id" {
  type        = string
  description = "Optional Microsoft Graph OAuth client ID for Outlook mail sync"
  default     = ""
}

variable "microsoft_mail_client_secret_arn" {
  type        = string
  description = "Optional Secrets Manager ARN for `MICROSOFT_MAIL_CLIENT_SECRET`"
  default     = ""
}

variable "microsoft_mail_tenant" {
  type        = string
  description = "Microsoft Entra tenant for Outlook mail sync (`MICROSOFT_MAIL_TENANT`)"
  default     = "common"
}
