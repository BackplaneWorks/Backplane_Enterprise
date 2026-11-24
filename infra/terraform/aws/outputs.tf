output "vpc_id" {
  value = module.network.vpc_id
}

output "alb_dns_name" {
  description = "ALB DNS name for HTTPS web portal, API, and desktop WSS relay"
  value       = module.edge.alb_dns_name
}

output "relay_mtls_nlb_dns_name" {
  description = "NLB DNS name (port 8443 TCP passthrough) for Boat VM outbound mTLS tunnels"
  value       = module.edge.nlb_dns_name
}

output "rds_endpoint" {
  description = "Private RDS PostgreSQL 16 endpoint (never publicly accessible)"
  value       = module.database.rds_endpoint
}

output "s3_bucket_name" {
  value = module.storage.bucket_name
}

output "shared_kms_key_arn" {
  description = "Single shared KMS CMK ARN ($1/mo) wrapping per-tenant DEKs with EncryptionContext={tenant_id}"
  value       = module.kms.shared_key_arn
}

output "boat_vm_security_group_id" {
  description = "Security group for optional on-demand Boat VMs (zero inbound rules)"
  value       = module.network.boat_vm_sg_id
}

output "migrate_task_definition_arn" {
  description = "ARM64 ECS task definition ARN for one-off schema migrations (only task with db_admin_url)"
  value       = module.ecs.migrate_task_definition_arn
}
