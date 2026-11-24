variable "name_prefix" { type = string }
variable "environment" { type = string }
variable "subnet_ids" { type = list(string) }
variable "security_group_id" { type = string }
variable "kms_key_arn" { type = string }
variable "instance_class" { type = string }
variable "allocated_storage" { type = number }
variable "multi_az" { type = bool }

resource "random_password" "db_admin" {
  length  = 32
  special = false
}

resource "random_password" "db_app" {
  length  = 32
  special = false
}

resource "aws_db_subnet_group" "this" {
  name       = "${var.name_prefix}-${var.environment}-db"
  subnet_ids = var.subnet_ids
}

resource "aws_db_parameter_group" "pg16" {
  name   = "${var.name_prefix}-${var.environment}-pg16"
  family = "postgres16"

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
}

resource "aws_db_instance" "this" {
  identifier                = "${var.name_prefix}-${var.environment}-pg"
  engine                    = "postgres"
  engine_version            = "16.4"
  instance_class            = var.instance_class
  allocated_storage         = var.allocated_storage
  max_allocated_storage     = var.allocated_storage * 5
  storage_type              = "gp3"
  storage_encrypted         = true
  kms_key_id                = var.kms_key_arn
  db_name                   = "backplane_enterprise"
  username                  = "bp_admin"
  password                  = random_password.db_admin.result
  db_subnet_group_name      = aws_db_subnet_group.this.name
  vpc_security_group_ids    = [var.security_group_id]
  parameter_group_name      = aws_db_parameter_group.pg16.name
  multi_az                  = var.multi_az
  publicly_accessible       = false
  backup_retention_period   = 7
  deletion_protection       = true
  copy_tags_to_snapshot     = true
  skip_final_snapshot       = false
  final_snapshot_identifier = "${var.name_prefix}-${var.environment}-final"
}

# Separate Secret 1: Schema owner URL — readable ONLY by the one-shot migrate task.
resource "aws_secretsmanager_secret" "db_admin_url" {
  name       = "${var.name_prefix}/${var.environment}/database-admin-url"
  kms_key_id = var.kms_key_arn
}

resource "aws_secretsmanager_secret_version" "db_admin_url" {
  secret_id     = aws_secretsmanager_secret.db_admin_url.id
  secret_string = "postgres://bp_admin:${random_password.db_admin.result}@${aws_db_instance.this.endpoint}/backplane_enterprise?sslmode=require"
}

# Separate Secret 2: Unprivileged bp_app (NOBYPASSRLS) URL — readable by runtime task only.
resource "aws_secretsmanager_secret" "db_app_url" {
  name       = "${var.name_prefix}/${var.environment}/database-app-url"
  kms_key_id = var.kms_key_arn
}

resource "aws_secretsmanager_secret_version" "db_app_url" {
  secret_id     = aws_secretsmanager_secret.db_app_url.id
  secret_string = "postgres://bp_app:${random_password.db_app.result}@${aws_db_instance.this.endpoint}/backplane_enterprise?sslmode=require"
}

# Separate Secret 3: Plain bp_app password passed ONLY to the migrate task (`BP_APP_DB_PASSWORD`)
# so `bp-ent-api migrate` sets `ALTER ROLE bp_app LOGIN PASSWORD` out-of-band.
resource "aws_secretsmanager_secret" "db_app_password" {
  name       = "${var.name_prefix}/${var.environment}/database-app-password"
  kms_key_id = var.kms_key_arn
}

resource "aws_secretsmanager_secret_version" "db_app_password" {
  secret_id     = aws_secretsmanager_secret.db_app_password.id
  secret_string = random_password.db_app.result
}

output "rds_endpoint" { value = aws_db_instance.this.endpoint }
output "db_admin_url_secret_arn" { value = aws_secretsmanager_secret.db_admin_url.arn }
output "db_app_url_secret_arn" { value = aws_secretsmanager_secret.db_app_url.arn }
output "db_app_password_secret_arn" { value = aws_secretsmanager_secret.db_app_password.arn }
