variable "name_prefix" { type = string }
variable "environment" { type = string }
variable "aws_region" { type = string }
variable "vpc_id" { type = string }
variable "public_subnet_ids" { type = list(string) }
variable "ecs_security_group_id" { type = string }
variable "portal_origin" { type = string }
variable "relay_mtls_host" { type = string }
variable "app_image" { type = string }
variable "desired_count" { type = number }
variable "task_cpu" { type = string }
variable "task_memory" { type = string }
variable "db_app_secret_arn" { type = string }
variable "db_admin_secret_arn" { type = string }
variable "db_app_password_secret_arn" { type = string }
variable "boat_ca_secret_arn" { type = string }
variable "shared_kms_key_arn" { type = string }
variable "s3_bucket_name" { type = string }
variable "s3_bucket_arn" { type = string }
variable "alb_app_target_group_arn" { type = string }
variable "nlb_relay_mtls_tg_arn" { type = string }
variable "boat_relay_idle_timeout_secs" { type = number }
variable "ses_identity_arn" { type = string }
variable "ses_from_email" { type = string }
variable "stripe_secret_key_arn" { type = string }
variable "stripe_webhook_secret_arn" { type = string }
variable "stripe_seat_price_id" { type = string }
variable "stripe_vm_price_id" { type = string }
variable "stripe_vm_meter_event" { type = string }
variable "google_mail_client_id" { type = string }
variable "google_mail_client_secret_arn" { type = string }
variable "microsoft_mail_client_id" { type = string }
variable "microsoft_mail_client_secret_arn" { type = string }
variable "microsoft_mail_tenant" { type = string }

locals {
  optional_runtime_secret_arns = compact([
    var.stripe_secret_key_arn,
    var.stripe_webhook_secret_arn,
    var.google_mail_client_secret_arn,
    var.microsoft_mail_client_secret_arn,
  ])

  optional_app_secrets = concat(
    var.stripe_secret_key_arn != "" ? [{ name = "STRIPE_SECRET_KEY", valueFrom = var.stripe_secret_key_arn }] : [],
    var.stripe_webhook_secret_arn != "" ? [{ name = "STRIPE_WEBHOOK_SECRET", valueFrom = var.stripe_webhook_secret_arn }] : [],
    var.google_mail_client_secret_arn != "" ? [{ name = "GOOGLE_MAIL_CLIENT_SECRET", valueFrom = var.google_mail_client_secret_arn }] : [],
    var.microsoft_mail_client_secret_arn != "" ? [{ name = "MICROSOFT_MAIL_CLIENT_SECRET", valueFrom = var.microsoft_mail_client_secret_arn }] : [],
  )

  optional_app_env = concat(
    var.stripe_seat_price_id != "" ? [{ name = "STRIPE_SEAT_PRICE_ID", value = var.stripe_seat_price_id }] : [],
    var.stripe_vm_price_id != "" ? [
      { name = "STRIPE_VM_PRICE_ID", value = var.stripe_vm_price_id },
      { name = "STRIPE_VM_METER_EVENT", value = var.stripe_vm_meter_event },
    ] : [],
    var.google_mail_client_id != "" ? [{ name = "GOOGLE_MAIL_CLIENT_ID", value = var.google_mail_client_id }] : [],
    var.microsoft_mail_client_id != "" ? [
      { name = "MICROSOFT_MAIL_CLIENT_ID", value = var.microsoft_mail_client_id },
      { name = "MICROSOFT_MAIL_TENANT", value = var.microsoft_mail_tenant },
    ] : [],
    var.ses_from_email != "" ? [
      { name = "BP_SES_REGION", value = var.aws_region },
      { name = "BP_SES_FROM", value = var.ses_from_email },
    ] : [],
  )
}

resource "aws_ecs_cluster" "this" {
  name = "${var.name_prefix}-${var.environment}"
}

resource "aws_cloudwatch_log_group" "this" {
  name              = "/ecs/${var.name_prefix}-${var.environment}"
  retention_in_days = 30
}

data "aws_iam_policy_document" "ecs_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

# Execution role for runtime service: reads ONLY db_app_secret_arn and boat_ca_secret_arn.
resource "aws_iam_role" "runtime_exec" {
  name               = "${var.name_prefix}-${var.environment}-runtime-exec"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

resource "aws_iam_role_policy_attachment" "runtime_exec_base" {
  role       = aws_iam_role.runtime_exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "runtime_exec_secrets" {
  name = "read-runtime-secrets"
  role = aws_iam_role.runtime_exec.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = concat([var.db_app_secret_arn, var.boat_ca_secret_arn], local.optional_runtime_secret_arns)
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = [var.shared_kms_key_arn]
        Condition = {
          StringEquals = {
            "kms:ViaService" = "secretsmanager.${var.aws_region}.amazonaws.com"
          }
        }
      }
    ]
  })
}

# Execution role for one-shot migrate task: ONLY role permitted to read db_admin_secret_arn
# and db_app_password_secret_arn.
resource "aws_iam_role" "migrate_exec" {
  name               = "${var.name_prefix}-${var.environment}-migrate-exec"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

resource "aws_iam_role_policy_attachment" "migrate_exec_base" {
  role       = aws_iam_role.migrate_exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "migrate_exec_secrets" {
  name = "read-admin-db-secrets"
  role = aws_iam_role.migrate_exec.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = [var.db_admin_secret_arn, var.db_app_password_secret_arn]
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = [var.shared_kms_key_arn]
        Condition = {
          StringEquals = {
            "kms:ViaService" = "secretsmanager.${var.aws_region}.amazonaws.com"
          }
        }
      }
    ]
  })
}

resource "aws_iam_role" "app_task" {
  name               = "${var.name_prefix}-${var.environment}-app-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

resource "aws_iam_role_policy" "app_task" {
  name = "scoped-s3-kms-ses"
  role = aws_iam_role.app_task.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
        Resource = ["${var.s3_bucket_arn}/tenants/*"]
      },
      {
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = [var.s3_bucket_arn]
        Condition = {
          StringLike = {
            "s3:prefix" = ["tenants/*"]
          }
        }
      },
      {
        # Direct KMS DEK wrap/unwrap MUST carry the tenant encryption context.
        Effect   = "Allow"
        Action   = ["kms:Encrypt", "kms:Decrypt"]
        Resource = [var.shared_kms_key_arn]
        Condition = {
          "ForAnyValue:StringLike" = {
            "kms:EncryptionContextKeys" = ["bpe:tenant_id"]
          }
        }
      },
      {
        # S3 SSE-KMS operations allowed only via the S3 service in this region.
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey*"]
        Resource = [var.shared_kms_key_arn]
        Condition = {
          StringEquals = {
            "kms:ViaService" = "s3.${var.aws_region}.amazonaws.com"
          }
        }
      }
      ], var.ses_identity_arn != "" ? [{
        Effect   = "Allow"
        Action   = ["ses:SendEmail"]
        Resource = [var.ses_identity_arn]
    }] : [])
  })
}

resource "aws_ecs_task_definition" "migrate" {
  family                   = "${var.name_prefix}-${var.environment}-migrate"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.migrate_exec.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "ARM64"
  }

  container_definitions = jsonencode([{
    name      = "migrate"
    image     = var.app_image
    command   = ["migrate"]
    essential = true
    secrets = [
      { name = "DATABASE_ADMIN_URL", valueFrom = var.db_admin_secret_arn },
      { name = "BP_APP_DB_PASSWORD", valueFrom = var.db_app_password_secret_arn }
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.this.name
        awslogs-region        = var.aws_region
        awslogs-stream-prefix = "migrate"
      }
    }
  }])
}

# Single unified ARM64 Graviton Fargate container (`bp-ent-api serve`):
# serves embedded Web Portal (`BP_WEB_DIR=/app/web`), HTTP API, Desktop WSS,
# and Boat mTLS (:8443) in one lean process.
resource "aws_ecs_task_definition" "control_plane" {
  family                   = "${var.name_prefix}-${var.environment}-app"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  execution_role_arn       = aws_iam_role.runtime_exec.arn
  task_role_arn            = aws_iam_role.app_task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "ARM64"
  }

  container_definitions = jsonencode([{
    name      = "app"
    image     = var.app_image
    command   = ["serve"]
    essential = true
    portMappings = [
      { containerPort = 8080, protocol = "tcp" },
      { containerPort = 8443, protocol = "tcp" }
    ]
    environment = concat([
      { name = "BP_BIND", value = "0.0.0.0:8080" },
      { name = "BP_WEB_DIR", value = "/app/web" },
      { name = "BP_PUBLIC_ORIGIN", value = var.portal_origin },
      { name = "BP_API_BASE_URL", value = var.portal_origin },
      { name = "BP_TRUSTED_PROXY_HOPS", value = "1" },
      { name = "S3_BUCKET", value = var.s3_bucket_name },
      { name = "S3_REGION", value = var.aws_region },
      { name = "BP_KMS_PROVIDER", value = "aws" },
      { name = "BP_KMS_KEY_ID", value = var.shared_kms_key_arn },
      { name = "BP_RELAY_DISABLED", value = var.nlb_relay_mtls_tg_arn != "" ? "0" : "1" },
      { name = "BP_RELAY_MTLS_ADDR", value = "0.0.0.0:8443" },
      { name = "BP_RELAY_MTLS_HOST", value = var.relay_mtls_host },
      { name = "BP_RELAY_IDLE_TIMEOUT_SECS", value = tostring(var.boat_relay_idle_timeout_secs) },
      { name = "RUST_LOG", value = "info" }
    ], local.optional_app_env)
    secrets = concat([
      { name = "DATABASE_URL", valueFrom = var.db_app_secret_arn },
      { name = "BP_BOAT_CA_CERT_PEM", valueFrom = "${var.boat_ca_secret_arn}:cert_pem::" },
      { name = "BP_BOAT_CA_KEY_PEM", valueFrom = "${var.boat_ca_secret_arn}:key_pem::" }
    ], local.optional_app_secrets)
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.this.name
        awslogs-region        = var.aws_region
        awslogs-stream-prefix = "app"
      }
    }
  }])
}

resource "aws_ecs_service" "control_plane" {
  name            = "${var.name_prefix}-${var.environment}-app"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.control_plane.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.public_subnet_ids
    security_groups  = [var.ecs_security_group_id]
    assign_public_ip = true
  }

  load_balancer {
    target_group_arn = var.alb_app_target_group_arn
    container_name   = "app"
    container_port   = 8080
  }

  dynamic "load_balancer" {
    for_each = var.nlb_relay_mtls_tg_arn != "" ? [var.nlb_relay_mtls_tg_arn] : []
    content {
      target_group_arn = load_balancer.value
      container_name   = "app"
      container_port   = 8443
    }
  }
}

output "migrate_task_definition_arn" { value = aws_ecs_task_definition.migrate.arn }
