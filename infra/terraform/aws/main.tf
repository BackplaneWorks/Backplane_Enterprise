module "network" {
  source = "./modules/network"

  name_prefix        = var.name_prefix
  environment        = var.environment
  vpc_cidr           = var.vpc_cidr
  availability_zones = var.availability_zones
}

module "kms" {
  source = "./modules/kms"

  name_prefix = var.name_prefix
  environment = var.environment
}

module "database" {
  source = "./modules/database"

  name_prefix       = var.name_prefix
  environment       = var.environment
  subnet_ids        = module.network.db_subnet_ids
  security_group_id = module.network.rds_sg_id
  kms_key_arn       = module.kms.shared_key_arn
  instance_class    = var.db_instance_class
  allocated_storage = var.db_allocated_storage
  multi_az          = var.db_multi_az
}

module "storage" {
  source = "./modules/storage"

  name_prefix = var.name_prefix
  environment = var.environment
  kms_key_arn = module.kms.shared_key_arn
}

module "edge" {
  source = "./modules/edge"

  name_prefix              = var.name_prefix
  environment              = var.environment
  vpc_id                   = module.network.vpc_id
  public_subnet_ids        = module.network.public_subnet_ids
  alb_security_group_id    = module.network.alb_sg_id
  acm_certificate_arn      = var.acm_certificate_arn
  enable_boat_mtls_nlb     = var.enable_boat_mtls_nlb
  enable_managed_waf_rules = var.enable_managed_waf_rules
}

module "ses" {
  source = "./modules/ses"

  count  = var.ses_domain != "" ? 1 : 0
  domain = var.ses_domain
}

module "ecs" {
  source = "./modules/ecs"

  name_prefix                  = var.name_prefix
  environment                  = var.environment
  aws_region                   = var.aws_region
  vpc_id                       = module.network.vpc_id
  public_subnet_ids            = module.network.public_subnet_ids
  ecs_security_group_id        = module.network.ecs_sg_id
  portal_origin                = "https://${var.portal_domain}"
  relay_mtls_host              = var.relay_mtls_domain
  app_image                    = var.app_image
  desired_count                = var.ecs_desired_count
  task_cpu                     = var.ecs_task_cpu
  task_memory                  = var.ecs_task_memory
  db_app_secret_arn            = module.database.db_app_url_secret_arn
  db_admin_secret_arn          = module.database.db_admin_url_secret_arn
  db_app_password_secret_arn   = module.database.db_app_password_secret_arn
  boat_ca_secret_arn           = module.kms.boat_ca_secret_arn
  shared_kms_key_arn           = module.kms.shared_key_arn
  s3_bucket_name               = module.storage.bucket_name
  s3_bucket_arn                = module.storage.bucket_arn
  alb_app_target_group_arn     = module.edge.app_target_group_arn
  nlb_relay_mtls_tg_arn        = module.edge.relay_mtls_target_group_arn
  boat_relay_idle_timeout_secs     = var.boat_relay_idle_timeout_secs
  ses_identity_arn                 = var.ses_domain != "" ? module.ses[0].domain_identity_arn : ""
  ses_from_email                   = var.ses_from_email
  stripe_secret_key_arn            = var.stripe_secret_key_arn
  stripe_webhook_secret_arn        = var.stripe_webhook_secret_arn
  stripe_seat_price_id             = var.stripe_seat_price_id
  stripe_vm_price_id               = var.stripe_vm_price_id
  stripe_vm_meter_event            = var.stripe_vm_meter_event
  google_mail_client_id            = var.google_mail_client_id
  google_mail_client_secret_arn    = var.google_mail_client_secret_arn
  microsoft_mail_client_id         = var.microsoft_mail_client_id
  microsoft_mail_client_secret_arn = var.microsoft_mail_client_secret_arn
  microsoft_mail_tenant            = var.microsoft_mail_tenant
}
