variable "name_prefix" { type = string }
variable "environment" { type = string }
variable "vpc_id" { type = string }
variable "public_subnet_ids" { type = list(string) }
variable "alb_security_group_id" { type = string }
variable "acm_certificate_arn" { type = string }
variable "enable_boat_mtls_nlb" { type = bool }
variable "enable_managed_waf_rules" { type = bool }

resource "aws_lb" "alb" {
  name                       = "${var.name_prefix}-${var.environment}-alb"
  internal                   = false
  load_balancer_type         = "application"
  security_groups            = [var.alb_security_group_id]
  subnets                    = var.public_subnet_ids
  drop_invalid_header_fields = true
}

resource "aws_lb_target_group" "app" {
  name        = "${var.name_prefix}-${var.environment}-app"
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"
  health_check {
    path = "/readyz"
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.alb.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.acm_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}

# Optional NLB TCP passthrough for Boat VM mTLS (disabled when Boat VMs are off to save ~$16/mo).
# preserve_client_ip = false ensures task SG only allows VPC NLB ENI IPs on port 8443.
resource "aws_lb" "nlb_mtls" {
  count              = var.enable_boat_mtls_nlb ? 1 : 0
  name               = "${var.name_prefix}-${var.environment}-mtls"
  internal           = false
  load_balancer_type = "network"
  subnets            = var.public_subnet_ids
}

resource "aws_lb_target_group" "relay_mtls" {
  count              = var.enable_boat_mtls_nlb ? 1 : 0
  name               = "${var.name_prefix}-${var.environment}-mtls"
  port               = 8443
  protocol           = "TCP"
  vpc_id             = var.vpc_id
  target_type        = "ip"
  preserve_client_ip = false
}

resource "aws_lb_listener" "relay_mtls" {
  count             = var.enable_boat_mtls_nlb ? 1 : 0
  load_balancer_arn = aws_lb.nlb_mtls[0].arn
  port              = 8443
  protocol          = "TCP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.relay_mtls[0].arn
  }
}

# Lean WAFv2: single per-IP rate-limit rule (~$6/mo total) by default.
resource "aws_wafv2_web_acl" "this" {
  name  = "${var.name_prefix}-${var.environment}-waf"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "RateLimitPerIP"
    priority = 1
    action {
      block {}
    }
    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "IP"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RateLimitPerIP"
      sampled_requests_enabled   = true
    }
  }

  dynamic "rule" {
    for_each = var.enable_managed_waf_rules ? [1] : []
    content {
      name     = "AWSManagedRulesCommonRuleSet"
      priority = 10
      override_action {
        none {}
      }
      statement {
        managed_rule_group_statement {
          name        = "AWSManagedRulesCommonRuleSet"
          vendor_name = "AWS"
        }
      }
      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "CommonRuleSet"
        sampled_requests_enabled   = true
      }
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.name_prefix}-${var.environment}-waf"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_web_acl_association" "alb" {
  resource_arn = aws_lb.alb.arn
  web_acl_arn  = aws_wafv2_web_acl.this.arn
}

output "alb_dns_name" { value = aws_lb.alb.dns_name }
output "nlb_dns_name" { value = var.enable_boat_mtls_nlb ? aws_lb.nlb_mtls[0].dns_name : "" }
output "app_target_group_arn" { value = aws_lb_target_group.app.arn }
output "relay_mtls_target_group_arn" { value = var.enable_boat_mtls_nlb ? aws_lb_target_group.relay_mtls[0].arn : "" }
