terraform {
  required_version = ">= 1.7.0"

  # IMPORTANT: Terraform state holds generated RDS passwords and the Boat CA private key.
  # Uncomment and configure an encrypted remote backend (SSE-KMS + locking) before applying:
  # backend "s3" {
  #   bucket       = "your-tfstate-bucket"
  #   key          = "backplane-enterprise/prod/terraform.tfstate"
  #   region       = "us-east-1"
  #   encrypt      = true
  #   kms_key_id   = "alias/your-tfstate-cmk"
  #   use_lockfile = true
  # }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.70"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "backplane-enterprise"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}
