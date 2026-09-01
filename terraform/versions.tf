terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }
}

provider "aws" {
  region                      = var.aws_region
  access_key                  = var.is_local ? "mock_access_key" : null
  secret_key                  = var.is_local ? "mock_secret_key" : null
  s3_use_path_style           = var.is_local ? true : null
  skip_credentials_validation = var.is_local ? true : false
  skip_metadata_api_check     = var.is_local ? true : false
  skip_requesting_account_id  = var.is_local ? true : false

  dynamic "endpoints" {
    for_each = var.is_local ? [1] : []
    content {
      s3             = var.local_endpoint
      kms            = var.local_endpoint
      iam            = var.local_endpoint
      sqs            = var.local_endpoint
      sns            = var.local_endpoint
      lambda         = var.local_endpoint
      cloudwatchlogs = var.local_endpoint
      events         = var.local_endpoint
      sts            = var.local_endpoint
    }
  }

  default_tags {
    tags = {
      Environment = var.is_local ? "LocalSecurityLab" : "Production"
      Project     = "halt.lab"
      ManagedBy   = "Terraform"
    }
  }
}
