###############################################################################
# AgentCore OWASP Risk Mitigation Demo - Terraform Infrastructure
#
# Deploys the complete security-hardened agent system including:
# - VPC with private subnets (ASI04, ASI05 - network isolation)
# - IAM roles with least privilege (ASI03 - identity & privilege)
# - KMS keys for encryption at rest (Data Security - credential exposure)
# - S3 bucket for agent code deployment
# - Lambda interceptors for input/output filtering (ASI01, Data Leakage)
# - CloudWatch log groups with retention (ASI09, ASI10 - audit)
# - Secrets Manager for API credentials (Data Security)
###############################################################################

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }

  # State stored in S3 with DynamoDB locking.
  # Run scripts/bootstrap.sh first to create the bucket and table,
  # then init with: terraform init -backend-config=backend.hcl
  backend "s3" {}
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "agentcore-owasp-mitigations"
      Environment = var.environment
      ManagedBy   = "terraform"
      Security    = "owasp-demo"
    }
  }
}

# Data sources
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
