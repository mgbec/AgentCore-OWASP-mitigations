###############################################################################
# S3 - Agent Code Storage (ASI04 - Supply Chain mitigation)
#
# Stores the agent code package for AgentCore Runtime deployment.
# Versioning enabled for rollback capability.
# Encryption at rest with customer-managed KMS key.
# Public access blocked.
###############################################################################

resource "aws_s3_bucket" "agent_code" {
  bucket_prefix = "${var.project_name}-code-"
  force_destroy = var.environment != "prod"

  tags = {
    Name    = "${var.project_name}-agent-code"
    Purpose = "agentcore-runtime-deployment"
  }
}

resource "aws_s3_bucket_versioning" "agent_code" {
  bucket = aws_s3_bucket.agent_code.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "agent_code" {
  bucket = aws_s3_bucket.agent_code.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.agent_secrets.arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "agent_code" {
  bucket = aws_s3_bucket.agent_code.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Lifecycle rule to clean up old versions
resource "aws_s3_bucket_lifecycle_configuration" "agent_code" {
  bucket = aws_s3_bucket.agent_code.id

  rule {
    id     = "cleanup-old-versions"
    status = "Enabled"

    filter {}

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}
