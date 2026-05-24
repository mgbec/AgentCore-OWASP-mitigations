###############################################################################
# KMS - Encryption at Rest (Data Security - Credential Exposure mitigation)
#
# Customer-managed KMS key for encrypting:
# - Agent credentials in Secrets Manager
# - Token vault secrets
# - CloudWatch log data
#
# Key policy restricts access to only the runtime and gateway roles.
###############################################################################

resource "aws_kms_key" "agent_secrets" {
  description             = "Encryption key for AgentCore OWASP demo secrets"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "RootAccountAccess"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "RuntimeDecrypt"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.agentcore_runtime.arn
        }
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = "*"
      },
      {
        Sid    = "AgentCoreServiceAccess"
        Effect = "Allow"
        Principal = {
          Service = "bedrock-agentcore.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Sid    = "CloudWatchLogsAccess"
        Effect = "Allow"
        Principal = {
          Service = "logs.${var.aws_region}.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name    = "${var.project_name}-secrets-key"
    Purpose = "credential-encryption"
  }
}

resource "aws_kms_alias" "agent_secrets" {
  name          = "alias/${var.project_name}-secrets"
  target_key_id = aws_kms_key.agent_secrets.key_id
}
