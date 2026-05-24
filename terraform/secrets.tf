###############################################################################
# Secrets Manager - Credential Storage (Data Security mitigation)
#
# Stores API keys and credentials encrypted with the customer-managed KMS key.
# AgentCore Identity token vault references these secrets.
# Credentials are never hardcoded or passed through LLM context.
###############################################################################

resource "aws_secretsmanager_secret" "financial_api_key" {
  name_prefix = "${var.project_name}/financial-api-key-"
  description = "API key for financial service integration"
  kms_key_id  = aws_kms_key.agent_secrets.arn

  # Force deletion after retention period (no recovery in dev)
  recovery_window_in_days = var.environment == "prod" ? 30 : 7

  tags = {
    Name        = "${var.project_name}-financial-api-key"
    Purpose     = "agent-credential"
    AgentCore   = "credential-provider"
  }
}

resource "aws_secretsmanager_secret_version" "financial_api_key" {
  count = var.financial_api_key != "" ? 1 : 0

  secret_id     = aws_secretsmanager_secret.financial_api_key.id
  secret_string = var.financial_api_key
}
