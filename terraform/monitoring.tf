###############################################################################
# Monitoring & Observability (ASI09, ASI10, Telemetry Leakage mitigation)
#
# CloudWatch log groups with:
# - Retention policies (prevent indefinite PII storage)
# - KMS encryption (protect telemetry data)
# - Metric filters for security anomaly detection
# - Alarms for rogue agent behavior patterns
###############################################################################

# Log group for AgentCore Runtime
resource "aws_cloudwatch_log_group" "agent_runtime" {
  name              = "/aws/bedrock-agentcore/${var.project_name}"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.agent_secrets.arn

  tags = {
    Name     = "${var.project_name}-runtime-logs"
    Security = "audit-trail"
  }
}

# Log group for Lambda interceptors
resource "aws_cloudwatch_log_group" "input_validator" {
  name              = "/aws/lambda/${aws_lambda_function.input_validator.function_name}"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.agent_secrets.arn

  tags = {
    Name = "${var.project_name}-input-validator-logs"
  }
}

resource "aws_cloudwatch_log_group" "output_filter" {
  name              = "/aws/lambda/${aws_lambda_function.output_filter.function_name}"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.agent_secrets.arn

  tags = {
    Name = "${var.project_name}-output-filter-logs"
  }
}

###############################################################################
# Metric Filters - Security Anomaly Detection (ASI10)
###############################################################################

# Detect prompt injection attempts
resource "aws_cloudwatch_log_metric_filter" "injection_blocked" {
  name           = "${var.project_name}-injection-blocked"
  pattern        = "{ $.security.blocked = true }"
  log_group_name = aws_cloudwatch_log_group.agent_runtime.name

  metric_transformation {
    name      = "PromptInjectionBlocked"
    namespace = "AgentCore/Security"
    value     = "1"
  }
}

# Detect rate limit hits
resource "aws_cloudwatch_log_metric_filter" "rate_limit_hit" {
  name           = "${var.project_name}-rate-limit-hit"
  pattern        = "\"Session operation limit reached\""
  log_group_name = aws_cloudwatch_log_group.agent_runtime.name

  metric_transformation {
    name      = "RateLimitHit"
    namespace = "AgentCore/Security"
    value     = "1"
  }
}

# Detect memory poisoning attempts
resource "aws_cloudwatch_log_metric_filter" "memory_write_blocked" {
  name           = "${var.project_name}-memory-write-blocked"
  pattern        = "\"Memory write blocked by guard\""
  log_group_name = aws_cloudwatch_log_group.agent_runtime.name

  metric_transformation {
    name      = "MemoryWriteBlocked"
    namespace = "AgentCore/Security"
    value     = "1"
  }
}

# Detect unauthorized account access
resource "aws_cloudwatch_log_metric_filter" "unauthorized_access" {
  name           = "${var.project_name}-unauthorized-access"
  pattern        = "\"Unauthorized account access attempt\""
  log_group_name = aws_cloudwatch_log_group.agent_runtime.name

  metric_transformation {
    name      = "UnauthorizedAccessAttempt"
    namespace = "AgentCore/Security"
    value     = "1"
  }
}

###############################################################################
# CloudWatch Alarms - Security Alerting
###############################################################################

resource "aws_cloudwatch_metric_alarm" "high_injection_rate" {
  alarm_name          = "${var.project_name}-high-injection-rate"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "PromptInjectionBlocked"
  namespace           = "AgentCore/Security"
  period              = 300
  statistic           = "Sum"
  threshold           = 10
  alarm_description   = "High rate of prompt injection attempts detected (possible attack)"
  treat_missing_data  = "notBreaching"

  tags = {
    Security = "ASI01-alert"
  }
}

resource "aws_cloudwatch_metric_alarm" "unauthorized_access_spike" {
  alarm_name          = "${var.project_name}-unauthorized-access-spike"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "UnauthorizedAccessAttempt"
  namespace           = "AgentCore/Security"
  period              = 300
  statistic           = "Sum"
  threshold           = 5
  alarm_description   = "Multiple unauthorized access attempts (possible privilege escalation)"
  treat_missing_data  = "notBreaching"

  tags = {
    Security = "ASI03-alert"
  }
}
